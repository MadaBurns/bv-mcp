#!/usr/bin/env python3
"""Offline tests for chaos-all-tools-sweep.py (no network)."""
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("chaos-all-tools-sweep.py")


def load_script():
    spec = importlib.util.spec_from_file_location("chaos_all_tools_sweep", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load_script()


def reply(status=200, body=None, text=None, transport=None):
    raw = text if text is not None else ("data: " + json.dumps(body) if body is not None else "")
    return {"status": status, "headers": {}, "text": raw, "json": M.parse_body(raw), "ms": 1, "transport": transport}


def tool_result(text, is_error=False):
    result = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    return {"jsonrpc": "2.0", "id": 1, "result": result}


def rpc_error(code, message="m"):
    return {"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}}


def case(label="domain:empty", must_reject=True, kind="chaos"):
    return {"tool": "check_spf", "label": label, "args": {}, "must_reject": must_reject, "kind": kind, "read_only": True}


def verdict(c, r):
    return M.classify(c, r)[0]


class ParseBodyTest(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(M.parse_body('{"a": 1}'), {"a": 1})

    def test_sse_uses_last_data_line(self):
        self.assertEqual(M.parse_body('event: message\ndata: {"a": 1}\n\ndata: {"a": 2}\n'), {"a": 2})

    def test_empty_and_garbage_are_none(self):
        self.assertIsNone(M.parse_body(""))
        self.assertIsNone(M.parse_body("<html>nope</html>"))
        self.assertIsNone(M.parse_body("{not json"))


class ClassifyFailTest(unittest.TestCase):
    def test_transport_error(self):
        self.assertEqual(verdict(case(), reply(status=0, transport="URLError: x")), "FAIL")

    def test_http_500(self):
        self.assertEqual(verdict(case(), reply(status=500, text="oops")), "FAIL")

    def test_internal_rpc_error(self):
        self.assertEqual(verdict(case(), reply(body=rpc_error(-32603))), "FAIL")

    def test_leak_in_rejection_still_fails(self):
        body = tool_result("Error: TypeError: x is not a function", is_error=True)
        self.assertEqual(verdict(case(), reply(body=body)), "FAIL")

    def test_stack_frame_leak(self):
        body = tool_result("failed at handler (worker.js:10:5)", is_error=True)
        self.assertEqual(verdict(case(), reply(body=body)), "FAIL")

    def test_accepted_ssrf_value_fails(self):
        self.assertEqual(verdict(case(label="domain:localhost"), reply(body=tool_result("scanned"))), "FAIL")
        self.assertEqual(verdict(case(label="domains:ssrf-mix"), reply(body=tool_result("scanned"))), "FAIL")


class ClassifyOtherVerdictsTest(unittest.TestCase):
    def test_rejection_by_tool_error_passes(self):
        self.assertEqual(verdict(case(), reply(body=tool_result("Error: Invalid domain", is_error=True))), "PASS")

    def test_rejection_by_rpc_error_passes(self):
        self.assertEqual(verdict(case(), reply(body=rpc_error(-32602))), "PASS")

    def test_rejection_by_http_400_passes(self):
        self.assertEqual(verdict(case(), reply(status=400, text="bad request")), "PASS")

    def test_accepted_non_ssrf_value_is_review(self):
        self.assertEqual(verdict(case(label="domain:double-dot"), reply(body=tool_result("scanned"))), "REVIEW")

    def test_tolerated_input_passes_either_way(self):
        tolerated = case(label="domain:uppercase", must_reject=False)
        self.assertEqual(verdict(tolerated, reply(body=tool_result("scanned"))), "PASS")
        self.assertEqual(verdict(tolerated, reply(body=tool_result("Error: nope", is_error=True))), "PASS")

    def test_rate_limit_and_quota_are_skipped(self):
        self.assertEqual(verdict(case(), reply(status=429, text="slow down")), "SKIP")
        self.assertEqual(verdict(case(), reply(body=rpc_error(-32029, "daily quota"))), "SKIP")

    def test_unparseable_success_body_is_review(self):
        self.assertEqual(verdict(case(), reply(status=200, text="<html>hello</html>")), "REVIEW")

    def test_control_outcomes(self):
        control = case(label="valid-control", must_reject=False, kind="control")
        self.assertEqual(verdict(control, reply(body=tool_result("ok"))), "PASS")
        self.assertEqual(verdict(control, reply(body=tool_result("Error: job not found", is_error=True))), "REVIEW")
        self.assertEqual(verdict(control, reply(body=tool_result("Error: requires a paid tier", is_error=True))), "TIER")


READ_ONLY_TOOL = {
    "name": "check_thing",
    "annotations": {"readOnlyHint": True},
    "inputSchema": {
        "type": "object",
        "required": ["domain"],
        "properties": {
            "domain": {"type": "string"},
            "format": {"type": "string", "enum": ["full", "compact"]},
            "domains": {"type": "array", "items": {"type": "string"}},
            "limit": {"type": "integer", "minimum": 1},
            "force": {"type": "boolean"},
        },
    },
}
MUTATING_TOOL = {
    "name": "register_thing",
    "annotations": {"readOnlyHint": False},
    "inputSchema": {
        "type": "object",
        "required": ["domain", "label"],
        "properties": {"domain": {"type": "string"}, "label": {"type": "string"}, "tags": {"type": "array"}, "count": {"type": "integer"}},
    },
}


class BuildCasesTest(unittest.TestCase):
    def test_read_only_tool_gets_ssrf_cases_and_one_control(self):
        cases = M.build_cases(READ_ONLY_TOOL)
        labels = [c["label"] for c in cases]
        for expected in ("no-args", "unknown-arg", "domain:localhost", "domain:metadata-ip", "format:bad-enum", "domains:ssrf-mix", "limit:string", "force:string"):
            self.assertIn(expected, labels)
        controls = [c for c in cases if c["kind"] == "control"]
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0]["args"], {"domain": "isc.org"})

    def test_ssrf_labels_are_recognised(self):
        ssrf = [c for c in M.build_cases(READ_ONLY_TOOL) if M.is_ssrf(c)]
        self.assertGreaterEqual(len(ssrf), 7)
        self.assertTrue(all(c["must_reject"] for c in ssrf))

    def test_mutating_tool_never_gets_a_complete_call(self):
        cases = M.build_cases(MUTATING_TOOL)
        self.assertTrue(cases)
        required = set(MUTATING_TOOL["inputSchema"]["required"])
        for c in cases:
            self.assertTrue(c["must_reject"], c["label"])
            self.assertNotEqual(c["kind"], "control")
            self.assertFalse(required.issubset(c["args"].keys()), c["label"])

    def test_valid_value_prefers_enum_then_default(self):
        self.assertEqual(M.valid_value("format", {"type": "string", "enum": ["a", "b"]}), "a")
        self.assertEqual(M.valid_value("depth", {"type": "string", "default": "deep"}), "deep")
        self.assertEqual(M.valid_value("domains", {"type": "array"}), ["isc.org", "nic.cz"])
        self.assertEqual(M.valid_value("when", {"type": ["null", "integer"], "minimum": 3}), 3)


class RunnerHelpersTest(unittest.TestCase):
    def test_exit_code_is_nonzero_only_on_fail(self):
        self.assertEqual(M.exit_code({"PASS": 3, "REVIEW": 2, "SKIP": 1}), 0)
        self.assertEqual(M.exit_code({"PASS": 3, "FAIL": 1}), 1)

    def test_summarize_puts_fail_before_review(self):
        rows = [{"verdict": "REVIEW", "tool": "a"}, {"verdict": "PASS", "tool": "b"}, {"verdict": "FAIL", "tool": "c"}]
        counts, attention = M.summarize(rows)
        self.assertEqual(counts, {"REVIEW": 1, "PASS": 1, "FAIL": 1})
        self.assertEqual([r["tool"] for r in attention], ["c", "a"])

    def test_key_is_read_from_file_without_quotes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "vars")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('OTHER=1\nBV_INTERNAL_DEV_KEY="synthetic-value"\n')
            self.assertEqual(M.resolve_key(path), "synthetic-value")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("OTHER=1\n")
            self.assertIsNone(M.resolve_key(path))

    def test_host_must_be_https_or_local(self):
        self.assertTrue(M.host_is_allowed("https://example.com/mcp"))
        self.assertTrue(M.host_is_allowed("http://127.0.0.1:8787/mcp"))
        self.assertTrue(M.host_is_allowed("http://localhost:8787/mcp"))
        self.assertFalse(M.host_is_allowed("http://example.com/mcp"))
        self.assertFalse(M.host_is_allowed("ftp://example.com/mcp"))
        self.assertFalse(M.host_is_allowed("example.com/mcp"))

    def test_clear_text_remote_host_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "vars")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("BV_INTERNAL_DEV_KEY=synthetic-value\n")
            self.assertEqual(M.main(["--dev-vars", path, "--host", "http://example.com/mcp"]), 2)

    def test_redirects_are_not_followed(self):
        self.assertIsNone(M.NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://elsewhere.example/"))

    def test_missing_key_exits_two_before_any_network_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "vars")
            open(path, "w", encoding="utf-8").close()
            self.assertEqual(M.main(["--dev-vars", path, "--host", "http://127.0.0.1:9/mcp"]), 2)


if __name__ == "__main__":
    unittest.main()
