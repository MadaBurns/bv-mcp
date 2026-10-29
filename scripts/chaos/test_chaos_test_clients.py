#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import unittest
from unittest import mock
import contextlib
import io
import subprocess


SCRIPT = pathlib.Path(__file__).with_name("chaos-test-clients.py")


def load_script():
    spec = importlib.util.spec_from_file_location("chaos_test_clients", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ToolsListValidationTest(unittest.TestCase):
    def test_any_non_empty_tools_list_count_is_valid(self):
        module = load_script()
        body = json.dumps({"result": {"tools": [{"name": f"tool_{i}"} for i in range(57)]}})

        ok, detail = module.tools_list_available(200, body)

        self.assertTrue(ok)
        self.assertEqual(detail, "57 tools")


class ParseMcpBodyTest(unittest.TestCase):
    def test_plain_json_body(self):
        module = load_script()
        self.assertEqual(module.parse_mcp_body('{"result": {}}'), {"result": {}})

    def test_sse_body_uses_last_data_line(self):
        module = load_script()
        body = 'id: 1\nevent: message\ndata: {"n": 1}\n\nid: 2\nevent: message\ndata: {"n": 2}\n'
        self.assertEqual(module.parse_mcp_body(body), {"n": 2})
        self.assertEqual(module.parse_mcp_body(body, "text/event-stream; charset=utf-8"), {"n": 2})

    def test_sse_content_type_overrides_sniffing(self):
        module = load_script()
        self.assertEqual(module.parse_mcp_body("data: [1, 2]", "text/event-stream"), [1, 2])

    def test_empty_body_is_none(self):
        module = load_script()
        self.assertIsNone(module.parse_mcp_body(""))
        self.assertIsNone(module.parse_mcp_body("   \n"))
        self.assertIsNone(module.parse_mcp_body("event: ping\n", "text/event-stream"))

    def test_normalize_keeps_json_text_for_callers(self):
        module = load_script()
        self.assertEqual(module.normalize_mcp_text('event: message\ndata: {"a": 1}\n'), '{"a": 1}')


class QuotaClassifierTest(unittest.TestCase):
    def envelope(self, code, message):
        return json.dumps({"error": {"code": code, "message": message}})

    def test_quota_messages_are_skipped(self):
        module = load_script()
        for msg in ("Daily limit of 5 distinct domains reached", "Free tier: 50 requests per day",
                    "Rate limited. Retry after 60s"):
            self.assertTrue(module.is_quota_skip(200, self.envelope(-32029, msg)), msg)
        self.assertTrue(module.is_quota_skip(429, self.envelope(-32000, "Retry after 5s")))

    def test_quota_inside_sse_body(self):
        module = load_script()
        body = "event: message\ndata: " + self.envelope(-32029, "requests per day exceeded") + "\n"
        self.assertTrue(module.is_quota_skip(200, body))

    def test_real_failures_are_not_skipped(self):
        module = load_script()
        self.assertFalse(module.is_quota_skip(429, self.envelope(-32000, "something else")))
        self.assertFalse(module.is_quota_skip(500, self.envelope(-32603, "Retry after crash")))
        self.assertFalse(module.is_quota_skip(200, "not json"))
        self.assertFalse(module.is_quota_skip(0, "TIMEOUT"))


class QueryKeyIgnoredTest(unittest.TestCase):
    def test_outcomes(self):
        module = load_script()
        self.assertTrue(module.query_key_ignored(401, ""))
        self.assertTrue(module.query_key_ignored(403, "{}"))
        self.assertTrue(module.query_key_ignored(200, json.dumps({"error": {"code": -32029, "message": "requests per day"}})))
        self.assertTrue(module.query_key_ignored(200, json.dumps({"result": {"content": [{"type": "text"}]}})))
        self.assertFalse(module.query_key_ignored(500, "garbage"))


class FailClosedHarnessTest(unittest.TestCase):
    def test_batch_quota_errors_are_incomplete_not_successful_results(self):
        for entries in (("quota", "quota"), ("success", "quota")):
            m = load_script()
            m.API_KEY = "synthetic-secret"
            payloads = {"quota": {"error": {"code": -32029, "message": "quota"}},
                        "success": {"result": {"content": [{"text": "ok"}]}}}
            body = json.dumps([payloads[x] for x in entries])
            replies = [(200, body, body),
                       (200, '[{"result":{"content":[{"text":"<!-- STRUCTURED_RESULT"}]}}]', ''),
                       (200, '[{"error":{"code":-32601}}]', '')]
            def call(*args, **kwargs):
                value = replies.pop(0)
                m._last.value = value[:2]
                return value
            with mock.patch.object(m, "create_session", return_value=("session", 200)), mock.patch.object(
                    m, "curl_json", side_effect=call), mock.patch.object(m, "delete_session"), contextlib.redirect_stdout(io.StringIO()):
                m.test_batch_jsonrpc()
            self.assertTrue(m.skipped_quota)
            self.assertEqual(m.acceptance_exit(m.results, m.skipped_quota), 2)

    def test_batch_unknown_method_always_records_a_verdict(self):
        for reply, expected in (("{}", False), ("[]", False), ("null", False),
                                ('[{"error":{"code":-32601}}]', True)):
            m = load_script()
            m.API_KEY = "synthetic-secret"
            good = json.dumps([{"result": {"content": [{"text": "ok"}]}}] * 2)
            with mock.patch.object(m, "create_session", return_value=("session", 200)), mock.patch.object(
                    m, "curl_json", side_effect=[(200, good, ''),
                    (200, '[{"result":{"content":[{"text":"<!-- STRUCTURED_RESULT"}]}}]', ''),
                    (200, reply, '')]), mock.patch.object(m, "delete_session"), contextlib.redirect_stdout(io.StringIO()):
                m.test_batch_jsonrpc()
            verdicts = [ok for name, ok in m.results if name.startswith("10d.")]
            self.assertEqual(verdicts, [expected], reply)

    def test_failure_precedes_incomplete_and_diagnostic_is_not_empty_success(self):
        m = load_script()
        self.assertEqual(m.acceptance_exit([("fail", False)], ["quota"]), 1)
        self.assertEqual(m.acceptance_exit([], []), 2)
        self.assertEqual(m.acceptance_exit([], ["quota"], True), 2)
        self.assertEqual(m.acceptance_exit([("ok", True)], ["quota"]), 2)
        self.assertEqual(m.acceptance_exit([("ok", True)], ["quota"], True), 0)
        self.assertEqual(m.acceptance_exit([("ok", True)], []), 0)

    def test_sse_credentials_stay_off_process_arguments(self):
        m = load_script()
        m.API_KEY = "synthetic-secret"
        response = subprocess.CompletedProcess([], 0, stdout='event: endpoint\ndata: /mcp/messages?sessionId=synthetic', stderr='')
        with mock.patch.object(m.subprocess, "run", return_value=response) as run, mock.patch.object(
                m, "curl_json", return_value=(400, '{}', '')), contextlib.redirect_stdout(io.StringIO()):
            m.test_legacy_sse_per_client()
        for call in run.call_args_list:
            self.assertNotIn("synthetic-secret", str(call.args))
            self.assertIn("synthetic-secret", call.kwargs["input"])

    def test_retired_runner_never_loads_network_dependencies(self):
        result = subprocess.run([__import__("sys").executable, str(SCRIPT.with_name("chaos-run.py"))],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("RETIRED", result.stdout)

    def test_explicit_skip_never_counts_as_a_pass(self):
        m = load_script()
        with contextlib.redirect_stdout(io.StringIO()):
            m.record("session", True, "skipped (rate limited)")
        self.assertFalse(m.results)
        self.assertEqual(m.skipped_quota, ["session"])


    def test_every_failed_session_is_counted_and_never_passes_burst(self):
        for status in (0, 200, 401, 403, 429, 503):
            with self.subTest(status=status):
                m = load_script()
                with mock.patch.object(m, "create_session", return_value=(None, status)), contextlib.redirect_stdout(io.StringIO()):
                    m.test_concurrent_burst()
                self.assertTrue(any(not ok for _, ok in m.results))
                if status == 503:
                    self.assertIn(("6. Concurrent burst: no 5xx errors", False), m.results)

    def test_successful_burst_is_positive_control(self):
        m = load_script()
        reply = json.dumps({"result": {"content": [{"type": "text", "text": "ok"}]}})
        with mock.patch.object(m, "create_session", return_value=("session", 200)), mock.patch.object(
                m, "tool_call", return_value=(200, reply, "")), mock.patch.object(m, "delete_session"), contextlib.redirect_stdout(io.StringIO()):
            m.test_concurrent_burst()
        self.assertTrue(m.results)
        self.assertTrue(all(ok for _, ok in m.results))

    def test_transport_errors_cannot_be_success_and_secrets_stay_off_argv(self):
        m = load_script()
        for rc in (0, 60):
            response = subprocess.CompletedProcess([], rc, stdout='{}\n200', stderr='')
            with mock.patch.object(m.subprocess, "run", return_value=response) as run:
                status, _, _ = m.curl_json("POST", "/mcp", headers=["Authorization: Bearer synthetic-secret"])
            self.assertEqual(status, 200 if rc == 0 else 0)
            self.assertNotIn("synthetic-secret", str(run.call_args.args))
            self.assertIn("synthetic-secret", run.call_args.kwargs["input"])

    def test_failed_owner_preflight_clears_key_and_stops_before_any_suite(self):
        m = load_script()
        m.API_KEY = "old-credential"
        with mock.patch.object(m, "verify_owner", return_value=(False, "not owner")), mock.patch.object(
                m, "test_session_lifecycle") as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.main([]), 1)
        self.assertIsNone(m.API_KEY)
        run.assert_not_called()

    def test_owner_probe_never_sends_credentials_to_insecure_or_redirected_targets(self):
        m = load_script()
        with mock.patch.object(m.urllib.request, "build_opener") as build:
            for host in ("http://example.test", "https://user:password@example.test", "https://example.test/path", "https://example.test?key=value"):
                self.assertFalse(m.verify_owner(host, "synthetic-secret")[0])
            build.assert_not_called()
        self.assertIsNone(m.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.example"))

    def test_owner_probe_rejects_transport_failure_and_missing_key(self):
        m = load_script()
        with mock.patch.object(m.urllib.request, "build_opener") as build:
            self.assertFalse(m.verify_owner("https://example.test", None)[0])
            build.assert_not_called()
            build.return_value.open.side_effect = OSError("synthetic network failure")
            self.assertFalse(m.verify_owner("https://example.test", "synthetic-secret")[0])

    def test_owner_probe_validates_status_envelope_and_tier(self):
        m = load_script()
        class Reply:
            def __init__(self, status, headers, body):
                self.status, self.headers, self.body = status, headers, body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self):
                return self.body.encode()
        for status, tier, body, expected in (
                (200, "owner", '{"result":{"content":[{"type":"text","text":"ok"}]}}', True),
                (200, "partner", '{"result":{"content":[{}]}}', False),
                (200, "free", '{"result":{"content":[{}]}}', False),
                (200, "", '{"result":{"content":[{}]}}', False),
                (403, "owner", '{}', False), (503, "owner", '{}', False),
                (200, "owner", '', False), (200, "owner", '{"error":{"code":-32029}}', False)):
            with self.subTest(status=status, tier=tier, body=body):
                replies = [Reply(200, {"Mcp-Session-Id": "a" * 64}, '{"result":{}}'),
                           Reply(202, {}, ''), Reply(status, {"x-quota-tier": tier}, body), Reply(204, {}, '')]
                with mock.patch.object(m.urllib.request, "build_opener") as build:
                    build.return_value.open.side_effect = replies
                    self.assertEqual(m.verify_owner("https://example.test", "synthetic-secret")[0], expected)


if __name__ == "__main__":
    unittest.main()
