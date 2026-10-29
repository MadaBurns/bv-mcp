#!/usr/bin/env python3
"""Offline tests for chaos-fix-regression.py (no network)."""
import contextlib
import importlib.util
import io
import json
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("chaos-fix-regression.py")


def load_script():
    spec = importlib.util.spec_from_file_location("chaos_fix_regression", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load_script()


def sse(payload):
    return "id: 1\nevent: message\ndata: " + json.dumps(payload) + "\n\n"


def tool_reply(text, is_error=False):
    result = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    return sse({"jsonrpc": "2.0", "id": 5, "result": result})


def rpc_err(code, message="m"):
    return sse({"jsonrpc": "2.0", "id": 5, "error": {"code": code, "message": message}})


class BodyParsingTest(unittest.TestCase):
    def test_sse_and_plain_json_bodies(self):
        self.assertEqual(M.safe_parse(sse({"a": 1})), {"a": 1})
        self.assertEqual(M.safe_parse('{"a": 2}'), {"a": 2})

    def test_garbage_and_empty_parse_to_none(self):
        self.assertIsNone(M.safe_parse("not json"))
        self.assertIsNone(M.safe_parse(""))
        self.assertEqual(M.rpc_error("ERROR: URLError"), (None, None))

    def test_rpc_error_extracts_code_and_message(self):
        self.assertEqual(M.rpc_error(rpc_err(-32002, "Resource not found: x")), (-32002, "Resource not found: x"))

    def test_tool_output_joins_text_and_reads_is_error(self):
        body = sse({"result": {"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}], "isError": True}})
        self.assertEqual(M.tool_output(body), ("a\nb", True))
        self.assertEqual(M.tool_output(tool_reply("ok")), ("ok", False))
        self.assertEqual(M.tool_output(rpc_err(-32603)), (None, None))

    def test_quota_reply_detection(self):
        self.assertTrue(M.is_quota_reply(200, rpc_err(-32029, "anything at all")))
        self.assertTrue(M.is_quota_reply(429, rpc_err(-32000, "Retry after 5s")))
        self.assertFalse(M.is_quota_reply(200, tool_reply("fine")))
        self.assertFalse(M.is_quota_reply(500, rpc_err(-32603, "boom")))


class KeyParserTest(unittest.TestCase):
    def test_plain_quoted_and_export_forms(self):
        self.assertEqual(M.parse_dev_vars_key("BV_INTERNAL_DEV_KEY=abc123\n"), "abc123")
        self.assertEqual(M.parse_dev_vars_key('BV_INTERNAL_DEV_KEY="abc 123"\n'), "abc 123")
        self.assertEqual(M.parse_dev_vars_key("BV_INTERNAL_DEV_KEY='abc'\n"), "abc")
        self.assertEqual(M.parse_dev_vars_key("export BV_INTERNAL_DEV_KEY = abc\n"), "abc")

    def test_commented_lines_never_match(self):
        self.assertIsNone(M.parse_dev_vars_key("# BV_INTERNAL_DEV_KEY=secret\n"))
        self.assertIsNone(M.parse_dev_vars_key("   #BV_INTERNAL_DEV_KEY=secret\n"))
        text = "# BV_INTERNAL_DEV_KEY=old\nBV_INTERNAL_DEV_KEY=live\n"
        self.assertEqual(M.parse_dev_vars_key(text), "live")

    def test_inline_comment_and_unrelated_names(self):
        self.assertEqual(M.parse_dev_vars_key("BV_INTERNAL_DEV_KEY=abc # note\n"), "abc")
        self.assertIsNone(M.parse_dev_vars_key("BV_INTERNAL_DEV_KEY_OTHER=abc\nOTHER_BV_INTERNAL_DEV_KEY=x\n"))

    def test_empty_value_is_none(self):
        self.assertIsNone(M.parse_dev_vars_key("BV_INTERNAL_DEV_KEY=\n"))
        self.assertIsNone(M.parse_dev_vars_key('BV_INTERNAL_DEV_KEY=""\n'))
        self.assertIsNone(M.parse_dev_vars_key(""))

    def test_env_override_wins_without_touching_git(self):
        self.assertEqual(M.resolve_key(env={"BV_VERIFY_KEY": " k1 "}), "k1")


class OauthTokenTest(unittest.TestCase):
    def test_4xx_with_no_store_passes(self):
        verdict, _ = M.classify_oauth_token(400, "no-store")
        self.assertEqual(verdict, M.PASS)
        self.assertEqual(M.classify_oauth_token(401, "private, No-Store")[0], M.PASS)

    def test_missing_no_store_fails(self):
        self.assertEqual(M.classify_oauth_token(400, None)[0], M.FAIL)
        self.assertEqual(M.classify_oauth_token(400, "max-age=60")[0], M.FAIL)

    def test_non_4xx_fails_and_429_is_skipped(self):
        self.assertEqual(M.classify_oauth_token(200, "no-store")[0], M.FAIL)
        self.assertEqual(M.classify_oauth_token(500, "no-store")[0], M.FAIL)
        self.assertEqual(M.classify_oauth_token(429, "no-store")[0], M.SKIPPED)


class ProtocolErrorsTest(unittest.TestCase):
    def test_resource_read(self):
        self.assertEqual(M.classify_resource_read(400, rpc_err(-32002))[0], M.PASS)
        self.assertEqual(M.classify_resource_read(200, rpc_err(-32002))[0], M.FAIL)
        self.assertEqual(M.classify_resource_read(400, rpc_err(-32603))[0], M.FAIL)
        self.assertEqual(M.classify_resource_read(400, "")[0], M.FAIL)

    def test_prompt_get(self):
        self.assertEqual(M.classify_prompt_get(400, rpc_err(-32602))[0], M.PASS)
        self.assertEqual(M.classify_prompt_get(400, rpc_err(-32603))[0], M.FAIL)
        self.assertEqual(M.classify_prompt_get(500, rpc_err(-32602))[0], M.FAIL)
        self.assertEqual(M.classify_prompt_get(400, "not json")[0], M.FAIL)


class DomainValidationTest(unittest.TestCase):
    REJECT = tool_reply('Error: Domain validation failed: Domain "home.arpa" is not allowed', True)
    ACCEPT = tool_reply("## MX Check\n**Status:** Passed")

    def outcomes(self, reserved, control):
        out = {d: M.classify_domain_validation(200, reserved) for d in M.RESERVED_DOMAINS}
        out[M.POSITIVE_CONTROL_DOMAIN] = M.classify_domain_validation(200, control)
        return out

    def test_single_domain_kinds(self):
        self.assertEqual(M.classify_domain_validation(200, self.REJECT)[0], "rejected")
        self.assertEqual(M.classify_domain_validation(200, self.ACCEPT)[0], "accepted")
        self.assertEqual(M.classify_domain_validation(200, rpc_err(-32029, "quota"))[0], "quota")
        self.assertEqual(M.classify_domain_validation(200, tool_reply("timeout talking to DoH", True))[0], "unknown")
        self.assertEqual(M.classify_domain_validation(0, "ERROR: URLError")[0], "unknown")

    def test_all_rejected_with_accepted_control_passes(self):
        self.assertEqual(M.classify_reserved_domains(self.outcomes(self.REJECT, self.ACCEPT))[0], M.PASS)

    def test_reserved_domain_accepted_fails(self):
        verdict, detail = M.classify_reserved_domains(self.outcomes(self.ACCEPT, self.ACCEPT))
        self.assertEqual(verdict, M.FAIL)
        self.assertIn("home.arpa=accepted", detail)

    def test_rejected_positive_control_fails(self):
        verdict, detail = M.classify_reserved_domains(self.outcomes(self.REJECT, self.REJECT))
        self.assertEqual(verdict, M.FAIL)
        self.assertIn("isc.org=rejected", detail)

    def test_quota_skips(self):
        quota = rpc_err(-32029, "requests per day")
        self.assertEqual(M.classify_reserved_domains(self.outcomes(quota, self.ACCEPT))[0], M.SKIPPED)


class NxdomainTest(unittest.TestCase):
    def test_does_not_resolve_passes(self):
        body = tool_reply("x.com does not resolve (NXDOMAIN), so its infrastructure was not assessed.")
        self.assertEqual(M.classify_nxdomain(200, body, "x.com")[0], M.PASS)

    def test_other_answers_fail(self):
        self.assertEqual(M.classify_nxdomain(200, tool_reply("All nameservers healthy"), "x.com")[0], M.FAIL)
        self.assertEqual(M.classify_nxdomain(500, "", "x.com")[0], M.FAIL)

    def test_quota_skips(self):
        self.assertEqual(M.classify_nxdomain(200, rpc_err(-32029), "x.com")[0], M.SKIPPED)


class RdapTest(unittest.TestCase):
    def reply(self, registrar_sentence):
        return tool_reply("## RDAP Check\n- Registration details\n  " + registrar_sentence + "\n  Confidence: deterministic")

    def test_extract_registrar_variants(self):
        self.assertEqual(M.extract_registrar("Registrar: EURid vzw. Source: whois."), "EURid vzw")
        self.assertEqual(M.extract_registrar("Registrar: DNS BE vzw/asbl. Created: 2012-06-13. Source: whois."),
                         "DNS BE vzw/asbl")
        self.assertEqual(M.extract_registrar("Registrar: Example Inc. Created: 2020-01-01."), "Example Inc")
        self.assertEqual(M.extract_registrar("Registrar: Lone Name"), "Lone Name")
        self.assertEqual(M.extract_registrar("Registrar: . Source: whois."), "")
        self.assertEqual(M.extract_registrar("No registrar line here"), "")

    def test_both_names_present_passes_and_reports_them(self):
        responses = {
            "eurid.eu": (200, self.reply("Registrar: EURid vzw. Source: whois.")),
            "dnsbelgium.be": (200, self.reply("Registrar: DNS BE vzw/asbl. Created: 2012-06-13. Source: whois.")),
        }
        verdict, detail = M.classify_rdap(responses)
        self.assertEqual(verdict, M.PASS)
        self.assertIn("EURid vzw", detail)
        self.assertIn("DNS BE vzw/asbl", detail)

    def test_missing_or_empty_name_fails(self):
        responses = {
            "eurid.eu": (200, self.reply("Created: 2012-06-13. Source: whois.")),
            "dnsbelgium.be": (200, self.reply("Registrar: DNS BE vzw/asbl. Source: whois.")),
        }
        verdict, detail = M.classify_rdap(responses)
        self.assertEqual(verdict, M.FAIL)
        self.assertIn("eurid.eu", detail)

    def test_non_result_body_fails_and_quota_skips(self):
        self.assertEqual(M.classify_rdap({"eurid.eu": (500, "boom")})[0], M.FAIL)
        self.assertEqual(M.classify_rdap({"eurid.eu": (200, rpc_err(-32029))})[0], M.SKIPPED)


class SessionsTest(unittest.TestCase):
    def sample(self, list_status=200, init_status=200, init_ms=100.0, notif_ms=50.0, quota=False):
        return M.Sample(init_status, init_ms, notif_ms, list_status, quota)

    def test_all_ok_reports_median_and_max(self):
        samples = [self.sample(init_ms=ms) for ms in (100.0, 300.0, 200.0)]
        verdict, detail = M.classify_sessions(samples)
        self.assertEqual(verdict, M.PASS)
        self.assertIn("sessions=3", detail)
        self.assertIn("init_median=200ms", detail)
        self.assertIn("init_max=300ms", detail)
        self.assertIn("404s=0", detail)

    def test_any_404_fails(self):
        verdict, detail = M.classify_sessions([self.sample(), self.sample(list_status=404)])
        self.assertEqual(verdict, M.FAIL)
        self.assertIn("404s=1", detail)

    def test_other_failures_fail(self):
        self.assertEqual(M.classify_sessions([self.sample(list_status=500)])[0], M.FAIL)
        failed_init = M.Sample(0, 10.0, None, 0, False)
        self.assertEqual(M.classify_sessions([self.sample(), failed_init])[0], M.FAIL)

    def test_quota_samples_are_excluded_and_all_quota_skips(self):
        self.assertEqual(M.classify_sessions([self.sample(), self.sample(list_status=429, quota=True)])[0], M.PASS)
        self.assertEqual(M.classify_sessions([self.sample(quota=True)])[0], M.SKIPPED)


class ExitCodeAndCliTest(unittest.TestCase):
    def results(self, *verdicts):
        return [M.Result(v, "SQ-%d" % i, "d") for i, v in enumerate(verdicts)]

    def test_exit_code_mapping(self):
        self.assertEqual(M.exit_code(self.results(M.PASS, M.SKIPPED, M.NOT_EXERCISED)), 0)
        self.assertEqual(M.exit_code(self.results(M.PASS, M.FAIL)), 1)
        self.assertEqual(M.exit_code([]), 0)

    def test_line_format(self):
        self.assertEqual(M.format_line(M.Result(M.PASS, "SQ-448", "HTTP 400")), "PASS  SQ-448  HTTP 400")

    def test_usage_errors_exit_2(self):
        for argv in (["--sessions", "0"], ["--host", "not-a-url"], ["--host", "https://x.example/path"],
                     ["--sessions", "many"], ["--bogus"]):
            with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()):
                M.main(argv, key="k", emit=lambda line: None)
            self.assertEqual(ctx.exception.code, 2, argv)

    def test_main_maps_runner_results_to_exit_code(self):
        original = M.Runner.run
        try:
            for verdicts, expected in (((M.PASS,), 0), ((M.PASS, M.FAIL), 1)):
                M.Runner.run = lambda self, v=verdicts: [M.Result(x, "SQ-0", "d") for x in v]
                lines = []
                self.assertEqual(M.main([], key="k", emit=lines.append), expected)
                self.assertIn("key=present", lines[0])
        finally:
            M.Runner.run = original

    def test_key_never_appears_in_header_line(self):
        original = M.Runner.run
        try:
            M.Runner.run = lambda self: []
            lines = []
            M.main([], key="s3cret-value", emit=lines.append)
            self.assertNotIn("s3cret-value", "\n".join(lines))
        finally:
            M.Runner.run = original

    def test_runner_without_key_skips_tool_checks_offline(self):
        r = M.Runner("https://h.example", None, 1, lambda line: None)
        r.check_oauth_token = lambda: None
        r.open_session = lambda: None
        r.check_protocol_errors = lambda session: None
        r.check_sessions = lambda: None
        verdicts = {x.check: x.verdict for x in r.run()}
        for check in ("SQ-452", "SQ-447", "SQ-451"):
            self.assertEqual(verdicts[check], M.SKIPPED)
        self.assertEqual(verdicts["SQ-450"], M.NOT_EXERCISED)


if __name__ == "__main__":
    unittest.main()
