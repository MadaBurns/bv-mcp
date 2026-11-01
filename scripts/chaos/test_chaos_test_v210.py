#!/usr/bin/env python3
"""Offline tests for chaos-test-v210.py's result classification (no network)."""

import contextlib
import importlib.util
import io
import pathlib
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).with_name("chaos-test-v210.py")


def load_script():
    spec = importlib.util.spec_from_file_location("chaos_test_v210", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


QUOTA_BODY = '{"jsonrpc":"2.0","id":1,"error":{"code":-32029,"message":"Rate limit exceeded. check_spf is limited to 25 requests"}}'
WAF_BODY = '<!DOCTYPE html>\n<html class="no-js" lang="en-US"><head><title>Attention Required! | Cloudflare</title></head></html>'


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.m = load_script()
        self.m.results.clear()

    def record(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.m.record(*args)
        return out.getvalue()

    def test_quota_refusal_needs_429_and_the_jsonrpc_code(self):
        self.assertTrue(self.m.is_quota_refusal(429, QUOTA_BODY))
        self.assertFalse(self.m.is_quota_refusal(429, '{"error":{"code":-32600}}'))
        self.assertFalse(self.m.is_quota_refusal(200, QUOTA_BODY))
        self.assertFalse(self.m.is_quota_refusal(429, None))

    def test_edge_waf_block_is_an_html_403_from_cloudflare(self):
        self.assertTrue(self.m.is_edge_waf_block(403, WAF_BODY))
        self.assertFalse(self.m.is_edge_waf_block(403, '{"error":"Forbidden: invalid Origin header"}'))
        self.assertFalse(self.m.is_edge_waf_block(404, WAF_BODY))
        self.assertFalse(self.m.is_edge_waf_block(403, None))

    def test_a_failed_check_while_the_last_response_was_a_quota_refusal_is_skipped(self):
        self.m.note_response(429, QUOTA_BODY)
        out = self.record("1k. tools/call check_spf → 200", False, "got 429")
        self.assertIn("[SKIPPED-QUOTA]", out)
        # A follow-on check that inspects the same refused body is skipped too (1l after 1k).
        out = self.record("1l. check_spf has text content", False, "content=empty")
        self.assertIn("[SKIPPED-QUOTA]", out)
        self.assertEqual(self.m.results, [])

    def test_a_passing_check_on_a_quota_refusal_still_passes(self):
        # The rate-limit envelope checks expect a 429; they must still count as passes.
        self.m.note_response(429, QUOTA_BODY)
        out = self.record("10a. 429 carries the -32029 envelope", True)
        self.assertIn("[PASS]", out)
        self.assertEqual(self.m.results, [("10a. 429 carries the -32029 envelope", True)])

    def test_a_later_good_response_clears_the_refusal_for_the_next_check(self):
        self.m.note_response(429, QUOTA_BODY)
        self.record("13b. earlier check", True)
        self.m.note_response(200, '{"result":{}}')
        out = self.record("13c. Nonexistent session → 404", False, "got 500")
        self.assertIn("[FAIL]", out)
        self.assertEqual(self.m.results[-1], ("13c. Nonexistent session → 404", False))

    def test_a_concurrent_refusal_followed_by_a_good_response_still_skips(self):
        # 18c: check_spf was refused, then check_mx/check_dmarc answered 200 on other threads.
        self.m.note_response(429, QUOTA_BODY)
        self.m.note_response(200, '{"result":{}}')
        out = self.record("18c. 3 concurrent tools same domain → all 200", False, "statuses=[429, 200, 200]")
        self.assertIn("[SKIPPED-QUOTA]", out)
        # The next check starts clean.
        out = self.record("19a. format=compact → success", False, "status=500")
        self.assertIn("[FAIL]", out)

    def test_curl_json_notes_each_response(self):
        completed = mock.Mock(stdout=QUOTA_BODY + "\n429")
        with mock.patch.object(self.m.subprocess, "run", return_value=completed):
            status, _, _ = self.m.curl_json("POST", "/mcp", body={"jsonrpc": "2.0"})
        self.assertEqual(status, 429)
        self.assertTrue(self.m._quota_refused)
        completed.stdout = '{"result":{}}\n200'
        with mock.patch.object(self.m.subprocess, "run", return_value=completed):
            self.m.curl_json("POST", "/mcp", body={"jsonrpc": "2.0"})
        self.assertFalse(self.m._quota_refused)


if __name__ == "__main__":
    unittest.main()
