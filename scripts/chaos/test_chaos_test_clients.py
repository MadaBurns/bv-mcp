#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import unittest


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


if __name__ == "__main__":
    unittest.main()
