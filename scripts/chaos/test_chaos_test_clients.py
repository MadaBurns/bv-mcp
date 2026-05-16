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


if __name__ == "__main__":
    unittest.main()
