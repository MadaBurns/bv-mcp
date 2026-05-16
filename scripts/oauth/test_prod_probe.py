#!/usr/bin/env python3
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import unittest
import urllib.parse
from unittest import mock


SCRIPT = pathlib.Path(__file__).with_name("prod-probe.py")
CONSENT_URL = "https://www.blackveilsecurity.com/oauth/mcp/consent"


def load_script():
    spec = importlib.util.spec_from_file_location("prod_probe", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, status, body="", headers=None):
        self.status = status
        self._body = body.encode("utf-8")
        self.headers = headers or {}

    def read(self):
        return self._body


class FakeOpener:
    def __init__(self, response, requests):
        self.response = response
        self.requests = requests

    def open(self, req, timeout=None):
        self.requests.append(req)
        return self.response


class ProdProbeRedirectTest(unittest.TestCase):
    def run_redirect(self, authorize_response):
        module = load_script()
        module.BASE = "https://mcp.example"

        authorize_requests = []

        def fake_urlopen(req, timeout=None):
            if req.full_url == "https://mcp.example/.well-known/oauth-authorization-server":
                return FakeResponse(
                    200,
                    json.dumps({
                        "issuer": "https://mcp.example",
                        "authorization_endpoint": "https://mcp.example/oauth/authorize",
                        "registration_endpoint": "https://mcp.example/oauth/register",
                    }),
                )
            if req.full_url == "https://mcp.example/oauth/register":
                headers = {name.lower(): value for name, value in req.header_items()}
                self.assertEqual(headers.get("user-agent"), module.USER_AGENT)
                return FakeResponse(201, json.dumps({"client_id": "client_123"}))
            self.fail(f"unexpected request to {req.full_url}")

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(module.sys, "argv", ["prod-probe.py", "--mode=redirect"]):
                with mock.patch.object(module, "pkce_pair", return_value=("verifier", "challenge_value")):
                    with mock.patch.object(module.urllib.request, "urlopen", side_effect=fake_urlopen):
                        with mock.patch.object(
                            module.urllib.request,
                            "build_opener",
                            return_value=FakeOpener(authorize_response, authorize_requests),
                        ):
                            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                                try:
                                    code = module.main()
                                except SystemExit as e:
                                    code = e.code

        return code, stdout.getvalue(), stderr.getvalue(), authorize_requests

    def test_redirect_mode_fails_when_authorize_returns_customer_login_not_configured(self):
        code, _, stderr, _ = self.run_redirect(
            FakeResponse(503, "OAuth customer login is not configured"),
        )

        self.assertEqual(code, 1)
        self.assertIn("OAuth customer login is not configured", stderr)

    def test_redirect_mode_accepts_customer_consent_redirect_with_oauth_params_preserved(self):
        location = (
            f"{CONSENT_URL}?"
            + urllib.parse.urlencode({
                "client_id": "client_123",
                "redirect_uri": "https://claude.ai/cb",
                "state": "state123",
                "scope": "mcp",
                "code_challenge": "challenge_value",
                "code_challenge_method": "S256",
            })
        )

        code, stdout, stderr, authorize_requests = self.run_redirect(
            FakeResponse(302, "", headers={"Location": location}),
        )

        self.assertEqual(code, 0, stderr)
        self.assertIn("OK:", stdout)

        self.assertEqual(len(authorize_requests), 1)
        parsed_request = urllib.parse.urlparse(authorize_requests[0].full_url)
        request_qs = urllib.parse.parse_qs(parsed_request.query)
        for name, expected in {
            "client_id": "client_123",
            "redirect_uri": "https://claude.ai/cb",
            "state": "state123",
            "scope": "mcp",
            "code_challenge": "challenge_value",
            "code_challenge_method": "S256",
        }.items():
            self.assertEqual(request_qs.get(name), [expected], name)


if __name__ == "__main__":
    unittest.main()
