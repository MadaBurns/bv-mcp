#!/usr/bin/env python3
"""
bv-mcp OAuth production smoke/redirect/e2e probe.

Modes:
  --mode=smoke   → POST junk payload to /oauth/token; expect 4xx (invalid_grant).
                   Verifies routing/rate-limiting works. Not a secret-presence test.
  --mode=redirect → register → authorize GET; expect 302 to bv-web customer consent.
                   Verifies modern customer-login OAuth is configured.
  --mode=e2e     → Legacy owner-key flow: register → authorize → token → /mcp with JWT.
                   Requires BV_API_KEY environment variable.

Environment:
  BV_MCP_BASE    → Base URL (default: https://dns-mcp.blackveilsecurity.com)
  BV_API_KEY     → Owner API key (required only for legacy --mode=e2e)

Exit codes:
  0  → Expected outcome
  1  → Unexpected outcome (FAIL: <reason> to stderr)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request
from typing import Optional
from urllib.error import HTTPError


BASE = os.getenv("BV_MCP_BASE", "https://dns-mcp.blackveilsecurity.com")
TIMEOUT = 10
CUSTOMER_CONSENT_URL = "https://www.blackveilsecurity.com/oauth/mcp/consent"
PROBE_REDIRECT_URI = "https://claude.ai/cb"
PROBE_SCOPE = "mcp"
PROBE_STATE = "state123"


def base64url(data: bytes) -> str:
    """Encode data as URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def pkce_pair() -> tuple[str, str]:
    """Generate PKCE (code_verifier, code_challenge) pair."""
    verifier = base64url(os.urandom(32))
    challenge = base64url(
        hashlib.sha256(verifier.encode("ascii")).digest()
    )
    return verifier, challenge


def smoke_mode() -> int:
    """
    POST junk to /oauth/token; expect 400 invalid_grant.
    Fail on 5xx, unexpected 2xx, or 4xx that isn't invalid_grant.
    """
    try:
        data = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": "junk",
            "redirect_uri": "https://claude.ai/cb",
            "client_id": "junk",
            "code_verifier": "junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk",
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{BASE}/oauth/token",
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "bv-mcp-smoke-probe/1.0",
            },
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req, timeout=TIMEOUT)
            status = resp.status
            # Unexpected 2xx
            print(
                f"FAIL: got {status} (unexpected for junk payload)",
                file=sys.stderr,
            )
            return 1
        except HTTPError as e:
            status = e.code
            body = e.read().decode("utf-8")

            if status == 400:
                # Check for invalid_grant in response
                if "invalid_grant" in body:
                    print(f"OK: got 400 with invalid_grant (expected)")
                    return 0
                else:
                    print(
                        f"FAIL: got 400 but missing invalid_grant. Body: {body[:200]}",
                        file=sys.stderr,
                    )
                    return 1
            elif 400 <= status < 500:
                # Other 4xx is unexpected
                print(
                    f"FAIL: got {status} (expected 400 invalid_grant). Body: {body[:200]}",
                    file=sys.stderr,
                )
                return 1
            else:
                # 5xx or other
                print(
                    f"FAIL: got {status} (expected 400). Body: {body[:200]}",
                    file=sys.stderr,
                )
                return 1
    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1


def get_json(url: str) -> tuple[int, Optional[dict]]:
    """GET JSON; return (status_code, parsed_json or None)."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "bv-mcp-oauth-probe/1.0"},
        method="GET",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        body = resp.read().decode("utf-8")
        return resp.status, json.loads(body)
    except HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, None


def post_json(url: str, obj: dict) -> tuple[int, Optional[dict]]:
    """POST JSON; return (status_code, parsed_json or None)."""
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        body = resp.read().decode("utf-8")
        return resp.status, json.loads(body)
    except HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, None


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """urllib handler that exposes 302 responses instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_no_redirect(url: str) -> tuple[int, str, Optional[str]]:
    """GET without following redirects; return (status, body_text, Location)."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "bv-mcp-oauth-probe/1.0"},
        method="GET",
    )
    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        resp = opener.open(req, timeout=TIMEOUT)
        body = resp.read().decode("utf-8")
        return resp.status, body, resp.headers.get("Location")
    except HTTPError as e:
        body = e.read().decode("utf-8")
        return e.code, body, e.headers.get("Location")


def post_form(url: str, data: dict) -> tuple[int, Optional[dict], Optional[str]]:
    """POST form data; return (status_code, parsed_json or None, Location header or None)."""
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        body = resp.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        return resp.status, parsed, resp.headers.get("Location")
    except HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        return e.code, parsed, e.headers.get("Location")


def redirect_mode() -> int:
    """
    Probe modern customer OAuth: discovery → register → authorize GET.
    Expects /oauth/authorize to 302 to the bv-web customer consent URL with
    the OAuth request parameters preserved. Does not require BV_API_KEY.
    """
    try:
        status, metadata = get_json(f"{BASE}/.well-known/oauth-authorization-server")
        if status != 200 or not metadata:
            print(
                f"FAIL: discovery returned {status}, expected 200 JSON",
                file=sys.stderr,
            )
            return 1

        authorization_endpoint = metadata.get("authorization_endpoint")
        registration_endpoint = metadata.get("registration_endpoint")
        if not isinstance(authorization_endpoint, str) or not authorization_endpoint:
            print("FAIL: discovery missing authorization_endpoint", file=sys.stderr)
            return 1
        if not isinstance(registration_endpoint, str) or not registration_endpoint:
            print("FAIL: discovery missing registration_endpoint", file=sys.stderr)
            return 1

        status, reg_data = post_json(
            registration_endpoint,
            {
                "redirect_uris": [PROBE_REDIRECT_URI],
                "client_name": "bv-mcp-redirect-probe",
            },
        )
        if status != 201 or not reg_data:
            print(
                f"FAIL: register returned {status}, expected 201 JSON",
                file=sys.stderr,
            )
            return 1
        client_id = reg_data.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            print("FAIL: register response missing client_id", file=sys.stderr)
            return 1

        _, challenge = pkce_pair()
        expected_params = {
            "client_id": client_id,
            "redirect_uri": PROBE_REDIRECT_URI,
            "state": PROBE_STATE,
            "scope": PROBE_SCOPE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        auth_params = {
            **expected_params,
            "response_type": "code",
        }
        auth_url = f"{authorization_endpoint}?{urllib.parse.urlencode(auth_params)}"

        status, body, location = get_no_redirect(auth_url)
        if status != 302:
            detail = body[:200] if body else "no response body"
            print(
                f"FAIL: authorize returned {status}, expected 302. Body: {detail}",
                file=sys.stderr,
            )
            return 1
        if not location:
            print("FAIL: authorize response missing Location header", file=sys.stderr)
            return 1

        actual = urllib.parse.urlparse(location)
        expected = urllib.parse.urlparse(CUSTOMER_CONSENT_URL)
        if (
            actual.scheme,
            actual.netloc,
            actual.path,
        ) != (
            expected.scheme,
            expected.netloc,
            expected.path,
        ):
            print(
                f"FAIL: authorize redirected to {actual.scheme}://{actual.netloc}{actual.path}, expected {CUSTOMER_CONSENT_URL}",
                file=sys.stderr,
            )
            return 1

        actual_qs = urllib.parse.parse_qs(actual.query)
        missing = []
        for name, expected_value in expected_params.items():
            if actual_qs.get(name, [None])[0] != expected_value:
                missing.append(name)
        if missing:
            print(
                f"FAIL: consent redirect missing or changed OAuth params: {', '.join(missing)}",
                file=sys.stderr,
            )
            return 1

        print(f"OK: authorize redirects to customer consent with {len(expected_params)} OAuth params preserved")
        return 0

    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1


def e2e_mode() -> int:
    """
    Legacy owner-key OAuth flow: register → authorize → token → /mcp.
    Requires BV_API_KEY.
    """
    api_key = os.getenv("BV_API_KEY")
    if not api_key:
        print(
            "FAIL: BV_API_KEY environment variable not set (required for --mode=e2e)",
            file=sys.stderr,
        )
        return 1

    try:
        # Step 1: register
        status, reg_data = post_json(
            f"{BASE}/oauth/register",
            {
                "redirect_uris": ["https://claude.ai/cb"],
                "client_name": "bv-mcp-probe",
            },
        )
        if status != 201:
            print(
                f"FAIL: register returned {status}",
                file=sys.stderr,
            )
            return 1
        if not reg_data:
            print("FAIL: register response not JSON", file=sys.stderr)
            return 1
        client_id = reg_data.get("client_id")
        if not client_id:
            print("FAIL: register response missing client_id", file=sys.stderr)
            return 1

        # Step 2: generate PKCE
        verifier, challenge = pkce_pair()

        # Step 3: authorize (POST with api_key + query params)
        auth_params = {
            "client_id": client_id,
            "redirect_uri": "https://claude.ai/cb",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp",
            "state": "state123",
        }
        query_string = urllib.parse.urlencode(auth_params)

        status, _, location = post_form(
            f"{BASE}/oauth/authorize",
            {"api_key": api_key, "_q": query_string},
        )
        if status != 302:
            print(
                f"FAIL: authorize returned {status}, expected 302 redirect",
                file=sys.stderr,
            )
            return 1
        if not location:
            print("FAIL: authorize response missing Location header", file=sys.stderr)
            return 1

        # Extract code from redirect
        parsed = urllib.parse.urlparse(location)
        qs = urllib.parse.parse_qs(parsed.query)
        code = qs.get("code", [None])[0]
        if not code:
            print("FAIL: redirect missing code parameter", file=sys.stderr)
            return 1

        # Step 4: token exchange
        status, token_data = post_form(
            f"{BASE}/oauth/token",
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://claude.ai/cb",
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )
        if status != 200:
            print(
                f"FAIL: token exchange returned {status}",
                file=sys.stderr,
            )
            if token_data:
                print(f"  Error: {token_data.get('error')}", file=sys.stderr)
            return 1

        if not token_data:
            print("FAIL: token response not JSON", file=sys.stderr)
            return 1
        access_token = token_data.get("access_token")
        if not access_token:
            print("FAIL: token response missing access_token", file=sys.stderr)
            return 1

        # Step 5: /mcp call with JWT
        mcp_data = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{BASE}/mcp",
            data=mcp_data,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req, timeout=TIMEOUT)
            body = resp.read().decode("utf-8")
            mcp_result = json.loads(body)
        except HTTPError as e:
            print(
                f"FAIL: /mcp returned {e.code}",
                file=sys.stderr,
            )
            return 1

        tools = mcp_result.get("result", {}).get("tools", [])
        if len(tools) < 40:
            print(
                f"FAIL: /mcp returned {len(tools)} tools, expected ≥40",
                file=sys.stderr,
            )
            return 1

        print(f"OK: e2e flow complete, {len(tools)} tools available")
        return 0

    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OAuth production smoke/redirect/e2e probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--mode",
        choices=["smoke", "redirect", "e2e"],
        required=True,
        help="Probe mode: smoke (routing check), redirect (customer consent), or e2e (legacy owner flow)",
    )
    args = parser.parse_args()

    if args.mode == "smoke":
        return smoke_mode()
    elif args.mode == "redirect":
        return redirect_mode()
    else:
        return e2e_mode()


if __name__ == "__main__":
    sys.exit(main())
