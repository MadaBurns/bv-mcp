#!/usr/bin/env python3
"""
bv-mcp OAuth production smoke/e2e probe.

Two modes:
  --mode=smoke   → POST junk payload to /oauth/token; expect 4xx (invalid_grant).
                   Verifies routing/rate-limiting works. Not a secret-presence test.
  --mode=e2e     → Full flow: register → authorize → token → /mcp with JWT.
                   Requires BV_API_KEY environment variable.

Environment:
  BV_MCP_BASE    → Base URL (default: https://dns-mcp.blackveilsecurity.com)
  BV_API_KEY     → Owner API key (required for --mode=e2e)

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


def e2e_mode() -> int:
    """
    Full OAuth flow: register → authorize → token → /mcp.
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
        description="OAuth production smoke/e2e probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--mode",
        choices=["smoke", "e2e"],
        required=True,
        help="Probe mode: smoke (routing check) or e2e (full flow)",
    )
    args = parser.parse_args()

    if args.mode == "smoke":
        return smoke_mode()
    else:
        return e2e_mode()


if __name__ == "__main__":
    sys.exit(main())
