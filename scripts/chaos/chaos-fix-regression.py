#!/usr/bin/env python3
"""
bv-mcp live regression probe for the 2026-10-29 chaos fixes.

Runs one read-only probe per fix against a deployed host and prints one line each:

    PASS | FAIL | SKIPPED | NOT-EXERCISED  <id>  <detail>

What it proves (live, against the host you point it at):
  SQ-448  POST /oauth/token with a bogus authorization_code is a 4xx carrying
          Cache-Control: no-store.
  SQ-449  resources/read with an unknown URI is HTTP 400 + JSON-RPC -32002;
          prompts/get with an unknown name is HTTP 400 + a code other than -32603.
  SQ-452  check_mx rejects home.arpa, foo.home.arpa and service.arpa at domain
          validation, while the positive control isc.org is accepted.
  SQ-447  check_authoritative_dns_infra on a per-run random non-existent .com
          answers "does not resolve".
  SQ-451  rdap_lookup on eurid.eu and dnsbelgium.be reports a non-empty registrar.
  SQ-453  N fresh anonymous sessions, each followed by tools/list, never 404;
          initialize latency (median/max) is reported, timed apart from
          notifications/initialized.

What it does NOT prove:
  * No 429 path: Retry-After on a rate-limited /oauth/token is reported
    NOT-EXERCISED, because the probe never trips the production limiter.
  * SQ-450 (internal latency) has no external signal: NOT-EXERCISED.
  * Live-only: nothing here replaces the Vitest suite, and a green run says
    nothing about builds that are not deployed to --host.

Auth: tool calls use an authenticated session. The key comes from the env var
BV_VERIFY_KEY, else BV_INTERNAL_DEV_KEY parsed from the main checkout's
.dev.vars (found via `git rev-parse --path-format=absolute --git-common-dir`).
The key is only ever sent in the Authorization header; it is never printed,
placed in argv, or logged. Without a key the tool-call checks report SKIPPED,
as does any -32029 quota reply.

Exit status: 0 = no FAIL, 1 = at least one FAIL, 2 = usage or prerequisite error.

Python 3.9 compatible, stdlib only.
"""

import argparse
import collections
import importlib.util
import json
import os
import pathlib
import re
import secrets
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request

DEFAULT_HOST = "https://dns-mcp.blackveilsecurity.com"
WORKERS_DEV_HOST = "https://bv-dns-security-mcp.bv-edge.workers.dev"
DEFAULT_SESSIONS = 20
USER_AGENT = "bv-chaos-fix-regression/1.0"
PROTOCOL_VERSION = "2025-03-26"
TOOL_TIMEOUT = 60
HTTP_TIMEOUT = 40

PASS = "PASS"
FAIL = "FAIL"
SKIPPED = "SKIPPED"
NOT_EXERCISED = "NOT-EXERCISED"

RESERVED_DOMAINS = ("home.arpa", "foo.home.arpa", "service.arpa")
RDAP_DOMAINS = ("eurid.eu", "dnsbelgium.be")
POSITIVE_CONTROL_DOMAIN = "isc.org"

Result = collections.namedtuple("Result", "verdict check detail")
Response = collections.namedtuple("Response", "status headers text elapsed_ms")
Sample = collections.namedtuple("Sample", "init_status init_ms notif_ms list_status quota")


def _load_clients_module():
    """Reuse the SSE/quota helpers from chaos-test-clients.py (hyphenated filename)."""
    path = pathlib.Path(__file__).with_name("chaos-test-clients.py")
    spec = importlib.util.spec_from_file_location("chaos_test_clients", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_clients = _load_clients_module()
parse_mcp_body = _clients.parse_mcp_body
is_quota_skip = _clients.is_quota_skip


# --- Parsing helpers (pure) --------------------------------------------------

def safe_parse(text):
    """parse_mcp_body that returns None instead of raising."""
    try:
        return parse_mcp_body(text)
    except Exception:
        return None


def rpc_error(text):
    """(code, message) of a JSON-RPC error envelope, or (None, None)."""
    doc = safe_parse(text)
    err = doc.get("error") if isinstance(doc, dict) else None
    if not isinstance(err, dict):
        return None, None
    code = err.get("code")
    return (code if isinstance(code, int) else None), str(err.get("message", ""))


def tool_output(text):
    """(joined content text, isError) of a tools/call result; (None, None) if not a result."""
    doc = safe_parse(text)
    result = doc.get("result") if isinstance(doc, dict) else None
    if not isinstance(result, dict) or not isinstance(result.get("content"), list):
        return None, None
    parts = [c.get("text", "") for c in result["content"] if isinstance(c, dict) and isinstance(c.get("text"), str)]
    return "\n".join(parts), bool(result.get("isError"))


def is_quota_reply(status, text):
    """A shared-IP quota reply: the existing marker match, or any -32029 code."""
    if is_quota_skip(status, text):
        return True
    code, _ = rpc_error(text)
    return code == -32029


def parse_dev_vars_key(text, name="BV_INTERNAL_DEV_KEY"):
    """Value of `name` in .dev.vars text. Commented lines never match; quotes are stripped."""
    value = None
    pattern = re.compile(r"^(?:export\s+)?" + re.escape(name) + r"\s*=\s*(.*)$")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = pattern.match(line)
        if not m:
            continue
        rest = m.group(1).strip()
        if len(rest) >= 2 and rest[0] in "'\"":
            end = rest.find(rest[0], 1)
            found = rest[1:end] if end != -1 else rest[1:]
        else:
            found = re.split(r"\s+#", rest, maxsplit=1)[0].strip()
        value = found or None
    return value


def main_checkout_dir(start_dir):
    """Main checkout root (parent of the shared .git dir), or None outside a git repo."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
            cwd=str(start_dir), capture_output=True, text=True, timeout=15,
        )
    except Exception:
        return None
    common = r.stdout.strip()
    if r.returncode != 0 or not common:
        return None
    return pathlib.Path(common).parent


def resolve_key(env=None, start_dir=None):
    """BV_VERIFY_KEY from env, else BV_INTERNAL_DEV_KEY from the main checkout's .dev.vars."""
    env = os.environ if env is None else env
    key = (env.get("BV_VERIFY_KEY") or "").strip()
    if key:
        return key
    root = main_checkout_dir(start_dir or pathlib.Path(__file__).parent)
    if root is None:
        return None
    try:
        return parse_dev_vars_key((root / ".dev.vars").read_text(encoding="utf-8"))
    except OSError:
        return None


# --- Classifiers (pure; one per check) ---------------------------------------

def classify_oauth_token(status, cache_control):
    if status == 429:
        return SKIPPED, "rate limited (HTTP 429); not retrying against the production limiter"
    if not 400 <= status < 500:
        return FAIL, "HTTP %s, expected 4xx for a bogus authorization_code" % status
    if "no-store" not in (cache_control or "").lower():
        return FAIL, "HTTP %s but Cache-Control=%r lacks no-store" % (status, cache_control)
    return PASS, "HTTP %s Cache-Control=%s" % (status, cache_control)


def classify_resource_read(status, text):
    code, _ = rpc_error(text)
    if status == 400 and code == -32002:
        return PASS, "HTTP 400 code -32002"
    return FAIL, "HTTP %s code %s, expected HTTP 400 code -32002" % (status, code)


def classify_prompt_get(status, text):
    code, _ = rpc_error(text)
    if status == 400 and code is not None and code != -32603:
        return PASS, "HTTP 400 code %s" % code
    return FAIL, "HTTP %s code %s, expected HTTP 400 and a code other than -32603" % (status, code)


def classify_domain_validation(status, text):
    """('rejected'|'accepted'|'quota'|'unknown', detail) for a check_* call on one domain."""
    if is_quota_reply(status, text):
        return "quota", "quota reply"
    content, is_error = tool_output(text)
    if content is None:
        return "unknown", "HTTP %s, no tool result" % status
    if is_error and "domain validation failed" in content.lower():
        return "rejected", "validation rejected"
    if is_error:
        return "unknown", "tool error without validation rejection: %s" % content[:80]
    return "accepted", "accepted"


def classify_reserved_domains(outcomes):
    """outcomes: {domain: (kind, detail)} over RESERVED_DOMAINS plus the positive control."""
    kinds = [k for k, _ in outcomes.values()]
    if "quota" in kinds:
        return SKIPPED, "quota reply (-32029)"
    bad = ["%s=%s" % (d, k) for d, (k, _) in outcomes.items()
           if k != ("accepted" if d == POSITIVE_CONTROL_DOMAIN else "rejected")]
    if bad:
        return FAIL, "unexpected: " + ", ".join(bad)
    return PASS, "rejected %s; accepted %s" % (", ".join(RESERVED_DOMAINS), POSITIVE_CONTROL_DOMAIN)


def classify_nxdomain(status, text, domain):
    if is_quota_reply(status, text):
        return SKIPPED, "quota reply (-32029)"
    content, _ = tool_output(text)
    if content is None:
        return FAIL, "HTTP %s, no tool result" % status
    if "does not resolve" in content.lower():
        return PASS, "%s answered 'does not resolve'" % domain
    return FAIL, "%s did not answer 'does not resolve': %r" % (domain, content[:120])


def extract_registrar(content):
    """Registrar name from rdap_lookup text ('Registrar: <name>. Created: ...'), or ''."""
    m = re.search(r"Registrar:\s*(.+?)\.\s+(?:[A-Z][A-Za-z ]*:)", content)
    if not m:
        m = re.search(r"Registrar:\s*(.+?)\.?\s*$", content, re.M)
    return m.group(1).strip() if m else ""


def classify_rdap(responses):
    """responses: {domain: (status, text)}. Reports each registrar name; FAIL if any is empty."""
    names, empty = [], []
    for domain, (status, text) in responses.items():
        if is_quota_reply(status, text):
            return SKIPPED, "quota reply (-32029)"
        content, _ = tool_output(text)
        name = extract_registrar(content) if content else ""
        (names if name else empty).append("%s=%r" % (domain, name) if name else domain)
    if empty:
        return FAIL, "no registrar name for: %s" % ", ".join(empty)
    return PASS, "registrar " + ", ".join(names)


def classify_sessions(samples):
    """FAIL on any 404 (or other session/tools-list failure); report init latency median/max."""
    usable = [s for s in samples if not s.quota]
    if not usable:
        return SKIPPED, "every session hit a quota reply"
    n404 = sum(1 for s in usable if s.list_status == 404)
    other = sum(1 for s in usable if s.list_status not in (200, 404) or s.init_status != 200)
    inits = [s.init_ms for s in usable]
    notifs = [s.notif_ms for s in usable if s.notif_ms is not None]
    detail = "sessions=%d 404s=%d other_failures=%d init_median=%dms init_max=%dms" % (
        len(usable), n404, other, statistics.median(inits), max(inits))
    if notifs:
        detail += " notif_median=%dms notif_max=%dms" % (statistics.median(notifs), max(notifs))
    return (FAIL if n404 or other else PASS), detail


def exit_code(results):
    return 1 if any(r.verdict == FAIL for r in results) else 0


def format_line(result):
    return "%s  %s  %s" % (result.verdict, result.check, result.detail)


# --- HTTP (urllib: headers never reach argv) ---------------------------------

def http_request(method, url, body=None, headers=None, timeout=HTTP_TIMEOUT):
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method)
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, hdrs, raw = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        status, hdrs, raw = e.code, e.headers, e.read()
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return Response(0, {}, "ERROR: %s" % type(e).__name__, elapsed)
    elapsed = (time.perf_counter() - start) * 1000
    lowered = {k.lower(): v for k, v in hdrs.items()}
    return Response(status, lowered, raw.decode("utf-8", "replace"), elapsed)


class Session(object):
    """One MCP session. The key lives only here and only goes into the Authorization header."""

    def __init__(self, host, key=None):
        self.host = host.rstrip("/")
        self._key = key
        self.sid = None
        self._next_id = 1

    def headers(self, content_type="application/json"):
        h = {"Content-Type": content_type, "User-Agent": USER_AGENT,
             "Accept": "application/json, text/event-stream"}
        if self._key:
            h["Authorization"] = "Bearer " + self._key
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        return h

    def rpc(self, method, params=None, notification=False, timeout=HTTP_TIMEOUT):
        body = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not notification:
            body["id"] = self._next_id
            self._next_id += 1
        return http_request("POST", self.host + "/mcp", json.dumps(body), self.headers(), timeout)

    def open(self):
        """initialize then notifications/initialized, timed separately. (init, notif) responses."""
        init = self.rpc("initialize", {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "bv-chaos-fix-regression", "version": "1.0"}})
        self.sid = init.headers.get("mcp-session-id")
        if not self.sid:
            return init, None
        return init, self.rpc("notifications/initialized", notification=True)

    def call_tool(self, name, arguments):
        return self.rpc("tools/call", {"name": name, "arguments": arguments}, timeout=TOOL_TIMEOUT)


# --- Live checks -------------------------------------------------------------

class Runner(object):
    def __init__(self, host, key, sessions, emit):
        self.host = host
        self.key = key
        self.sessions = sessions
        self.emit = emit
        self.results = []
        self._tier_reported = False

    def record(self, check, verdict_detail):
        result = Result(verdict_detail[0], check, verdict_detail[1])
        self.results.append(result)
        self.emit(format_line(result))

    def note_tier(self, response):
        if not self._tier_reported and self.key:
            self._tier_reported = True
            self.emit("# x-quota-tier=%s" % response.headers.get("x-quota-tier", "(not reported)"))

    def tool(self, session, name, arguments):
        response = session.call_tool(name, arguments)
        self.note_tier(response)
        return response

    def run(self):
        self.check_oauth_token()
        session = self.open_session()
        self.check_protocol_errors(session)
        if session is None or not self.key:
            for check in ("SQ-452", "SQ-447", "SQ-451"):
                self.record(check, (SKIPPED, "no key (set BV_VERIFY_KEY or BV_INTERNAL_DEV_KEY)" if not self.key
                                    else "no authenticated session"))
        else:
            self.check_reserved_domains(session)
            self.check_nxdomain(session)
            self.check_rdap(session)
        self.check_sessions()
        self.record("SQ-450", (NOT_EXERCISED, "internal latency; no external signal"))
        return self.results

    def open_session(self):
        session = Session(self.host, self.key)
        init, _ = session.open()
        if not session.sid:
            self.emit("# session open failed: HTTP %s" % init.status)
            return None
        return session

    def check_oauth_token(self):
        form = ("grant_type=authorization_code&client_id=bv-chaos-probe&code=bogus-%s"
                "&redirect_uri=https%%3A%%2F%%2Fexample.com%%2Fcb&code_verifier=%s"
                % (secrets.token_hex(8), "v" * 50))
        r = http_request("POST", self.host + "/oauth/token", form, {
            "Content-Type": "application/x-www-form-urlencoded", "User-Agent": USER_AGENT})
        self.record("SQ-448", classify_oauth_token(r.status, r.headers.get("cache-control")))
        self.record("SQ-448/retry-after", (NOT_EXERCISED, "429 path never tripped against the production limiter"))

    def check_protocol_errors(self, session):
        if session is None:
            self.record("SQ-449", (FAIL, "could not open a session"))
            return
        res = session.rpc("resources/read", {"uri": "bv-chaos://unknown/%s" % secrets.token_hex(4)})
        prm = session.rpc("prompts/get", {"name": "bv_chaos_unknown_%s" % secrets.token_hex(4)})
        if is_quota_reply(res.status, res.text) or is_quota_reply(prm.status, prm.text):
            self.record("SQ-449", (SKIPPED, "quota reply (-32029)"))
            return
        rv, rd = classify_resource_read(res.status, res.text)
        pv, pd = classify_prompt_get(prm.status, prm.text)
        verdict = PASS if rv == PASS and pv == PASS else FAIL
        self.record("SQ-449", (verdict, "resources/read: %s [%s]; prompts/get: %s [%s]" % (rd, rv, pd, pv)))

    def check_reserved_domains(self, session):
        outcomes = {}
        for domain in RESERVED_DOMAINS + (POSITIVE_CONTROL_DOMAIN,):
            r = self.tool(session, "check_mx", {"domain": domain, "format": "compact"})
            outcomes[domain] = classify_domain_validation(r.status, r.text)
        self.record("SQ-452", classify_reserved_domains(outcomes))

    def check_nxdomain(self, session):
        domain = "bv-chaos-%s.com" % secrets.token_hex(6)
        r = self.tool(session, "check_authoritative_dns_infra", {"domain": domain})
        self.record("SQ-447", classify_nxdomain(r.status, r.text, domain))

    def check_rdap(self, session):
        responses = {}
        for domain in RDAP_DOMAINS:
            r = self.tool(session, "rdap_lookup", {"domain": domain})
            responses[domain] = (r.status, r.text)
        self.record("SQ-451", classify_rdap(responses))

    def check_sessions(self):
        samples = []
        for _ in range(self.sessions):
            session = Session(self.host)
            init, notif = session.open()
            if notif is None:
                samples.append(Sample(init.status, init.elapsed_ms, None, 0, is_quota_reply(init.status, init.text)))
                continue
            listed = session.rpc("tools/list", {})
            samples.append(Sample(init.status, init.elapsed_ms, notif.elapsed_ms, listed.status,
                                  is_quota_reply(listed.status, listed.text)))
        self.record("SQ-453", classify_sessions(samples))


# --- CLI ---------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="Live regression probe for the 2026-10-29 chaos fixes (read-only; never trips the 429 limiter).")
    p.add_argument("--host", default=DEFAULT_HOST,
                   help="base URL (default %(default)s; workers.dev host: " + WORKERS_DEV_HOST + ")")
    p.add_argument("--sessions", type=int, default=DEFAULT_SESSIONS,
                   help="anonymous sessions for SQ-453 (default %(default)s)")
    return p


def main(argv=None, key=None, emit=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not re.match(r"^https?://[^/\s]+/?$", args.host):
        parser.error("--host must be an http(s) origin without a path, got %r" % args.host)
    if args.sessions < 1:
        parser.error("--sessions must be at least 1")
    if key is None:
        key = resolve_key()
    emit = emit or (lambda line: print(line, flush=True))
    emit("# host=%s key=%s sessions=%d" % (args.host.rstrip("/"), "present" if key else "absent", args.sessions))
    results = Runner(args.host.rstrip("/"), key, args.sessions, emit).run()
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
