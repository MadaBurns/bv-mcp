#!/usr/bin/env python3
"""Schema-driven live chaos sweep of every tool the server lists. Python 3.9, stdlib only.

It reads tools/list, builds hostile and malformed arguments for each tool from its
inputSchema, calls the tool, and classifies every response:

  PASS    rejected what must be rejected, or answered a tolerated input cleanly
  FAIL    HTTP 5xx, JSON-RPC -32603, a transport error, an internal-detail leak in the
          body, or an SSRF-class value (localhost, private or metadata address) accepted
  REVIEW  accepted an input the harness expected to be refused, or refused a valid control
  TIER    a valid control refused because the calling tier may not use that tool
  SKIP    rate limited or out of quota, so nothing was measured for that case

Usage:
  python3 scripts/chaos/chaos-all-tools-sweep.py --dev-vars .dev.vars
  python3 scripts/chaos/chaos-all-tools-sweep.py --dev-vars .dev.vars --only check_spf,scan_domain
  python3 scripts/chaos/chaos-all-tools-sweep.py --dev-vars .dev.vars --list      # plan only, no tool calls

The key comes from the BV_INTERNAL_DEV_KEY line of --dev-vars, or from the environment
variable of the same name. It is sent only in the Authorization header, only to --host
(https, or http to localhost), never across a redirect, and is never printed or written
to the results. Exit status: 0 no FAIL, 1 at least one FAIL, 2 a
prerequisite is missing.

Limits, so a clean run is not over-read:
  - It measures the tier the key resolves to from this machine. An owner key from an
    address outside the owner allowlist runs as partner; the tier preflight line says which.
  - Mutating tools (readOnlyHint is not true) only ever get one malformed parameter. Their
    success paths are never exercised.
  - Valid controls use placeholder values for identifiers (job ids, report ids). A REVIEW
    on a tool that needs a real identifier is the harness, not the server.
  - SKIP rows are unmeasured. A run with many of them is a partial run.
  - REVIEW needs a human read: some tools refuse a bad entry per item inside a successful
    reply, which this classifier cannot see.
"""
import argparse
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

DEFAULT_HOST = 'https://dns-mcp.blackveilsecurity.com/mcp'
HOST = DEFAULT_HOST
UA = 'bv-chaos-sweep/1.0'
PROTO = '2025-06-18'
TIMEOUT = 60

LEAK = re.compile(
    r'(TypeError|ReferenceError|RangeError|SyntaxError: |Cannot read prop|is not a function|undefined is not|'
    r'D1_ERROR|SQLITE_|no such table|\bat [\w.$<>]+ \((?:file|node|worker|index)|\.ts:\d+:\d+|\.js:\d+:\d+|'
    r'wrangler|"stack"\s*:|Bearer [A-Za-z0-9_\-]{20,}|BV_[A-Z_]+_KEY)'
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is returned as its 3xx response, so the key never follows one to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def host_is_allowed(url):
    """https anywhere, or plain http to the local machine only: the key must not travel in clear text."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme == 'https' and parsed.hostname:
        return True
    return parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1')


def read_key(path):
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            if line.startswith('BV_INTERNAL_DEV_KEY='):
                return line.split('=', 1)[1].strip().strip('"').strip("'")
    return None


class Client:
    def __init__(self, key):
        self.key = key
        self.session = None
        self.lock = threading.Lock()

    def post(self, body, session=True, raw=None, auth=True, timeout=TIMEOUT):
        headers = {
            'content-type': 'application/json',
            'accept': 'application/json, text/event-stream',
            'mcp-protocol-version': PROTO,
            'user-agent': UA,
        }
        if auth and self.key:
            headers['authorization'] = 'Bearer ' + self.key
        if session and self.session:
            headers['mcp-session-id'] = self.session
        data = raw if raw is not None else json.dumps(body).encode('utf-8')
        req = urllib.request.Request(HOST, data=data, headers=headers, method='POST')
        t0 = time.time()
        try:
            with OPENER.open(req, timeout=timeout) as resp:
                status, hdrs, text = resp.status, dict(resp.headers), resp.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as err:
            status, hdrs, text = err.code, dict(err.headers), err.read().decode('utf-8', 'replace')
        except Exception as err:  # noqa: BLE001 - transport failures are a result class
            return {'status': 0, 'headers': {}, 'text': '', 'json': None, 'ms': int((time.time() - t0) * 1000), 'transport': type(err).__name__ + ': ' + str(err)[:160]}
        return {'status': status, 'headers': {k.lower(): v for k, v in hdrs.items()}, 'text': text, 'json': parse_body(text), 'ms': int((time.time() - t0) * 1000), 'transport': None}

    def init(self):
        with self.lock:
            r = self.post({'jsonrpc': '2.0', 'id': 0, 'method': 'initialize', 'params': {'protocolVersion': PROTO, 'capabilities': {}, 'clientInfo': {'name': 'chaos-sweep', 'version': '1'}}}, session=False)
            self.session = r['headers'].get('mcp-session-id')
            if self.session:
                self.post({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
            return r

    def call(self, tool, args, ident=1):
        body = {'jsonrpc': '2.0', 'id': ident, 'method': 'tools/call', 'params': {'name': tool, 'arguments': args}}
        for attempt in range(4):
            r = self.post(body)
            if r['status'] == 404 and 'session' in r['text'].lower():
                self.init()
                continue
            if r['status'] == 429 and attempt < 3:
                try:
                    wait = min(30, int(r['headers'].get('retry-after', '5')))
                except ValueError:
                    wait = 5
                time.sleep(wait + 1)
                continue
            return r
        return r


def parse_body(text):
    text = text.strip()
    if not text:
        return None
    if text.startswith('{') or text.startswith('['):
        try:
            return json.loads(text)
        except ValueError:
            return None
    last = None
    for line in text.splitlines():
        if line.startswith('data:'):
            last = line[5:].strip()
    if last:
        try:
            return json.loads(last)
        except ValueError:
            return None
    return None


# (label, value, must_reject)
DOMAIN_BAD = [
    ('empty', '', True),
    ('space', ' ', True),
    ('localhost', 'localhost', True),
    ('loopback-ip', '127.0.0.1', True),
    ('metadata-ip', '169.254.169.254', True),
    ('ipv6-loopback', '[::1]', True),
    ('private-ip', '10.0.0.1', True),
    ('nip-io', '127.0.0.1.nip.io', True),
    ('double-dot', 'a..b.com', True),
    ('leading-hyphen', '-bad.com', True),
    ('long-label', ('a' * 64) + '.com', True),
    ('too-long', '.'.join(['abcdefghij'] * 30) + '.com', True),
    ('path', 'example.com/../../etc/passwd', True),
    ('url', 'http://example.com', True),
    ('nul', 'exam\x00ple.com', True),
    ('crlf', 'example.com\r\nX-Injected: 1', True),
    ('at-userinfo', 'user@127.0.0.1', True),
    ('tld-only', 'com', True),
    ('dot-invalid', 'nothing.invalid', True),
    ('home-arpa', 'foo.home.arpa', True),
    ('underscore', 'bad_label.com', False),
    ('script', '<script>alert(1)</script>.com', True),
    ('sqli', "example.com' OR '1'='1", True),
    ('template', '${7*7}.com', True),
    ('huge', 'a' * 10000, True),
    ('uppercase', 'ISC.ORG', False),
    ('trailing-dot', 'isc.org.', False),
    ('idn', 'münchen.de', False),
    ('nxdomain', 'bv-chaos-sweep-nx-7f3a9c1e.com', False),
]
TYPE_BAD = [('number', 12345, True), ('null', None, True), ('array', ['isc.org'], True), ('object', {'a': 1}, True), ('bool', True, True)]
STRING_BAD = [('empty', '', False), ('nul', 'a\x00b', False), ('crlf', 'a\r\nb', False), ('huge', 'x' * 20000, False), ('script', '<img src=x onerror=1>', False), ('number', 7, True), ('object', {'a': 1}, True)]


def is_domain_prop(name):
    n = name.lower()
    return n in ('domain', 'target', 'hostname', 'host', 'apex', 'brand_domain', 'primary_domain') or n.endswith('_domain')


def is_domains_prop(name):
    n = name.lower()
    return n in ('domains', 'targets', 'hostnames') or n.endswith('_domains')


def valid_value(name, schema):
    t = schema.get('type')
    if isinstance(t, list):
        t = next((x for x in t if x != 'null'), 'string')
    if 'enum' in schema:
        return schema['enum'][0]
    if 'default' in schema:
        return schema['default']
    if t == 'string':
        if is_domain_prop(name):
            return 'isc.org'
        return 'test'
    if t == 'array':
        if is_domains_prop(name):
            return ['isc.org', 'nic.cz']
        items = schema.get('items', {})
        return [valid_value(name, items)] if items else []
    if t in ('number', 'integer'):
        return schema.get('minimum', 1)
    if t == 'boolean':
        return False
    if t == 'object':
        return {}
    return 'test'


def build_cases(tool):
    name = tool['name']
    schema = tool.get('inputSchema') or {}
    props = schema.get('properties') or {}
    required = schema.get('required') or []
    read_only = bool((tool.get('annotations') or {}).get('readOnlyHint'))
    base = {p: valid_value(p, props.get(p, {})) for p in required}
    cases = []

    def add(label, args, must_reject, kind='chaos'):
        cases.append({'tool': name, 'label': label, 'args': args, 'must_reject': must_reject, 'kind': kind, 'read_only': read_only})

    if required:
        add('no-args', {}, True)
    add('unknown-arg', dict(base, bogus_arg_zz='x') if read_only else {'bogus_arg_zz': 'x'}, True)
    add('proto-key', dict(base, **{'__proto__': {'polluted': True}}) if read_only else {'__proto__': {'polluted': True}}, True)

    for pname, pschema in props.items():
        ptype = pschema.get('type')
        if isinstance(ptype, list):
            ptype = next((x for x in ptype if x != 'null'), 'string')
        # Mutating tools: only this one parameter, wrong type or empty. Never a complete valid-looking call.
        if not read_only:
            if ptype == 'string':
                add(pname + ':number', {pname: 12345}, True)
                add(pname + ':empty', {pname: ''}, True)
                add(pname + ':object', {pname: {'a': 1}}, True)
            elif ptype == 'array':
                add(pname + ':not-array', {pname: 'isc.org'}, True)
                add(pname + ':empty-array', {pname: []}, True)
            elif ptype in ('number', 'integer'):
                add(pname + ':string', {pname: 'five'}, True)
            elif ptype == 'boolean':
                add(pname + ':string', {pname: 'yes'}, True)
            continue
        if ptype == 'string' and 'enum' in pschema:
            add(pname + ':bad-enum', dict(base, **{pname: 'zz-not-a-member'}), True)
            add(pname + ':enum-number', dict(base, **{pname: 3}), True)
        elif ptype == 'string' and is_domain_prop(pname):
            for label, value, must in DOMAIN_BAD + TYPE_BAD:
                add(pname + ':' + label, dict(base, **{pname: value}), must)
        elif ptype == 'string':
            for label, value, must in STRING_BAD:
                add(pname + ':' + label, dict(base, **{pname: value}), must)
        elif ptype == 'array':
            add(pname + ':not-array', dict(base, **{pname: 'isc.org'}), True)
            add(pname + ':empty-array', dict(base, **{pname: []}), False)
            add(pname + ':numbers', dict(base, **{pname: [1, 2, 3]}), True)
            add(pname + ':nested', dict(base, **{pname: [['isc.org']]}), True)
            if is_domains_prop(pname):
                add(pname + ':ssrf-mix', dict(base, **{pname: ['localhost', '127.0.0.1', '169.254.169.254']}), True)
                add(pname + ':oversize', dict(base, **{pname: ['d%d.invalid' % i for i in range(5000)]}), True)
        elif ptype in ('number', 'integer'):
            add(pname + ':string', dict(base, **{pname: 'five'}), True)
            add(pname + ':negative', dict(base, **{pname: -1}), False)
            add(pname + ':huge', dict(base, **{pname: 1e18}), False)
            add(pname + ':float', dict(base, **{pname: 1.5}), False)
        elif ptype == 'boolean':
            add(pname + ':string', dict(base, **{pname: 'yes'}), True)
            add(pname + ':number', dict(base, **{pname: 1}), True)
        elif ptype == 'object':
            add(pname + ':string', dict(base, **{pname: 'x'}), True)

    if read_only and all(p in base for p in required):
        add('valid-control', base, False, kind='control')
    return cases


def classify(case, r):
    """Returns (verdict, detail). Verdicts: PASS FAIL REVIEW SKIP TIER."""
    if r['transport']:
        return 'FAIL', 'transport: ' + r['transport']
    text = r['text']
    status = r['status']
    if status >= 500:
        return 'FAIL', 'HTTP %d: %s' % (status, text[:200].replace('\n', ' '))
    leak = LEAK.search(text)
    if leak:
        return 'FAIL', 'leak pattern %r near: %s' % (leak.group(0)[:40], text[max(0, leak.start() - 60):leak.start() + 100].replace('\n', ' '))
    if status == 429:
        return 'SKIP', 'rate limited (HTTP 429)'
    body = r['json']
    rejected = False
    detail = ''
    if isinstance(body, dict) and 'error' in body:
        code = (body['error'] or {}).get('code')
        msg = str((body['error'] or {}).get('message', ''))[:160]
        if code == -32603:
            return 'FAIL', 'JSON-RPC -32603 internal error: ' + msg
        if code == -32029:
            return 'SKIP', 'quota (-32029): ' + msg
        rejected = True
        detail = 'rpc %s: %s' % (code, msg)
    elif isinstance(body, dict) and 'result' in body:
        res = body['result'] or {}
        first = ''
        for item in res.get('content') or []:
            if isinstance(item, dict) and item.get('type') == 'text':
                first = item.get('text', '')[:160].replace('\n', ' ')
                break
        if res.get('isError'):
            rejected = True
            detail = 'isError: ' + first
        else:
            detail = 'ok: ' + first
    elif 400 <= status < 500:
        rejected = True
        detail = 'HTTP %d: %s' % (status, text[:160].replace('\n', ' '))
    else:
        return 'REVIEW', 'unparseable HTTP %d body: %s' % (status, text[:160].replace('\n', ' '))

    low = (detail + ' ' + text[:600]).lower()
    if rejected and re.search(r'requires|upgrade|tier|not available on|forbidden|unauthori[sz]ed|not authorized|watchlist', low) and case['kind'] == 'control':
        return 'TIER', detail
    if case['kind'] == 'control':
        return ('PASS', detail) if not rejected else ('REVIEW', 'valid control rejected: ' + detail)
    if case['must_reject']:
        return ('PASS', detail) if rejected else ('FAIL' if is_ssrf(case) else 'REVIEW', 'accepted input that should be rejected: ' + detail)
    return 'PASS', detail


def is_ssrf(case):
    return any(k in case['label'] for k in ('localhost', 'loopback', 'metadata', 'private-ip', 'nip-io', 'ssrf', 'at-userinfo', 'home-arpa'))


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Schema-driven live chaos sweep of every listed tool.')
    parser.add_argument('--dev-vars', help='file holding a BV_INTERNAL_DEV_KEY= line (else the environment variable is used)')
    parser.add_argument('--host', default=DEFAULT_HOST, help='MCP endpoint URL (default: production)')
    parser.add_argument('--out', help='directory for tools.json and results.jsonl (default: a new temp directory)')
    parser.add_argument('--only', help='comma-separated tool names to sweep')
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--list', action='store_true', help='print the per-tool case plan and stop before any tool call')
    return parser.parse_args(argv)


def resolve_key(dev_vars):
    if dev_vars:
        return read_key(dev_vars)
    return os.environ.get('BV_INTERNAL_DEV_KEY') or None


def summarize(rows):
    """Returns (counts, attention) where attention is the FAIL and REVIEW rows, FAIL first."""
    counts = {}
    for row in rows:
        counts[row['verdict']] = counts.get(row['verdict'], 0) + 1
    attention = [r for r in rows if r['verdict'] == 'FAIL'] + [r for r in rows if r['verdict'] == 'REVIEW']
    return counts, attention


def exit_code(counts):
    return 1 if counts.get('FAIL') else 0


def print_plan(tools, cases):
    per = {}
    for case in cases:
        per[case['tool']] = per.get(case['tool'], 0) + 1
    for tool in tools:
        props = (tool.get('inputSchema') or {}).get('properties') or {}
        read_only = bool((tool.get('annotations') or {}).get('readOnlyHint'))
        print('  %-42s ro=%-5s cases=%-3d props=%s' % (tool['name'], read_only, per.get(tool['name'], 0), ','.join(props.keys())))


def run_cases(client, cases, out_path, workers):
    rows = []
    lock = threading.Lock()

    def run(case):
        r = client.call(case['tool'], case['args'])
        verdict, detail = classify(case, r)
        row = {'tool': case['tool'], 'label': case['label'], 'kind': case['kind'], 'verdict': verdict, 'detail': detail, 'status': r['status'], 'ms': r['ms'], 'tier': r['headers'].get('x-quota-tier')}
        with lock:
            out.write(json.dumps(row) + '\n')
            out.flush()
            rows.append(row)
            if len(rows) % 200 == 0:
                print('  progress %d/%d %s' % (len(rows), len(cases), summarize(rows)[0]), flush=True)

    with open(out_path, 'w', encoding='utf-8') as out:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(run, cases))
    return rows


def main(argv=None):
    global HOST
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not host_is_allowed(args.host):
        print('PREREQ: --host must be https, or http to localhost')
        return 2
    HOST = args.host
    key = resolve_key(args.dev_vars)
    if not key:
        print('PREREQ: BV_INTERNAL_DEV_KEY not found (pass --dev-vars <file> or set the environment variable)')
        return 2
    out_dir = args.out or tempfile.mkdtemp(prefix='bv-chaos-sweep-')
    os.makedirs(out_dir, exist_ok=True)

    client = Client(key)
    init = client.init()
    info = ((init['json'] or {}).get('result') or {}).get('serverInfo') or {}
    print('target: %s' % HOST)
    print('initialize: HTTP %s version=%s session=%s' % (init['status'], info.get('version'), 'yes' if client.session else 'NO'))
    if not client.session:
        print('PREREQ: no session; body: ' + init['text'][:200])
        return 2
    listing = client.post({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
    tools = (((listing['json'] or {}).get('result')) or {}).get('tools') or []
    print('tools/list: %d tools' % len(tools))
    if not tools:
        print('PREREQ: tools/list returned no tools; body: ' + listing['text'][:200])
        return 2
    with open(os.path.join(out_dir, 'tools.json'), 'w', encoding='utf-8') as fh:
        json.dump(tools, fh)

    only = set(args.only.split(',')) if args.only else None
    cases = []
    for tool in tools:
        if only and tool['name'] not in only:
            continue
        cases.extend(build_cases(tool))
    read_only = sum(1 for t in tools if (t.get('annotations') or {}).get('readOnlyHint'))
    print('read-only tools: %d, mutating: %d, cases: %d' % (read_only, len(tools) - read_only, len(cases)))
    if args.list:
        print_plan(tools, cases)
        return 0
    if not cases:
        print('PREREQ: no cases to run (does --only name a listed tool?)')
        return 2

    probe = client.call('check_spf', {'domain': 'isc.org'})
    print('tier preflight: HTTP %s x-quota-tier=%s' % (probe['status'], probe['headers'].get('x-quota-tier')))

    started = time.time()
    results_path = os.path.join(out_dir, 'results.jsonl')
    rows = run_cases(client, cases, results_path, args.workers)
    counts, attention = summarize(rows)
    print('DONE %d cases in %ds: %s' % (len(rows), int(time.time() - started), counts))
    for row in attention:
        print('  %-6s %s %s -> %s' % (row['verdict'], row['tool'], row['label'], row['detail'][:200]))
    print('results: ' + results_path)
    return exit_code(counts)


if __name__ == '__main__':
    sys.exit(main())
