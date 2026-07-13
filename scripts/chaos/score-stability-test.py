#!/usr/bin/env python3
"""
Score stability chaos test — scan N domains across R rounds, compare scores.
Detects score fluctuations across force_refresh runs.

Usage:
  score-stability-test.py                      # 20 default domains, 2 rounds
  score-stability-test.py --count 100 --rounds 3 --concurrency 10
  score-stability-test.py --from tranco-scan.json --count 200 --rounds 3
"""

import argparse
import subprocess
import json
import sys
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "https://dns-mcp.blackveilsecurity.com"
API_KEY = os.getenv("BV_API_KEY") or os.getenv("BV_INTERNAL_DEV_KEY")

DEFAULT_DOMAINS = [
    "cloudflare.com", "google.com", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "netflix.com", "brand-theta.example.com",
    "shopify.com", "zoom.us", "slack.com", "dropbox.com",
    "fastly.com", "digitalocean.com", "vercel.com", "gitlab.com",
    "hashicorp.com", "datadog.com", "pagerduty.com", "twilio.com",
]

DOMAINS: list[str] = []
PROTOCOL_VERSION = "2025-06-18"

# ─── Helpers ─────────────────────────────────────────────────────────────────

def curl_json(method, path, body, headers, timeout=30, params=None):
    url = f"{BASE}{path}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{qs}"
    cmd = ["curl", "-sS", "-w", "\n%{http_code}",
           "--connect-timeout", "10", "--max-time", str(timeout)]
    if method != "GET":
        cmd += ["-X", method]
    for h in headers:
        cmd += ["-H", h]
    if body is not None:
        cmd += ["-d", json.dumps(body) if isinstance(body, (dict, list)) else body]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        output = r.stdout.strip()
        if not output:
            return 0, r.stderr.strip() or "curl returned no response"
        lines = output.split("\n")
        status = int(lines[-1]) if lines[-1].isdigit() else 0
        response_body = "\n".join(lines[:-1])
        if r.returncode != 0:
            return 0, r.stderr.strip() or response_body or f"curl exited {r.returncode}"
        return status, response_body
    except Exception as e:
        return 0, str(e)


def make_headers(sid=None):
    h = [
        "Content-Type: application/json",
        "Accept: application/json, text/event-stream",
        f"MCP-Protocol-Version: {PROTOCOL_VERSION}",
        "User-Agent: score-stability-test/1.0",
    ]
    if API_KEY:
        h.append(f"Authorization: Bearer {API_KEY}")
    if sid:
        h.append(f"Mcp-Session-Id: {sid}")
    return h


def parse_mcp_payload(text):
    """Parse a single JSON-RPC response from JSON or Streamable HTTP SSE."""
    stripped = text.strip()
    if not stripped:
        raise ValueError("empty MCP response body")

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Streamable HTTP may frame a JSON-RPC response as one or more SSE events.
    # Join multiple data lines as required by the SSE field folding rules and
    # return the first valid JSON-RPC payload for this single-request harness.
    for event in re.split(r"\r?\n\r?\n", stripped):
        data_lines = []
        for line in event.splitlines():
            if line == "data":
                data_lines.append("")
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip(" "))
        if not data_lines:
            continue
        data = "\n".join(data_lines)
        if data == "[DONE]":
            continue
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            continue

    preview = stripped[:120].replace("\n", "\\n")
    raise ValueError(f"invalid MCP response body: {preview}")


def create_session():
    body = {"jsonrpc": "2.0", "method": "initialize", "id": 1,
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "score-stability-test", "version": "1.0"}}}
    cmd = ["curl", "-sS", "-D-", "-w", "\n%{http_code}",
           "--connect-timeout", "10", "--max-time", "15",
           "-X", "POST", f"{BASE}/mcp",
           "-H", "Content-Type: application/json",
           "-H", "Accept: application/json, text/event-stream",
           "-H", "User-Agent: score-stability-test/1.0"]
    if API_KEY:
        cmd += ["-H", f"Authorization: Bearer {API_KEY}"]
    cmd += ["-d", json.dumps(body)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        sid = None
        for line in r.stdout.split("\n"):
            if line.lower().startswith("mcp-session-id:"):
                sid = line.split(":", 1)[1].strip()
                break
        if sid:
            # send initialized notification
            curl_json("POST", "/mcp",
                      {"jsonrpc": "2.0", "method": "notifications/initialized"},
                      make_headers(sid))
        return sid
    except Exception:
        return None


def scan_domain(sid, domain):
    """Scan a domain, return (domain, score, grade, category_scores, finding_count, error)."""
    body = {"jsonrpc": "2.0", "method": "tools/call", "id": 10,
            "params": {"name": "scan_domain",
                       "arguments": {"domain": domain, "force_refresh": True, "format": "compact"}}}
    status, text = curl_json("POST", "/mcp", body, make_headers(sid), timeout=30)
    if status != 200:
        detail = text[:160].replace("\n", " ") if text else "no response body"
        return domain, None, None, {}, 0, f"HTTP {status}: {detail}"

    try:
        d = parse_mcp_payload(text)
        if "error" in d:
            msg = d["error"].get("message", "unknown")
            return domain, None, None, {}, 0, msg

        result = d.get("result")
        if not isinstance(result, dict):
            return domain, None, None, {}, 0, "MCP response missing result object"

        content = result.get("content", [])
        full_text = "\n".join(c.get("text", "") for c in content)
        if result.get("isError"):
            return domain, None, None, {}, 0, full_text[:240] or "tool returned isError"

        structured = result.get("structuredContent", {})
        if not isinstance(structured, dict):
            structured = {}

        # Extract score and grade
        m = re.search(r"Overall Score:\s*(\d+)/100\s*\(([A-F][+]?)\)", full_text)
        structured_score = structured.get("score")
        score = structured_score if isinstance(structured_score, (int, float)) else (int(m.group(1)) if m else None)
        structured_grade = structured.get("grade")
        grade = structured_grade if isinstance(structured_grade, str) else (m.group(2) if m else None)

        if score is None or grade is None:
            return domain, None, None, {}, 0, "scan result missing score or grade"

        # Extract category scores
        structured_categories = structured.get("categoryScores")
        if isinstance(structured_categories, dict):
            cats = structured_categories
        else:
            cats = {}
            for cm in re.finditer(r"(?:✓|✗|⚠)\s+(\w+)\s+(\d+)/100", full_text):
                cats[cm.group(1)] = int(cm.group(2))

        # Count findings
        finding_counts = structured.get("findingCounts")
        if isinstance(finding_counts, dict):
            findings = sum(value for value in finding_counts.values() if isinstance(value, int))
        else:
            findings = len(re.findall(r"\[(HIGH|MEDIUM|LOW|INFO|CRITICAL)\]", full_text))

        return domain, score, grade, cats, findings, None
    except Exception as e:
        return domain, None, None, {}, 0, str(e)


def run_round(label, domains, concurrency=5):
    """Scan all domains, return dict of {domain: (score, grade, cats, findings)}."""
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"{'='*70}")

    sid = create_session()
    if not sid:
        print("  FATAL: could not create session")
        return {}

    quiet = len(domains) > 30
    results = {}
    t0 = time.monotonic()
    ok_count = 0
    err_count = 0

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = {pool.submit(scan_domain, sid, d): d for d in domains}
        for f in as_completed(futs):
            domain, score, grade, cats, findings, err = f.result()
            if err:
                err_count += 1
                if not quiet:
                    print(f"  ERR  {domain:25s}  {err}")
                results[domain] = (None, None, {}, 0, err)
            else:
                ok_count += 1
                if not quiet:
                    print(f"  OK   {domain:25s}  {score:3d}/100 ({grade:2s})  "
                          f"{len(cats)} cats  {findings} findings")
                else:
                    # Progress indicator every 25 domains
                    if (ok_count + err_count) % 25 == 0:
                        print(f"  ... {ok_count + err_count}/{len(domains)} "
                              f"({ok_count} ok, {err_count} err)")
                results[domain] = (score, grade, cats, findings, None)

    elapsed = time.monotonic() - t0
    print(f"  --- {ok_count} ok, {err_count} err, {elapsed:.1f}s ---")

    # cleanup
    curl_json("DELETE", "/mcp", None, make_headers(sid))
    return results


def compare_multi(rounds):
    """Compare N rounds, report fluctuations. rounds is a list of dicts."""
    print(f"\n{'='*70}")
    print(f"  COMPARISON ({len(rounds)} rounds)")
    print(f"{'='*70}")

    drifts = []
    stable = 0
    errors = 0

    for domain in DOMAINS:
        runs = [r.get(domain) for r in rounds]
        if any(d is None for d in runs):
            errors += 1
            continue
        # Check if any run had an error
        if any(d[4] for d in runs):  # d = (score, grade, cats, findings, err)
            errors += 1
            continue

        scores = [d[0] for d in runs]
        grades = [d[1] for d in runs]
        cats_list = [d[2] for d in runs]
        findings_list = [d[3] for d in runs]

        score_deltas = max(scores) - min(scores)
        grades_match = len(set(grades)) == 1
        findings_deltas = max(findings_list) - min(findings_list)

        # Check category-level diffs across all rounds
        all_cats = set()
        for c in cats_list:
            all_cats.update(c.keys())
        cat_diffs = []
        for cat in sorted(all_cats):
            values = [c.get(cat) for c in cats_list]
            if len(set(values)) > 1:
                cat_diffs.append(f"{cat}: {'→'.join(str(v) for v in values)}")

        if score_deltas == 0 and grades_match and not cat_diffs and findings_deltas == 0:
            stable += 1
        else:
            drifts.append(domain)
            score_str = '→'.join(str(s) for s in scores)
            findings_str = '→'.join(str(f) for f in findings_list)
            print(f"  DRIFT {domain:30s}  score={score_str} (Δ{score_deltas})  "
                  f"findings={findings_str}")
            if cat_diffs:
                print(f"        category diffs: {', '.join(cat_diffs)}")

    print(f"\n{'='*70}")
    print(f"  RESULTS: {stable} stable, {len(drifts)} drifted, {errors} errors")
    print(f"{'='*70}")

    if drifts or errors:
        reasons = []
        if drifts:
            reasons.append(f"{len(drifts)}/{len(DOMAINS)} domain(s) drifted")
        if errors:
            reasons.append(f"{errors}/{len(DOMAINS)} domain(s) errored")
        print(f"\n  FAILED — {'; '.join(reasons)}")
        if drifts:
            print(f"  DRIFT RATE: {100*len(drifts)/max(len(DOMAINS),1):.1f}%")
        return 1
    else:
        print(f"\n  STABLE — all {stable} domains scored identically across all {len(rounds)} rounds")
        return 0


def load_domains(from_file, count):
    """Load domains from a tranco JSON file or fall back to DEFAULT_DOMAINS."""
    if from_file:
        try:
            with open(from_file) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            raise ValueError(f"could not load domain file {from_file}: {e}") from e

        if not isinstance(data, list):
            raise ValueError("domain file must be a JSON array")

        domains = []
        for index, item in enumerate(data):
            domain = item.get("domain") if isinstance(item, dict) else item
            if not isinstance(domain, str) or not domain.strip():
                raise ValueError(f"domain file entry {index + 1} must be a non-empty domain string")
            normalized = domain.strip().lower()
            if normalized not in domains:
                domains.append(normalized)

        if not domains:
            raise ValueError("domain file must contain at least one domain")
        return domains[:count]

    if count <= len(DEFAULT_DOMAINS):
        return DEFAULT_DOMAINS[:count]

    # Extend default list by cycling if count > 20 and no file provided
    return (DEFAULT_DOMAINS * (count // len(DEFAULT_DOMAINS) + 1))[:count]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--count', type=int, default=20, help='Number of domains to scan (default: 20)')
    parser.add_argument('--rounds', type=int, default=2, help='Number of rounds (default: 2)')
    parser.add_argument('--concurrency', type=int, default=5, help='Parallel scan workers (default: 5)')
    parser.add_argument('--from', dest='from_file', default=None, help='Load domains from JSON file')
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be at least 1")
    if args.rounds < 2:
        parser.error("--rounds must be at least 2 to measure stability")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")

    global DOMAINS
    try:
        DOMAINS = load_domains(args.from_file, args.count)
    except ValueError as error:
        parser.error(str(error))

    if len(DOMAINS) < args.count:
        parser.error(f"requested {args.count} domains, but only {len(DOMAINS)} unique domains were loaded")

    print("="*70)
    print(f"  Score Stability Chaos Test — {len(DOMAINS)} domains x {args.rounds} rounds")
    print(f"  Target: {BASE}/mcp")
    print(f"  Auth: {'API key loaded' if API_KEY else 'none (may hit rate limits)'}")
    print(f"  Concurrency: {args.concurrency}")
    print("="*70)

    rounds = []
    for i in range(args.rounds):
        r = run_round(f"Round {i+1} (force_refresh)", DOMAINS, concurrency=args.concurrency)
        rounds.append(r)
        if i < args.rounds - 1:
            time.sleep(1)

    code = compare_multi(rounds)
    sys.exit(code)


if __name__ == "__main__":
    main()
