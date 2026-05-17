import json
import os
import subprocess
import sys
import tempfile
import time


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


BASE_URL = require_env("BV_TENANT_SCAN_BASE_URL").rstrip("/")
TENANT_ID = require_env("BV_TENANT_ID")
INTERNAL_KEY = require_env("BV_WEB_INTERNAL_KEY")
DOMAINS_JSON = os.getenv("BV_DOMAINS_JSON", "test/data/domains.json")

with open(DOMAINS_JSON, "r") as f:
    content = json.load(f)

domains: list[str] = []
for entry in content:
    for row in entry.get("results", []):
        if "domain" in row:
            domains.append(row["domain"])

limit = int(os.getenv("BV_SYNC_LIMIT", "10000"))
domains = domains[:limit]

CHUNK_SIZE = int(os.getenv("BV_SYNC_CHUNK_SIZE", "50"))
total_chunks = (len(domains) + CHUNK_SIZE - 1) // CHUNK_SIZE

print(f"Starting {total_chunks} sync batches for {len(domains)} domains...")

success_count = 0

for i in range(total_chunks):
    chunk = domains[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
    payload = {"mode": "sync", "domains": chunk, "concurrency": 10}

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        batch_file = f.name

    print(f"[{i + 1}/{total_chunks}] Dispatching {len(chunk)} domains...", end=" ")
    sys.stdout.flush()

    cmd = [
        "curl",
        "-s",
        "-X",
        "POST",
        f"{BASE_URL}/internal/tenants/scan",
        "-H",
        f"X-Tenant: {TENANT_ID}",
        "-H",
        f"Authorization: Bearer {INTERNAL_KEY}",
        "-H",
        "Content-Type: application/json",
        "-d",
        f"@{batch_file}",
    ]
    try:
        start_time = time.time()
        result = subprocess.check_output(cmd, text=True)
        duration = time.time() - start_time
        print(f"Done in {duration:.1f}s: {result[:50]}...")
        success_count += len(chunk)
    except Exception as e:
        print(f"ERROR: {e}")

print(f"\nCompleted {success_count} domains via sync.")
