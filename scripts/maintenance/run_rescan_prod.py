import json
import os
import subprocess
import tempfile


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


BASE_URL = require_env("BV_TENANT_SCAN_BASE_URL").rstrip("/")
TENANT_ID = require_env("BV_TENANT_ID")
INTERNAL_KEY = require_env("BV_WEB_INTERNAL_KEY")
TENANT_DB_NAME = require_env("BV_TENANT_DB_NAME")
LIMIT = int(os.getenv("BV_RESCAN_LIMIT", "500"))

cmd = [
    "npx",
    "wrangler",
    "d1",
    "execute",
    TENANT_DB_NAME,
    "--remote",
    "--command",
    f"SELECT domain FROM domains LIMIT {LIMIT};",
    "--json",
]
result = subprocess.check_output(cmd, text=True)
data = json.loads(result)

domains: list[str] = []
for entry in data:
    for row in entry.get("results", []):
        if "domain" in row:
            domains.append(row["domain"])

payload = {"mode": "queue", "domains": domains, "concurrency": 25}

with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
    json.dump(payload, f)
    payload_path = f.name

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
    f"@{payload_path}",
]
print(subprocess.check_output(cmd, text=True))
