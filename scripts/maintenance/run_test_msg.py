import json
import subprocess

URL = "https://bv-dns-security-mcp.bv-edge.workers.dev"

batch_file = "batch_test.json"
payload = {
    "mode": "queue",
    "domains": ["example.com"],
    "concurrency": 1
}
with open(batch_file, "w") as f:
    json.dump(payload, f)

cmd = [
    "curl", "-s", "-X", "POST", f"{URL}/internal/tenants/scan",
    "-H", "X-Tenant: tenant-example",
    "-H", "X-Synthetic-Dispatch: synthetic-force-scan-10k",
    "-H", "Content-Type: application/json",
    "-d", f"@{batch_file}"
]
print(subprocess.check_output(cmd, text=True))
