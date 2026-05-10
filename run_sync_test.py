import subprocess
import json

URL = "https://bv-dns-security-mcp.bv-edge.workers.dev"

payload = {
    "mode": "sync",
    "domains": ["example.com"],
    "concurrency": 1
}

with open("sync_test.json", "w") as f:
    json.dump(payload, f)

# We need to ensure the domain is registered first or handled by the tool.
# Let's try registering a domain first using the API if possible, or just send the scan.
# We'll use the emergency bypass to send the request.

cmd = [
    "curl", "-s", "-X", "POST", f"{URL}/internal/tenants/scan",
    "-H", "X-Tenant: tenant-example",
    "-H", "X-Synthetic-Dispatch: synthetic-force-scan-10k",
    "-H", "Content-Type: application/json",
    "-d", "@sync_test.json"
]

print(subprocess.check_output(cmd, text=True))
