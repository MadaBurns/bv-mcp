import json
import subprocess
import time

URL = "https://bv-dns-security-mcp.bv-edge.workers.dev"

# Get domains that are now registered
cmd = ["npx", "wrangler", "d1", "execute", "tenant-db-tenant-pilot-1", "--remote", "--command", "SELECT domain FROM domains LIMIT 500;", "--json"]
result = subprocess.check_output(cmd, text=True)
data = json.loads(result)

domains = []
for entry in data:
    for row in entry.get('results', []):
        if 'domain' in row:
            domains.append(row['domain'])

# Dispatch scan
payload = {
    "mode": "queue",
    "domains": domains,
    "concurrency": 25
}
with open("rescan_batch.json", "w") as f:
    json.dump(payload, f)

cmd = [
    "curl", "-s", "-X", "POST", f"{URL}/internal/tenants/scan",
    "-H", "X-Tenant: tenant-pilot-1",
    "-H", "X-Emergency-Dispatch: true-force-scan-10k",
    "-H", "Content-Type: application/json",
    "-d", "@rescan_batch.json"
]
print(subprocess.check_output(cmd, text=True))
