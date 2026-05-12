import json
import subprocess
import time
import sys

URL = "https://bv-dns-security-mcp.bv-edge.workers.dev"

with open('domains.json', 'r') as f:
    content = json.load(f)

domains = []
for entry in content:
    for row in entry.get('results', []):
        if 'domain' in row:
            domains.append(row['domain'])

domains = domains[:10000]

CHUNK_SIZE = 50
total_chunks = (len(domains) + CHUNK_SIZE - 1) // CHUNK_SIZE

print(f"Starting {total_chunks} sync batches for {len(domains)} domains...")

success_count = 0

for i in range(total_chunks):
    chunk = domains[i*CHUNK_SIZE:(i+1)*CHUNK_SIZE]
    payload = {
        "mode": "sync",
        "domains": chunk,
        "concurrency": 10
    }
    batch_file = "temp_sync_batch.json"
    with open(batch_file, "w") as f:
        json.dump(payload, f)
        
    print(f"[{i+1}/{total_chunks}] Dispatching {len(chunk)} domains...", end=" ")
    sys.stdout.flush()
    
    cmd = [
        "curl", "-s", "-X", "POST", f"{URL}/internal/tenants/scan",
        "-H", "X-Tenant: tenant-example",
        "-H", "X-Synthetic-Dispatch: synthetic-force-scan-10k",
        "-H", "Content-Type: application/json",
        "-d", f"@{batch_file}"
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
