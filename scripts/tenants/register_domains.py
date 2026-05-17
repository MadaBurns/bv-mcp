"""Generate deterministic synthetic tenant registration SQL.

This script intentionally avoids reading customer, scan, or third-party domain
lists. The committed SQL files are OSS-safe fixtures under the reserved
example.test namespace.
"""

# Note: D1 execute has a character limit, so we chunk into 50s.
TOTAL_DOMAINS = 500
CHUNK_SIZE = 50
ADDED_AT = 1778400000

domains = [f"tenant-seed-{i:03d}.example.test" for i in range(1, TOTAL_DOMAINS + 1)]

for i in range(0, len(domains), CHUNK_SIZE):
    chunk = domains[i:i + CHUNK_SIZE]
    values = ", ".join([f"('{d}', 'synthetic-batch-import', {ADDED_AT})" for d in chunk])
    sql = f"INSERT OR IGNORE INTO domains (domain, source, added_at) VALUES {values};"

    with open(f'register_{i//CHUNK_SIZE}.sql', 'w') as f:
        f.write(sql)

print(f"Generated {len(domains) // CHUNK_SIZE} synthetic registration scripts.")
