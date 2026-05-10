import json

# Read the domains extracted earlier
with open('domains.json', 'r') as f:
    content = json.load(f)

domains = []
for entry in content:
    for row in entry.get('results', []):
        if 'domain' in row:
            domains.append(row['domain'])

# Limit to 500 domains for initial test registration
unique_domains = sorted(list(set(domains)))[:500]

# Generate a single batch insert statement
# Note: D1 execute has a character limit, so we chunk into 50s.
CHUNK_SIZE = 50
for i in range(0, len(unique_domains), CHUNK_SIZE):
    chunk = unique_domains[i:i + CHUNK_SIZE]
    values = ", ".join([f"('{d}', 'batch-import', {1778400000})" for d in chunk])
    sql = f"INSERT OR IGNORE INTO domains (domain, source, added_at) VALUES {values};"
    
    with open(f'register_{i//CHUNK_SIZE}.sql', 'w') as f:
        f.write(sql)

print(f"Generated {len(unique_domains)//CHUNK_SIZE + 1} registration scripts.")
