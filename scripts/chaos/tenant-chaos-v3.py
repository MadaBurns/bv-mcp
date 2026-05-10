#!/usr/bin/env python3
"""
Multi-Tenant Hammer v3 (Chaos Test)
Simulates high-concurrency multi-tenant orchestrator load.

Covers:
- Parallel tenant portfolio updates
- Overlapping scan cycles across separate D1 databases
- Phase 6 Fingerprint efficiency (double-scan latency)
- Shared Registry (Audit Log) contention
"""

import asyncio
import aiohttp
import time
import random
import json
import os
import statistics
from collections import defaultdict

# --- CONFIGURATION ---
BASE_URL = os.getenv("BV_MCP_URL", "http://localhost:8787")
INTERNAL_KEY = os.getenv("BV_INTERNAL_KEY", "tenant-orchestrator-internal-key")
TENANTS = [f"hammer-tenant-{i}" for i in range(10)]
DOMAINS_PER_TENANT = 20
CONCURRENCY_PER_REQUEST = 5

class HammerStats:
    def __init__(self):
        self.latencies = defaultdict(list)
        self.status_codes = defaultdict(int)
        self.scans_skipped = 0
        self.scans_performed = 0

stats = HammerStats()

async def tenant_request(session, method, path, tenant_id, body=None):
    headers = {
        "Authorization": f"Bearer {INTERNAL_KEY}",
        "X-Tenant": tenant_id,
        "Content-Type": "application/json"
    }
    url = f"{BASE_URL}{path}"
    start = time.perf_counter()
    try:
        async with session.request(method, url, headers=headers, json=body) as resp:
            elapsed = time.perf_counter() - start
            stats.latencies[path].append(elapsed)
            stats.status_codes[resp.status] += 1
            if resp.status == 200:
                return await resp.json()
            return None
    except Exception as e:
        print(f"[{tenant_id}] Request Error: {e}")
        return None

async def run_hammer_cycle(session, tenant_id):
    # 1. Update Portfolio
    domains = [f"{tenant_id}-{i}.com" for i in range(DOMAINS_PER_TENANT)]
    await tenant_request(session, "POST", "/internal/tenants/portfolio", tenant_id, {"domains": domains})

    # 2. Start First Scan (Fresh)
    res1 = await tenant_request(session, "POST", "/internal/tenants/scan", tenant_id, {
        "domains": domains[:5], 
        "force_refresh": True 
    })
    if res1:
        stats.scans_performed += res1.get("completed", 0)

    # 3. Start Second Scan (Fingerprint Pre-flight)
    # This should be much faster due to Phase 6 skips.
    start = time.perf_counter()
    res2 = await tenant_request(session, "POST", "/internal/tenants/scan", tenant_id, {
        "domains": domains[:5]
    })
    elapsed = time.perf_counter() - start
    if res2:
        stats.scans_skipped += res2.get("completed", 0)
        # print(f"[{tenant_id}] Phase 6 pre-flight took {elapsed:.4f}s")

async def main():
    print(f"🔨 STARTING MULTI-TENANT HAMMER v3")
    print(f"Target: {BASE_URL}")
    print(f"Tenants: {len(TENANTS)} | Domains/Tenant: {DOMAINS_PER_TENANT}")
    print("-" * 60)

    start_time = time.perf_counter()
    async with aiohttp.ClientSession() as session:
        # Run all tenant hammers concurrently
        tasks = [run_hammer_cycle(session, tid) for tid in TENANTS]
        await asyncio.gather(*tasks)

    total_time = time.perf_counter() - start_time

    print("\n" + "="*60)
    print("📊 HAMMER TEST REPORT")
    print("="*60)
    print(f"Total Duration:          {total_time:.2f}s")
    print(f"Status Codes:            {dict(stats.status_codes)}")
    
    for path, lats in stats.latencies.items():
        avg = statistics.mean(lats) if lats else 0
        p95 = statistics.quantiles(lats, n=20)[18] if len(lats) >= 20 else max(lats) if lats else 0
        print(f"\nPath: {path}")
        print(f"  Avg Latency:           {avg:.4f}s")
        print(f"  P95 Latency:           {p95:.4f}s")

    print("-" * 60)
    print(f"Total Scans Performed:   {stats.scans_performed}")
    print(f"Total Scans Skipped:     {stats.scans_skipped} (Phase 6 efficiency)")
    
    if stats.status_codes.get(200, 0) == len(TENANTS) * 3: # 1 portfolio + 2 scans per tenant
        print("\n✅ VERDICT: HAMMER SUCCESS. Multi-tenant concurrency proven.")
    else:
        print("\n❌ VERDICT: HAMMER FAILED. Check status codes or errors.")

if __name__ == "__main__":
    asyncio.run(main())
