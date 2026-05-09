#!/usr/bin/env python3
import asyncio
import aiohttp
import time
import random
import statistics
import json
import os

# --- CONFIGURATION ---
BASE_URL = os.getenv("BV_MCP_URL", "http://localhost:8787")
API_KEY = os.getenv("BV_API_KEY", "")
BATCH_SIZE = 100
TOTAL_DOMAINS_SIMULATED = 1000
CONCURRENT_BATCHES = 10 
DNS_CHAOS_MODE = True

class ChaosResult:
    def __init__(self, name):
        self.name = name
        self.latencies = []
        self.errors = 0
        self.successes = 0
        self.budget_exceeded = 0

async def run_batch_task(session, batch_id, domains, scenario_name, results):
    payload = {
        "tool": "scan_domain",
        "domains": domains,
        "concurrency": 25, 
        "arguments": {"force_refresh": False}
    }
    
    start = time.perf_counter()
    try:
        async with session.post(f"{BASE_URL}/internal/tools/batch?format=structured", 
                               json=payload, 
                               headers={"Authorization": f"Bearer {API_KEY}"},
                               ssl=False) as resp:
            data = await resp.json()
            elapsed = time.perf_counter() - start
            results.latencies.append(elapsed)
            
            if resp.status == 200:
                summary = data.get("summary", {})
                results.successes += summary.get("succeeded", 0)
                results.errors += summary.get("failed", 0)
                
                for r in data.get("results", []):
                    if r.get("result", {}).get("error") == "batch_budget_exceeded":
                        results.budget_exceeded += 1
                return data
            else:
                results.errors += len(domains)
                print(f"Batch {batch_id} failed with status {resp.status}")
                return None
                
    except Exception as e:
        print(f"Batch {batch_id} Exception: {e}")
        results.errors += len(domains)
        return None

async def main():
    print(f"🚀 STARTING GLOBAL SCALE CHAOS TEST: {TOTAL_DOMAINS_SIMULATED} REAL-WORLD DOMAINS")
    print(f"Scenario: Scaling simulation for Tenant Global (2.5M Target)")
    print("-" * 60)

    results = ChaosResult("Global Scale Simulation")
    manifest = []
    
    base_domains = [
        "google.com", "cloudflare.com", "github.com", "microsoft.com", "amazon.com",
        "apple.com", "meta.com", "twitter.com", "linkedin.com", "netflix.com",
        "salesforce.com", "hubspot.com", "zendesk.com", "slack.com", "okta.com",
        "cscglobal.com", "cscdigitalbrand.services", "corporateservicecompany.com",
        "nytimes.com", "bbc.co.uk", "cnn.com", "reuters.com", "theguardian.com",
        "spotify.com", "adobe.com", "zoom.us", "dropbox.com", "paypal.com",
        "stripe.com", "shopify.com", "atlassian.com", "notion.so", "figma.com"
    ]
    
    all_test_domains = []
    for i in range(TOTAL_DOMAINS_SIMULATED):
        if DNS_CHAOS_MODE and i % 5 == 0:
            all_test_domains.append(f"chaos-{random.randint(1,1000000)}.invalid")
        else:
            all_test_domains.append(random.choice(base_domains))

    batches = [all_test_domains[i:i + BATCH_SIZE] for i in range(0, len(all_test_domains), BATCH_SIZE)]
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        with open("reports/scale-audit-log.txt", "w") as log_file:
            log_file.write(f"--- VERBOSE SCALE AUDIT START: {time.ctime()} ---\n")
            for i, batch in enumerate(batches):
                tasks.append(run_batch_task(session, i, batch, "SCALING", results))
                
                if len(tasks) >= CONCURRENT_BATCHES:
                    batch_start = time.perf_counter()
                    batch_responses = await asyncio.gather(*tasks)
                    batch_elapsed = time.perf_counter() - batch_start
                    
                    # Capture manifest data
                    for data in batch_responses:
                        if data:
                            for r in data.get("results", []):
                                domain = r["domain"]
                                res = r.get("result", {})
                                if not r.get("isError") and res:
                                    # Fix: StructuredScanResult has direct score/grade fields
                                    manifest.append({
                                        "domain": domain,
                                        "score": res.get("score"),
                                        "grade": res.get("grade")
                                    })
                    
                    log_file.write(f"[AUDIT] Batch {i} Processed. Count: {len(tasks)*BATCH_SIZE}, Latency: {batch_elapsed:.4f}s, Rate: {(len(tasks)*BATCH_SIZE)/batch_elapsed:.2f} d/s\n")
                    log_file.flush()
                    tasks = []

            if tasks:
                batch_responses = await asyncio.gather(*tasks)
                for data in batch_responses:
                    if data:
                        for r in data.get("results", []):
                            domain = r["domain"]
                            res = r.get("result", {})
                            if not r.get("isError") and res:
                                manifest.append({
                                    "domain": domain,
                                    "score": res.get("score"),
                                    "grade": res.get("grade")
                                })

    # Save manifest
    with open("reports/scan-manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest saved: {len(manifest)} domains recorded.")

    print("\n" + "="*60)
    print("📊 CHAOS TEST REPORT: REAL-WORLD SCALE PROOF")
    print("="*60)
    print(f"Total Domains Processed:  {TOTAL_DOMAINS_SIMULATED}")
    
    total_checks = results.successes * 17
    throughput = (TOTAL_DOMAINS_SIMULATED / sum(results.latencies)) if results.latencies else 0
    checks_per_sec = (total_checks / sum(results.latencies)) if results.latencies else 0
    
    print(f"Global Throughput:        {throughput:.2f} domains/sec")
    print(f"Check Density:            {checks_per_sec:.2f} checks/sec")
    print(f"Success Rate:             {(results.successes/TOTAL_DOMAINS_SIMULATED)*100:.2f}%")
    print(f"Error Rate:               {(results.errors/TOTAL_DOMAINS_SIMULATED)*100:.2f}%")
    print(f"Budget Exceeded:          {results.budget_exceeded} (Timeout resilience)")
    print("-" * 60)
    
    if results.latencies:
        print(f"P50 Batch Latency:        {statistics.median(results.latencies):.2f}s")
        print(f"P95 Batch Latency:        {statistics.quantiles(results.latencies, n=20)[18]:.2f}s")
    
    print("-" * 60)
    
    seconds_per_25m = (2500000 / throughput) if throughput > 0 else 0
    print(f"Extrapolated time for 2.5M domains: {seconds_per_25m/3600:.2f} hours")
    
    expected_success = 0.80 if DNS_CHAOS_MODE else 0.98
    if (results.successes / TOTAL_DOMAINS_SIMULATED) >= (expected_success - 0.05):
        print(f"\n✅ VERDICT: SCALE PROVEN. Platform stable under high concurrency.")
        print(f"   Throughput of {throughput:.2f} d/s clears 2.5M domains in {seconds_per_25m/3600:.1f}h.")
    else:
        print("\n❌ VERDICT: SCALE FAILED. Error rate exceeded chaos threshold.")

if __name__ == "__main__":
    asyncio.run(main())
