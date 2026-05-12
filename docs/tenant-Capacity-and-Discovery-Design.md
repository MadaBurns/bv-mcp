# Tenant Global — 2.5M-Domain Capacity Assessment + Registrar-Discovery Design

**Status:** internal prep doc, gitignored. Not for distribution.
**Date:** 2026-05-09
**Companion to:** `redacted-tenant-Call-Prep.md`

---

## TL;DR

1. **Capacity for 2.5M scans:** ✅ feasible. Realistic runtime **20 hours sustained or 2.5 days at 50% concurrency**; **bottleneck is KV writes**, not CPU or origin DoH. Estimated additive Cloudflare cost **$200–250 one-shot** or **$25–35/day amortised over 7 days**. No re-architecture needed — current `/internal/tools/batch` endpoint is the right path. **`partner` tier daily quota for `scan_domain` (100K/day) must be raised** for Tenant-class customers.
2. **Registrar-discovery system:** ✅ designable as a separate phased capability on top of existing `discover_subdomains` + `rdap_lookup` + DMARC-RUA mining. Doesn't need new ingest scale; runs offline against a customer's known-domain seed set. Ships as a new MCP tool `discover_brand_domains` + a bv-web admin route. **Estimated build: 3–5 days for v1**.

---

## 1. Capacity assessment — projecting 2.5M domains

### 1.1 Observed unit economics (last 7 days, prod analytics)

| Metric | Value | Source |
|---|---|---|
| `scan_domain` p50 latency | **12.5 s** | Analytics Engine, last 7d (1.4M calls) |
| `scan_domain` p95 latency | 18.0 s | same |
| `scan_domain` p99 latency | 21.7 s | same |
| Sub-check fanout per scan | 16 leaf checks | `src/tools/scan-domain.ts:196` |
| KV ops per cold scan | ~34 (17 reads + 17 writes) | `runWithCache` × 16 + top-level |
| KV ops per warm scan (5-min TTL hit) | ~2 (1 read + 0 writes) | top-level `cache:<domain>` hit |
| Tool-call analytics events / scan | 1 (orchestrator) | only orchestrator emits |
| DoH queries per scan | 16–48 (depends on record types) | DNS-over-HTTPS facade |
| Origin HTTPS fetches per scan | 2–6 | `safeFetch` call sites |

### 1.2 Throughput projection

**Scenario A — single hot day (one-shot batch)**

| Resource | Per-scan cost | × 2.5M | Daily limit (paid) | Verdict |
|---|---|---|---|---|
| Workers requests (via `/internal/tools/batch`, 100 domains/req) | 1 | 25,000 batch reqs | 10,000,000 included | ✅ trivial |
| Workers CPU (bundled) | ~12.5s wall, ~1–2s billable CPU | ~5,000 CPU-min | per-request 30s ceiling | ✅ fits |
| KV reads (cold) | 17 | **42.5 M** | 10 M/day included | ⚠️ overage ~$16 |
| KV writes (cold) | 17 | **42.5 M** | 1 M/day included | ⚠️ overage **~$207** |
| Analytics Engine writes | 1 tool_call event | 2.5 M | 100 M/day included | ✅ fits |
| DoH queries | 16 avg | 40 M | unlimited (own DoH) | ✅ |
| `partner` tier daily `scan_domain` quota | 1 | 2.5 M | **100,000/day** | 🔴 **MUST RAISE** |

**Estimated Cloudflare add-on cost for one-shot run: $200–250.**

**Scenario B — spread over 7 days (recommended)**

| Resource | Per-day | Daily limit | Verdict |
|---|---|---|---|
| KV reads | 6.07 M | 10 M | ✅ within |
| KV writes | 6.07 M | 1 M | ⚠️ ~$25/day overage = **~$175 total** |

### 1.2.1 Calibration findings (2026-05-09)

Three measurements against prod via the public `/mcp` endpoint (`tools/call name=scan_domain`, anonymous tier, 50/min rate limit):

| Test | N | Concurrency | force_refresh | p50 latency | p95 latency | Notes |
|---|---|---|---|---|---|---|
| Warm cache, popular pool | 25 | 10 | `false` | 126 ms | 457 ms | All hit `cache:<domain>` 5-min TTL |
| Cold scan, popular pool | 20 | 5 | `true` | 141 ms | 465 ms | Fast-resolving DNS hierarchies (Google/CF/AWS NS) |
| Production aggregate (last 7d) | 1,425,003 | various | mixed | 12,473 ms | 17,963 ms | Mix of fast-resolving and slow-resolving customer portfolios |

**Reading:** the 100× spread between calibration (~140 ms) and production aggregate (~12.5 s) reflects which DNS hierarchies the domains live on. Tenant's customers have heterogeneous portfolios — assume the production-aggregate envelope (12.5s p50) for capacity planning, **but** repeat-scan / monitoring throughput is bounded by the warm-path number (~140 ms) because the orchestrator-level `cache:<domain>` (5 min TTL) absorbs the second hit. This is significant for use case 2 (continuous monitoring): a weekly re-scan of an unchanged portfolio mostly hits the cache and runs at ~7 scans/sec/concurrent-slot rather than ~0.1/sec.

**Empirical confirmation of:**
- Anonymous tier per-IP rate limit (50/min) — not exceeded at the test concurrencies.
- `tools/call scan_domain` returns successful result frame on every call (no parse / schema error).
- The `force_refresh: true` argument does propagate (cold-path via the `skipCache` plumb).

**Empirical gaps still to fill (need owner-tier auth):**
- Owner-authenticated throughput at concurrency=50 (current `BV_API_KEY` env var is a rotated-out key — Worker rejects with 401; rotate or fetch from password manager).
- 2,000-domain run with mixed-portfolio domains (slow-resolving + fast-resolving) to ground-truth the 12.5s p50 against synthetic load rather than passive prod traffic.
- `/internal/tools/batch` calibration — only callable from a CF Worker via service binding, so requires running the script from inside a sister Worker (or accepting the public-`/mcp` data as proxy).

### 1.3 Throughput envelope

Past load test (v1.1.0, 2026-03-13): peak **4,266 RPS** on the protocol layer, sweet spot **2,300 RPS sustained**. Scan throughput is materially lower because each `scan_domain` spawns 16 internal DoH queries and waits.

**Realistic batch throughput (`/internal/tools/batch` with concurrency=25, batch=100, 10 concurrent batches):**

```
domains_per_second = (10 batches × 25 concurrent) / 12.5s p50 = 20 scans/sec sustained
2.5M ÷ 20 = 125,000 sec ≈ 35 hours
```

**Bumping `concurrency` to 50 (max per `/internal/tools/batch`) + 20 concurrent batches:**

```
50 × 20 = 1,000 in flight, 1,000 / 12.5s = 80 scans/sec → ~9 hours
```

**Recommendation:** spread over 2–3 calendar days at the 80-scans/sec setting to amortise KV writes and stay polite to CF DoH origin pool.

### 1.4 Required configuration changes (today)

1. **Raise `partner.scan_domain` quota** in `src/lib/config.ts` `TIER_TOOL_DAILY_LIMITS.partner.scan_domain` from `100_000` to either `2_500_000` (one-shot) **or** add a new `enterprise_scale` tier for Tenant-class customers. Path-of-least-resistance: bump `partner` cap. **2-line change → ship as v2.10.13.**
2. **Whitelist Tenant IPs in `OWNER_ALLOW_IPS`** OR provision a new high-tier API key.
3. **No code changes needed for the scan path itself.** `/internal/tools/batch` already handles concurrency, budget, and validation.

### 1.5 Pre-flight checks before greenlighting

| Check | How | Owner |
|---|---|---|
| Verify CF account on Workers Paid plan | `wrangler whoami` + dashboard | Adam |
| Pre-warm KV write quota | Increase via dashboard → Workers Plan | Adam |
| Confirm batch budget defaults | `BATCH_DEFAULT_CONCURRENCY=10`, `BATCH_MAX_BODY_BYTES=262144` (already current) | dev |
| Calibration run (200 domains) | `tenant-scale-chaos.py TOTAL_DOMAINS_SIMULATED=200` | dev — needs explicit auth |
| Daily quota override for Tenant | new `partner` cap or new tier | dev |

---

## 2. Registrar-discovery system design

### 2.1 Goal

Given a Tenant customer's known portfolio (e.g. 800 domains they manage with Tenant), surface domains they ALSO own that are registered with **other registrars** (GoDaddy, Network Solutions, Tucows, Namecheap, etc.) — typically due to:

- Acquisitions where the acquired company's domains haven't been transferred
- Marketing-team registrations on personal credit cards
- Regional/country-specific subsidiaries
- Defensive registrations (typos, lookalikes) at the cheapest registrar
- Legacy / forgotten domains

**Pitch value:** *"You manage 800 with us. We found 217 more your org owns at GoDaddy/NetSol — including 9 with no DNSSEC, 23 with broken DMARC, and 4 expired-soon."*

### 2.2 Discovery pipeline (six independent signal sources)

**Tier 1 — High confidence (deterministic ownership signals):**

1. **TLS Subject Alternative Name (SAN) clustering.** *(External research 2026-05-09 — prior art: `bit4woo/teemo`, 1k⭐ on GitHub.)* When a customer renews a wildcard or multi-domain cert, the SAN list is published to CT logs forever. For every customer-domain seed: query `crt.sh?q=<domain>&output=json`, extract every distinct SAN across the matched certs, dedupe → those domains are co-owned. **Deterministic** for any cert issued for the customer's portfolio. Cheap (CT logs are free). **Lead signal — should run first.**
2. **NS-record correlation.** Fetch NS records for every customer domain. Reverse-lookup: enumerate the customer's NS records *across* their portfolio, then crt.sh / CT-log for any other domains pointing at the same NS pool. A custom self-hosted NS = strong ownership signal.
3. **DMARC `rua=mailto:` aggregation.** Customer's known domains expose RUA report addresses. Other domains with the same RUA address are almost certainly co-owned.
4. **DKIM selector + key reuse.** Same DKIM key published at `selector._domainkey.<other-domain>` is near-deterministic (selector + RSA public key match).

**Tier 2 — Medium confidence (statistical):**

4. **SPF `include:` graph.** Customer domains include `_spf.customer.com`; reverse-correlate any external domain with the same `include:` directive.
5. **CAA records.** Customer-specific CAA `issue "ca.example.com; account=12345"` (account-bound CAA) appears on co-owned domains.
6. **Subdomain leak via CT logs.** `discover_subdomains` already exists. Run against `*.acquired-brand.com` patterns for known acquisitions.

**Tier 3 — Low confidence (corroboration only):**

7. **WHOIS/RDAP registrant name match.** Many domains have privacy guards; useful when registrant data is exposed.
8. **Reverse-DNS / hosting IP overlap.** Domains pointing at the customer's IP space (via SPF `ip4:` or A records).
9. **Brand-mention TLDs.** Generated typos / lookalikes against the known domain — `check_lookalikes` already exists; run with widened similarity threshold.

### 2.3 Architecture (v1 — no new infra)

```
┌─────────────────────────────────────────────────────────┐
│  bv-web admin route: /admin-v3/business.brand-discovery │
│  inputs: customer_id (from Tenant's tenant DB)             │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  bv-mcp new tool: discover_brand_domains                │
│   args: {                                               │
│     seed_domains: string[],     // ≤500 known portfolio │
│     signals: ('ns'|'rua'|'dkim'|'spf'|'caa'|'ct')[]    │
│     max_candidates: 1000,                               │
│   }                                                     │
└────────────────────────┬────────────────────────────────┘
                         │  parallel signal collection
        ┌────────────────┼────────────────┬───────────┐
        ▼                ▼                ▼           ▼
  ┌──────────┐    ┌──────────┐    ┌──────────┐  ┌──────────┐
  │ NS pool  │    │ DMARC    │    │ DKIM     │  │ CT logs  │
  │ extract  │    │ rua=     │    │ selector │  │(certstr) │
  └────┬─────┘    └────┬─────┘    └────┬─────┘  └────┬─────┘
       └────────┬──────┴───────────────┴─────────────┘
                ▼
         ┌─────────────┐
         │ Reverse     │  e.g. crt.sh, certstream, RDAP
         │ correlator  │  scoring 0–100 per candidate
         └──────┬──────┘
                ▼
         ┌─────────────────────────────┐
         │ Candidate registrar lookup  │  RDAP query → who's the registrar
         │ (filter: NOT in Tenant list)   │
         └──────┬──────────────────────┘
                ▼
         ┌─────────────────────────────┐
         │ Risk scan (existing)        │  ← scan_domain on each candidate
         │ scan_domain × N             │
         └──────┬──────────────────────┘
                ▼
         ┌─────────────────────────────┐
         │ Output:                     │
         │  {                          │
         │   candidate: 'foo.com',     │
         │   confidence: 0.92,         │
         │   signals: ['rua','dkim'],  │
         │   registrar: 'GoDaddy',     │
         │   risk_score: 42,           │
         │   issues: ['no DMARC',...] │
         │  }                          │
         └─────────────────────────────┘
```

### 2.4 New code surface

| Layer | New file |
|---|---|
| `src/tools/discover-brand-domains.ts` | orchestrator |
| `src/tools/brand-signals/ns-correlator.ts` | NS-pool reverse lookup |
| `src/tools/brand-signals/rua-correlator.ts` | DMARC RUA address mining |
| `src/tools/brand-signals/dkim-correlator.ts` | DKIM key fingerprint match |
| `src/tools/brand-signals/spf-correlator.ts` | SPF include-graph reverse |
| `src/tools/brand-signals/caa-correlator.ts` | CAA account-binding match |
| `src/tools/brand-signals/registrar-classifier.ts` | RDAP → registrar normalisation |
| `src/schemas/tool-args.ts` | `DiscoverBrandDomainsArgs` Zod |
| `src/schemas/tool-definitions.ts` | tool entry |
| `src/lib/config.ts` | `discover_brand_domains` quota |
| `test/discover-brand-domains.spec.ts` | unit + integration tests |
| `bv-web app/routes/admin-v3/business.brand-discovery.tsx` | UI |
| `bv-web app/lib/services/clients/bv-mcp-client.ts` | client method `discoverBrandDomains` |

### 2.5 Build sequence (v1, 3–5 days)

| Day | Deliverable |
|---|---|
| 1 | NS + DMARC RUA correlators + reverse-lookup helper. Unit tests with fixtures. |
| 2 | DKIM + SPF correlators + registrar classifier (RDAP wrapper). |
| 3 | Orchestrator + scoring + Zod schema + tool registry wire-up. CT-log integration via existing `BV_CERTSTREAM` binding. |
| 4 | bv-web admin UI + service-binding client method. End-to-end test against a known seed (e.g. `blackveilsecurity.com` portfolio). |
| 5 | Hardening: rate-limit per-customer, cost ceilings, dataset-size caps, audit logging. Demo dry-run against Tenant's public portfolio. |

### 2.6 Privacy / legal considerations

- **DMARC RUA mining is public data.** Anyone can query `_dmarc.*` and see the RUA. No privacy concern.
- **DKIM key disclosure is public.** Public DNS by design.
- **NS reverse-lookup via crt.sh is public CT-log data.** No privacy concern.
- **WHOIS/RDAP registrant data** — increasingly redacted under GDPR. Use as soft signal only; don't store redacted data.
- **Tenant contractual question:** can they share their customer's seed domains with us for the discovery run? Likely yes under their existing customer contracts (DNS security audit is a common service add-on). **Ask Tenant's legal before pilot.**
- **Output is a list of public domains owned by the customer's parent org.** No PII leak.

### 2.7 Pricing model (suggested)

- **Per-customer flat rate:** $2,500–5,000 per discovery run (one-shot deep audit).
- **Or:** $500/customer/month for ongoing monitoring (re-run weekly, alert on new candidates).
- Tenant margin: bundle as a value-add to their renewal pitch ("we found you N hidden domains").

### 2.8 Risks / open questions

1. **False-positive rate.** A small/medium business might share a generic SPF include like `_spf.google.com` with thousands of unrelated orgs. **Mitigation:** only correlate on **customer-specific** signals (custom DKIM keys, custom NS pools, custom RUA addresses with the customer's domain).
2. **Rate-limit on RDAP / crt.sh.** Both have polite-use limits. **Mitigation:** cache aggressively, batch lookups.
3. **Tenant customer trust.** They might not want to share their customer list with us. **Alternative:** Tenant runs the tool on their side via service binding (we provide the binary).
4. **Legal vetting.** Cross-border discovery (EU customers, GDPR) may need legal review before commercial offering.
5. **Acquisition data accuracy.** Public M&A databases (Crunchbase, etc.) can seed the search but are noisy.

---

## 3. Recommended next steps (in order)

1. **Today:** raise `TIER_TOOL_DAILY_LIMITS.partner.scan_domain` from 100K → 2.5M (or add `enterprise_scale` tier). PR + ship as v2.10.13. **(2-line change.)**
2. **Pre-call (1 day):** run `tenant-scale-chaos.py` with 200 domains for empirical throughput numbers — replaces the estimates above with measured. Update §1.2 of this doc.
3. **Call:** present capacity numbers + discovery-system pitch. Get green-light on legal/contractual.
4. **Post-call (3–5 days):** build `discover_brand_domains` v1 per §2.5.
5. **Pilot (1 week):** demo run against 1 Tenant customer's public portfolio. Iterate on confidence scoring.
6. **GA (2 weeks after pilot):** package as a Tenant value-add, wire pricing.

---

*Working doc — refine before sharing externally.*
