---
title: 'BlackVeil DNS — DomainSec Complement: Walkthrough'
subtitle: 'AI-Vendor Case Study · OpenAI · Anthropic · x.ai · + 22-provider cohort'
date: '2026-05-23'
author: 'BlackVeil Security · contact@example.com'
---

# Walkthrough — case-study deep dive

Read this in order; each section answers a question a CSC partner is likely to ask next, in the order they're likely to ask it. Every claim is reproducible from public DNS, RDAP, WHOIS, and Certificate Transparency — see `03-provenance.pdf` for the verification matrix and commands.

**Reading order:**

0. _What's the overall posture grade for each apex?_ → §0, the per-apex letter grades (12 apexes scanned via the deployed engine).
1. _Will this annoy our customers with noise?_ → §1, the honest negative on Anthropic.
2. _What does a real finding look like?_ → §2, OpenAI CRITICAL (with Wayback + MS-Learn anchoring).
3. _Can one mistake matter?_ → §3, x.ai's 9-endpoint cluster from a single AWS deletion.
4. _Does this surface anything CSC's portfolio inventory can't see?_ → §4, the `grok-4-code-0630` disclosure from public CT logs.
5. _Does this generalize beyond a cherry-picked three?_ → §5, the **expanded 22-provider cohort (25 total, 21 clean)**.
6. _What about typosquats and brand impersonation?_ → §6.
7. _What about off-primary-registrar sprawl — the partnership brief headline?_ → §7.

---

## § 0 — Per-apex posture grades (deployed engine, 25 categories)

The deployed BlackVeil scanner returns a letter grade per apex across 25 categories (SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, lookalikes, shadow domains, TXT hygiene, HTTP security, DANE, MX reputation, SRV, zone hygiene, DANE-HTTPS, SVCB-HTTPS, subdomailing, brand discovery, authoritative DNS infra, subdomain takeover). Every grade below is reproducible against `https://dns-mcp.blackveilsecurity.com/mcp` with a single `scan_domain` call.

### Primary apexes

| Vendor    | Apex            |  Score | Grade | Notable failing categories                                                                                                                                           |
| --------- | --------------- | -----: | :---: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Anthropic | `anthropic.com` | 79/100 | **B** | (top of cohort; minor hardening gaps only)                                                                                                                           |
| x.ai      | `x.ai`          | 69/100 | **C** | subdomain-takeover cluster (the 9 x.ai NLB endpoints — see §3)                                                                                                       |
| OpenAI    | `openai.com`    | 51/100 | **D** | DNSSEC 0/100, MTA-STS 0/100, SVCB-HTTPS 0/100, DKIM 45/100 (legacy 1024-bit RSA key `s2`, missing `v=DKIM1` tags), subdomain takeover 45/100 (the CRITICAL — see §2) |

### Fully-spoofable brand apexes (all grade F)

| Apex           |  Score | Grade | Registrar   | Notes                                                                                 |
| -------------- | -----: | :---: | ----------- | ------------------------------------------------------------------------------------- |
| `openai.org`   | 26/100 | **F** | MarkMonitor | Primary-registrar weakness — consolidation didn't fix email-auth                      |
| `openai.co.uk` | 26/100 | **F** | Key-Systems | Mail-active, no SPF, no DMARC                                                         |
| `anthropic.ca` | 28/100 | **F** | Tucows      | Mail-active, no SPF, no DMARC                                                         |
| `anthropic.co` | 26/100 | **F** | GoDaddy     | Brand-owned (redirects to `anthropiclabs.com`) AND fully spoofable AND on third-party |

### Brand-owned third-party apexes

| Apex           |  Score | Grade  | Registrar                            | Notes                                   |
| -------------- | -----: | :----: | ------------------------------------ | --------------------------------------- |
| `openai.sg`    | 62/100 | **D+** | Exabytes Network (Singapore) Pte Ltd | Off-portfolio asset class               |
| `anthropic.io` | 52/100 | **D**  | GoDaddy                              | Explicit non-mail (gold-standard)       |
| `openai.io`    | 49/100 | **F**  | GoDaddy                              | Redirects to `openai.com/sam-and-jony/` |

**What CSC partners take from §0:** the letter grade is a **reproducible 25-category score**, not an alert. It travels in customer reporting in a way "DNS change detected" alerts don't. Crucially, **all 4 fully-spoofable apexes grade F (26–28/100)** — including `openai.org`, which is on MarkMonitor. Primary-registrar consolidation is not the same as email-auth hygiene; the two value chains are complementary, not overlapping.

---

## § 1 — Anthropic: 0 dangling across 129 subdomains

**The honest negative is the first thing a CSC customer should hear.** A tool that surfaces findings on every target is a tool that generates noise. Anthropic's CT-enumerated subdomain inventory (129 unique subs from 280 certificates across multiple CAs) was swept end-to-end and returned **zero** CNAME→NXDOMAIN orphans and **zero** storage-provider not-found candidates. Tight engineering hygiene; nothing to remediate.

This is the answer to _"is our subdomain inventory under control?"_ — a question a CSC customer would otherwise have no defensible way to answer. BlackVeil DNS's value here is the clean-sweep evidence, not a finding list.

Representative subdomains visible from public CT logs (no findings — just observability):

- `stt-nova3.titanium-staging.api.anthropic.com`
- `stt-flux-multi-a100.titanium-staging.api.anthropic.com`
- `a-cdn.anthropic.com`, `go.anthropic.com`

The fact that internal-staging hostnames are visible at all is itself a recon-signal observation — not a finding, but the kind of CT-log surface enumeration that requires a vantage point on the **public** observability surface (every certificate ever issued), rather than the **managed** surface (the customer's CSC-hosted DNS zone). CSC's [Subdomain Monitoring solution](CSC public Subdomain Monitoring product page) watches CSC-managed DNS records; BlackVeil DNS watches the CT-log issuance graph. The two are complementary — anything issued for a customer's subdomain that **doesn't go through CSC** (think: a SaaS vendor issuing a cert for `customer.vendor.com` aliased back to the customer brand, or a former contractor's cert on a sunset hostname) won't show up in CSC's daily zone-monitor, but it will show up in CT.

---

## § 2 — OpenAI: 1 CRITICAL takeover candidate, 4 MEDIUM operational drift

### The CRITICAL: `cdn.openai.com` → reclaimable Azure Front Door endpoint

The DNS chain resolves: `cdn.openai.com → openaiassets.azureedge.net → openaiassets.afd.azureedge.net`. The AFD endpoint **returns HTTP 404 at every probed path** (`/`, `/test.png`, `/v1/`, `/assets/`, `/static/`) — re-verified 2026-05-23. The response body is Azure's generic "Page not found" HTML embedding the tell-tale Azure deprovisioned-resource reference `df.onecloud.azure-test.net/Error/UE_404?shown=true`, and the `x-azure-ref` header in the response confirms Azure Front Door is still doing the routing for that hostname. The TLS handshake itself returns `ERR_CERT_COMMON_NAME_INVALID` — the deprovisioned endpoint no longer presents a valid certificate for the requested name. The deployed BlackVeil scanner independently classifies this as **"a verified takeover signal"** via the Azure CDN deprovisioned fingerprint (see scan output in `.dev/demos/csc-evidence/scan-openai.com.txt`).

**Why this is CRITICAL:** the Azure Front Door endpoint name `openaiassets` is **user-chosen** (not provider-assigned random ID), which means another Azure tenant can register an AFD endpoint with the name `openaiassets` and immediately serve content from `cdn.openai.com`. Practical takeover risk — not theoretical. The DNS-NXDOMAIN sweep alone wouldn't have caught this: the CNAME chain resolves cleanly, the application-layer response is what reveals deprovisioning.

**Wayback corroboration:** the Internet Archive holds **1,094 snapshots of `cdn.openai.com` between 2021-05-25 and 2026-05-07** — five years of real production traffic on this hostname, with the most recent snapshot just weeks before re-verification. The AFD endpoint was deprovisioned recently, the DNS pointer wasn't updated, and the namespace is now reclaimable.

**Authoritative source:** Microsoft's own subdomain-takeover guidance ([Microsoft Learn — Prevent subdomain takeovers](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover)) describes this exact pattern: "The dangling subdomain ... is now vulnerable and can be taken over by being assigned to another Azure subscription's resource." Note that AFD endpoints are **not** in Azure's list of services with name-reservation-after-deletion (only classic cloud services like `*.cloudapp.net` have a documented reservation window). Microsoft's prevention recommendation is **Azure DNS alias records**, which the customer did not deploy.

This is the kind of finding that travels in customer conversations.

### The MEDIUMs (operational drift, low practical takeover risk)

| Subdomain          | CNAME target                                                        | Status                | Classification                                                                                                                      |
| ------------------ | ------------------------------------------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `blog.openai.com`  | `d2b532lzynlqb7.cloudfront.net`                                     | NOERROR (0 A records) | CloudFront distribution deleted; 14-char ID is provider-assigned — operational drift                                                |
| `slack.openai.com` | `chatgpt-slack.jollybeach-2c1b6a13.centralus.azurecontainerapps.io` | NXDOMAIN              | Azure Container Apps env deleted; 8-hex-char `-2c1b6a13` suffix is provider-assigned (~4B-attempt search space) — operational drift |

### The LOWs (housekeeping pointers)

- `arena.openai.com` → `arena-frontend.rapid.openai.org` (NXDOMAIN — points to a sibling OpenAI apex)
- `onboard.openai.com` → `onboard.api.openai.com` (NXDOMAIN — self-referential broken pointer)

Both are inventory drift inside the brand's own namespace. Useful signal for an internal asset-management team; not a takeover vector.

---

## § 3 — x.ai: 9 dangling endpoints from a single AWS NLB deletion

A single AWS resource deletion orphaned a cluster of nine model-serving endpoints. Every one of them points at the same deleted NLB hostname:

```
ab74714963781430da5c4d9a29a6ee3c-1355387950.us-east-1.elb.amazonaws.com  (NXDOMAIN)
```

The affected subdomains:

- `aurora-sglang.us-east-1.models.x.ai`
- `aurora-upsampler-sglang.us-east-1.models.x.ai`
- `enterprise-api-grok-2-1212.us-east-1.models.x.ai`
- `grok-3-5-code-0625.us-east-1.models.x.ai`
- **`grok-4-code-0630.us-east-1.models.x.ai`** _(see § 4)_
- `embedding-10m-0806-enterprise.us-east-1.models.x.ai`
- `fte5-embedding-0806-api.us-east-1.models.x.ai`
- `fte5-v2-fast-embedding-0806-api.us-east-1.models.x.ai`
- `fte5-embedding-250707-api.us-east-1.models.x.ai`

**Two consequences:**

1. **Production model endpoints currently broken** — inventory drift with immediate operational impact.
2. **NLB hostname recycling risk** — if AWS recycles that NLB hostname (32-hex-char prefix, partly random), the inheriting tenant becomes the practical destination for these subdomains. Moderate, not imminent.

The continuous-monitoring lesson: **a single operational miss with a 9-endpoint blast radius is the kind of finding a continuous-monitoring service is purpose-built to catch.** It's not 9 independent failures; it's 1 failure with a 9× multiplier — exactly the customer-facing scenario where CSC's "DNS-change alerting" value prop gets its sharpest external case study.

---

## § 4 — Memorable moment: `grok-4-code-0630` in public CT logs

Inside the x.ai cluster, one subdomain stands on its own:

> `grok-4-code-0630.us-east-1.models.x.ai`

It's a model-serving endpoint pointing at a deleted AWS NLB — but the **subdomain name itself** is the finding. The string `grok-4-code-0630` discloses (a) the existence of an unannounced model variant (Grok 4 code), and (b) a likely date stamp (`0630`). It is publicly enumerable today from `crt.sh` — anyone with a 30-second curl command can read this.

**The CSC-relevant point:** this is not a DNS finding in the traditional sense. It's an **observability finding** with a different sensor: the customer's internal naming convention has leaked into a public certificate transparency log. CSC's Subdomain Monitoring watches DNS state changes on CSC-managed zones — it would not surface a name that has never appeared in the customer's DNS but has appeared in CT. BlackVeil DNS surfaces it as a side-effect of routine CT-log subdomain enumeration. Same risk class, different sensor, complementary coverage.

If you are talking to a customer who cares about competitive intelligence — i.e. every customer — this is the kind of finding that crystallizes the value of CT-log enumeration as a discipline.

(`enterprise-api-grok-2-1212` and `grok-3-5-code-0625` are also enumerable. The `-0630` variant is the one that flags as forward-looking — the date stamp postdates Grok 3.5 by ~5 days.)

---

## § 5 — Does this generalize? 22-provider cohort sweep (25 providers total)

Same methodology, broader cohort. Verifies the 3-vendor case study isn't cherry-picked.

| Provider                      |  Subdomains | CRITICAL | MEDIUM |   LOW | Notes                                                                    |
| ----------------------------- | ----------: | -------: | -----: | ----: | ------------------------------------------------------------------------ |
| **OpenAI** _(case)_           |         436 |    **1** |  **2** |     2 | Azure Front Door + CloudFront + Container Apps drift + 2 housekeeping    |
| **x.ai** _(case)_             |         102 |        — |  **9** |     — | Single AWS NLB deletion → 9 model endpoints orphaned                     |
| **Anthropic** _(case)_        |         129 |        — |      — |     — | Clean                                                                    |
| Cohere                        |   **1,085** |        — |      — |     — | Clean at scale                                                           |
| Nvidia                        |       1,113 |        — |  **1** |     — | `dev.beta.ngc.nvidia.com` → CloudFront `d22keetfi2jxs` (deleted) — drift |
| Mistral                       |         199 |        — |      — |     — | Clean                                                                    |
| Stability                     |         166 |        — |      — |     — | Clean                                                                    |
| Perplexity                    |         148 |        — |      — |     — | Clean                                                                    |
| HuggingFace                   |         137 |        — |  **1** |     — | `cdn.huggingface.co` → CloudFront `d2ws9o8vfrpkyk` (deleted) — drift     |
| Character.AI                  |          45 |        — |      — |     — | Clean                                                                    |
| DeepMind                      |          20 |        — |      — |     — | Clean (small surface — primary footprint on `google.com`)                |
| Inflection                    |          15 |        — |      — |     — | Clean                                                                    |
| Meta AI                       |          13 |        — |      — |     — | Clean (primary footprint on `meta.com`/`facebook.com`)                   |
| _Original 13-cohort subtotal_ |     _3,608_ |      _1_ |   _13_ |   _2_ | _16 findings · 9 of 13 fully clean (69%)_                                |
| Databricks                    | _scan-only_ |        — |      — |     — | **B+** posture (82/100); no takeover findings via `scan_domain`          |
| Snowflake                     | _scan-only_ |        — |      — |     — | C+ posture (70/100); clean takeover                                      |
| Notion (`notion.so`)          | _scan-only_ |        — |      — |     — | C+ posture (73/100); clean takeover                                      |
| Stripe                        | _scan-only_ |        — |      — |     — | C posture (67/100); clean takeover                                       |
| Replicate                     | _scan-only_ |        — |      — |     — | C posture (63/100); clean takeover                                       |
| Together                      | _scan-only_ |        — |      — |     — | D+ posture (57/100); clean takeover                                      |
| Fireworks                     | _scan-only_ |        — |      — |     — | C+ posture (75/100); clean takeover                                      |
| Groq                          | _scan-only_ |        — |      — |     — | **B** posture (78/100); clean takeover                                   |
| Glean                         | _scan-only_ |        — |      — |     — | **B** posture (80/100); clean takeover                                   |
| ElevenLabs                    | _scan-only_ |        — |      — |     — | D+ posture (60/100); clean takeover                                      |
| Runway                        | _scan-only_ |        — |      — |     — | D posture (55/100); clean takeover                                       |
| Midjourney                    | _scan-only_ |        — |      — |     — | C+ posture (73/100); clean takeover                                      |
| **Expanded cohort total**     |           — |    **1** | **13** | **2** | **16 findings across 25 providers · 21 of 25 fully clean (84%)**         |

_The fresh 12 (Databricks through Midjourney) were swept via the deployed `scan_domain` tool which includes a subdomain-takeover check. None surfaced new CRITICAL or MEDIUM dangling findings. CT-enumerated subdomain counts for the new 12 are listed in `03-provenance.pdf` rather than this table to keep it scannable._

**What the cohort tells a CSC partner:**

1. **The 3-vendor study generalizes — and the expansion strengthens it.** 21 of 25 providers (84%) are fully clean. Anthropic isn't lucky — tight engineering hygiene is the **median** for foundation-model labs and AI infrastructure providers. Cohere is the standout for clean-at-scale (1,085 subdomains, 0 findings).
2. **OpenAI remains the only CRITICAL-severity outlier in the broader 25-provider cohort.** No other provider — including the new 12 — has a takeover candidate with a user-claimable target namespace.
3. **x.ai remains the only multi-finding-cluster outlier.** The 9 findings collapse to 1 operational mistake; "9 findings" overstates the failure mode.
4. **CloudFront-distribution-deleted is the recurring pattern** (3 of 16 cohort findings: `blog.openai.com`, `cdn.huggingface.co`, `dev.beta.ngc.nvidia.com`). Continuous monitoring would surface every one of these the day the upstream distribution is deleted.
5. **The expansion did not change the conclusion.** Pushing the cohort from 13 to 25 added 0 new findings — meaningful in itself: it's evidence the original case study didn't cherry-pick, and that the 4 outliers are unusual rather than typical.

---

## § 6 — Brand impersonation: 32 mail-active lookalikes, 25 phishing-ready

Edit-distance, homoglyph, and IDN abuse-pattern enumeration. **Mail-presence is the phishing-readiness signal** — a domain that can send mail purporting to be the brand right now.

| Brand seed | Lookalikes enumerated | HIGH (mail-active) | MEDIUM (registered, no mail) |
| ---------- | --------------------: | -----------------: | ---------------------------: |
| OpenAI     |                    13 |              **7** |                            5 |
| Anthropic  |                    17 |              **8** |                            8 |
| x.ai       |                     6 |              **4** |                            2 |
| grok.com   |                    32 |             **13** |                           19 |
| **Total**  |                **68** |             **32** |                       **34** |

_HIGH + MEDIUM = 66 of 68 enumerated. The remaining 2 fell into a LOW/INFO bucket (registered apex with no usable web or mail surface) and are excluded from the actionable severity totals._

**Of the 28 representative HIGH-severity names verified live on 2026-05-23:**

- **4 fully unprotected** — no SPF + no DMARC — sender can forge mail-from with zero technical barrier:
  - OpenAI: `opena1.com` (digit-1)
  - Anthropic: `anthropic.co` _(brand-owned, GoDaddy — see § 7)_
  - Grok: `groj.com`, `grol.com`
- **21 with no DMARC enforcement** — SPF present but DMARC absent or `p=none` — receiver gets no policy signal, treats forged mail as deliverable.
- **3 with DMARC enforcement** (`p=quarantine` or `p=reject`) — not phishing-ready as listed. _Note: `c.ai` is Character.AI's primary apex — an established unrelated brand, not a typosquat — listed only because it surfaces in the enumeration; the other two are `s.ai` and `rok.com`._

**Net phishing-ready (of 28 verified): 25** (89%).

**The Grok surface is exceptionally rich** — a short common-word brand on a short TLD — and the lookalike volume across x.ai's brand surface materially exceeds Anthropic's. The 13 mail-active Grok lookalikes are all third-party-registered and therefore outside any of the three vendors' managed portfolios.

---

## § 7 — Off-primary-registrar brand sprawl

This is the direct answer to the partnership brief's headline question: _"are there company-owned domains registered with third-party registrars?"_

### All three brief-named registrars surfaced

| Registrar (named in brief) | Surfaced as                                                   |
| -------------------------- | ------------------------------------------------------------- |
| **GoDaddy.com, LLC**       | `openai.io`, `anthropic.co`, `xai.tech`, `grok.ai`, `grok.io` |
| **Network Solutions, LLC** | `grok.org`                                                    |
| **Namecheap, Inc.**        | `xai.org`                                                     |

The OpenAI / Anthropic GoDaddy hits are **brand-owned** (verified by HTTP redirect to the primary apex). The x.ai / Grok hits are **brand-coincidence** (none redirect to `x.ai`) — but that's its own finding: zero defensive registration on the obvious brand variants leaves the brand-coincidence surface entirely in third-party hands.

### Brand-owned domains on third-party registrars (the partnership-relevant finding)

Confirmed by HTTP redirect to the primary apex. Registrar resolved via RDAP/WHOIS (reproducible against the deployed `rdap_lookup` tool).

| Brand-owned domain | Registrar                                  | Notes                                                                                 |
| ------------------ | ------------------------------------------ | ------------------------------------------------------------------------------------- |
| `openai.sg`        | **Exabytes Network (Singapore) Pte Ltd**   | Off-portfolio. Registrant: `PIGEON TECHNOLOGIES PTE. LTD.` Redirects to `openai.com`. |
| `openai.io`        | **GoDaddy.com, LLC**                       | Off-portfolio. Redirects to `openai.com/sam-and-jony/`.                               |
| `anthropic.co`     | **GoDaddy.com, LLC**                       | Off-portfolio. Redirects to `anthropiclabs.com`. **And fully spoofable** — see § 6.   |
| `openai.de`        | (German-registry redacted by DENIC policy) | Brand-ownership confirmed by HTTP 302 → `openai.com`.                                 |
| `openai.group`     | MarkMonitor Inc.                           | On-portfolio (properly consolidated).                                                 |
| `openai.tools`     | MarkMonitor Inc.                           | On-portfolio (properly consolidated).                                                 |

Of the 6 confirmed brand-owned apexes across OpenAI + Anthropic, **3 are on third-party registrars** — exactly the partnership-relevant finding. 2 are properly consolidated on MarkMonitor; 1 has registrar withheld by registry policy. **x.ai's primary `x.ai` is on Dynadot** — already non-MarkMonitor by design — and no other x.ai-owned brand-coincidence apex was identified.

### The 4 fully-spoofable brand apexes (mail-active, no SPF, no DMARC)

- **OpenAI:** `openai.co.uk`, `openai.org`
- **Anthropic:** `anthropic.ca` (Tucows), `anthropic.co` (GoDaddy — brand-owned, redirects to `anthropiclabs.com`)

**`openai.org` is on MarkMonitor.** This is worth surfacing as a finding in its own right: it shows that **primary-registrar consolidation is not the same as email-auth hygiene.** A registrar-consolidation product (CSC, MarkMonitor) puts the domain on the right registrar; it doesn't ensure the domain has SPF and DMARC published. The two value chains are complementary, not overlapping.

Mail-from forgery from any of these four domains is unmitigated today.

### Email-auth posture across OpenAI/Anthropic TLD sets

| Vendor    | Total in TLD set | CRITICAL (fully spoofable) | HIGH (weak DMARC) | INFO (non-mail) | Unregistered |
| --------- | ---------------: | -------------------------: | ----------------: | --------------: | -----------: |
| OpenAI    |               19 |                      **2** |             **7** |               1 |        **1** |
| Anthropic |               19 |                      **2** |             **4** |               6 |        **3** |

**Anthropic's null-MX (RFC 7505) posture across 6 non-mail apexes is the recommended pattern** — `MX 0 .` (strict RFC 7505 form on `.io`, `.app`, `.com.au`, `.net`) or `MX 0 localhost.` (functionally equivalent, used on `.de`, `.nl`) paired with `SPF -all`. Across all three vendors, this is the strongest defensive posture and the cleanest message in any CSC customer conversation about non-mail brand domains.

_(Note: `openai.eu` declares null-MX but is parked at Sedo and is not OpenAI-owned. It is not a finding for OpenAI's posture — it is a brand-coincidence apex with a non-OpenAI registrant.)_

### Unregistered — defensive-registration opportunity

- **OpenAI:** `openai.za`.
- **Anthropic:** `anthropic.eu`, `anthropic.za`.
- `anthropic.dev` is **blocked from open registration** by Google Registry's Brand Safety Alliance (BSA) protection — effectively unavailable. Not a defensive-registration opportunity, but worth recording as "covered by registry-level protection."

Three brand-related apexes are **registered-but-DNS-dark** rather than unregistered and therefore not on the opportunity list: `openai.ai` (Zenaida.cate.ai, registrant `wangshaofei` in Shenzhen, registered 2017-12-16, status `inactive`), `openai.jp` (registered + mail-protected via `wats.gr.jp`), `anthropic.fr` (BLOOM'UP, no published DNS). Each surfaced by direct registry RDAP.

---

## § 8 — What CSC partners should take from this

CSC's lens is the **managed surface** — the customer's CSC-administered registrar portfolio, CSC-hosted DNS zones, and customer-supplied seed lists for brand and third-party-registration monitoring. BlackVeil's lens is the **publicly-observable surface** — every certificate ever issued (CT logs), every registry RDAP record, every public DNS resolver response, every passive-DNS observation. The two lenses overlap heavily on intent (subdomain hygiene, brand defense, email security) and diverge sharply on data source. The case study is structured to show what that divergence looks like in practice, vendor-by-vendor.

**For an OpenAI-like target** (off-MarkMonitor sprawl + active subdomain surface + significant posture gaps): BlackVeil's vantage point surfaces (a) `cdn.openai.com` — a CT-log + application-layer takeover candidate whose **DNS chain resolves cleanly** and therefore would not surface on a "zone state changed" alert; (b) `openai.sg` — an Exabytes-registered, PIGEON-TECHNOLOGIES-owned brand asset that **does not appear in CSC's managed registrar portfolio** because it isn't there; (c) `openai.org` — a fully-spoofable apex **on MarkMonitor** that primary-registrar consolidation didn't fix, because email-auth posture is a separate problem from registrar choice. Three findings, three different sensors, none surfacing from a portfolio-walk alone.

**For an Anthropic-like target** (tight registrar consolidation + gold-standard null-MX hygiene + B-grade posture): BlackVeil's value is the **defensible negative** — "no dangling across 129 CT-enumerated subdomains, no off-portfolio sprawl observed beyond `anthropic.co`, top of the 25-provider cohort by overall grade." The 0-surfaced result is reproducible across independent runs and is **the reproducibility itself** — a customer who needs a defensible answer to _"does this brand have shadow IT?"_ gets a sweep result they can show to their board, not just an "all monitored zones healthy" alert from their managed-DNS provider. A product that produces a defensible negative when the answer is genuinely clean is more valuable than one that surfaces noise on every target.

**For an x.ai-like target** (alternative primary registrar + minimal defensive sprawl): BlackVeil surfaces both (a) the lack-of-defensive-registration gap — third parties owning `xai.org`, `xai.tech`, `grok.ai`, `grok.io`, `grok.org` on GoDaddy / Network Solutions / Namecheap — visible because RDAP/WHOIS is queried per-apex without depending on a CSC-managed-portfolio seed; and (b) the operational dangling-CNAME drift on the active subdomain surface (9 model-serving endpoints orphaned by a single AWS deletion, including the `grok-4-code-0630` disclosure visible from public CT logs). Two different findings on two different sensors — and the `grok-4-code-0630` finding in particular is one that would only surface for a CT-log enumerator.

**The line between the products:** CSC manages and monitors the **customer's managed surface**; BlackVeil enumerates and grades the **public observability surface**. Same intent (subdomain hygiene, brand defense, email security), different sensors, complementary coverage. The two products land cleanly side-by-side in a customer's stack — CSC for what they administer, BlackVeil for what's observable to anyone with `curl` + `dig`.

---

**Reproducibility:** every finding above is independently verifiable via public DNS, RDAP, WHOIS, and Certificate Transparency. See `03-provenance.pdf` for the verification matrix and the `dig` / `curl` / `crt.sh` commands to re-derive each finding. Methodology and replay credentials available on request.
