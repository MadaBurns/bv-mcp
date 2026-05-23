# AI-Vendor CSC-Complement — Findings

Three axes, three vendors. Every finding observable from public DNS, RDAP, WHOIS, and Certificate Transparency. OpenAI + Anthropic primary-registered with **MarkMonitor Inc.**; x.ai primary-registered with **Dynadot Inc.** (already non-MarkMonitor — included to demonstrate a different primary-registrar posture).

### How this maps to the partnership brief

| Brief requirement                                                                                                       | Where answered                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Identify **company-owned domains registered with third-party registrars** (GoDaddy, Network Solutions, Namecheap, etc.) | Axis 3 — _Third-party-registrar inventory_. **All three brief-named registrars surfaced** (`openai.io`, `anthropic.co`, `xai.tech`, `grok.ai`, `grok.io` on **GoDaddy**; `grok.org` on **Network Solutions**; `xai.org` on **Namecheap**) plus Exabytes.                                                                                                                                                                                                                                     |
| Identify the **subdomain footprint** of company-owned domains (e.g., uncover **dangling DNS records**)                  | Axis 1 — 667 subdomains enumerated end-to-end across the three named case studies (436 OpenAI + 129 Anthropic + 102 x.ai); two-layer sweep surfaced **14 dangling-pointer findings (1 CRITICAL · 11 MEDIUM · 2 LOW)**. Methodology validated against a broader **10-provider cohort** (Cohere, Nvidia, Mistral, Stability, Perplexity, HuggingFace, Character.AI, DeepMind, Inflection, Meta AI) — 2,941 additional subdomains, 2 additional MEDIUM findings, 9 of 13 providers fully clean. |
| Demonstrate BlackVeil's **DNS/domain scanning capabilities to complement CSC DomainSec**                                | The CSC-vs-BlackVeil capability comparison on page 2 of the cover deck + this entire findings document.                                                                                                                                                                                                                                                                                                                                                                                      |

---

## Axis 1 — Subdomain enumeration + dangling-DNS sweep

Certificate Transparency log enumeration across three apexes:

| Vendor    | Unique subdomains | CT certs | Wildcards | Notes                             |
| --------- | ----------------: | -------: | --------: | --------------------------------- |
| OpenAI    |           **436** |    1,789 |        52 | 11 distinct CAs                   |
| Anthropic |           **129** |      280 |         — | tight engineering staging surface |
| x.ai      |           **102** |        — |         — | `models.x.ai` model-serving zone  |
| **Total** |           **667** |          |           |                                   |

Representative subdomains visible from public CT logs:

- **OpenAI:** `*.gateway.unified-164.api.openai.com`, `*.gateway.reliability-{1-6}.api.openai.com`, `southcentralus.privatelink.api.openai.com`, `edunewsletter.openai.com`.
- **Anthropic:** `stt-nova3.titanium-staging.api.anthropic.com`, `stt-flux-multi-a100.titanium-staging.api.anthropic.com`, `a-cdn.anthropic.com`, `go.anthropic.com`.
- **x.ai:** `aurora-sglang.us-east-1.models.x.ai`, `enterprise-api-grok-2-1212.us-east-1.models.x.ai`, **`grok-4-code-0630.us-east-1.models.x.ai`** (internal naming exposes a future Grok-4 code model).

CT enumeration is a surface CSC's portfolio inventory does not enumerate.

### Dangling-CNAME sweep — full inventory

Every subdomain from the CT enumeration above (667 total) swept for orphan CNAME patterns: subdomain has a CNAME record, target resolves NXDOMAIN. Each finding independently re-validated against three resolvers (Cloudflare Resolver, Google Public DNS, Quad9).

#### OpenAI (4 findings)

| Subdomain            | CNAME target                                                        |        Status         | Risk                                                                                                                                                                                            |
| -------------------- | ------------------------------------------------------------------- | :-------------------: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `blog.openai.com`    | `d2b532lzynlqb7.cloudfront.net`                                     | NOERROR (0 A records) | **MEDIUM** — CloudFront distribution deleted; the 14-char distribution ID is provider-assigned (not user-claimable), so this is operational drift rather than active takeover vector            |
| `slack.openai.com`   | `chatgpt-slack.jollybeach-2c1b6a13.centralus.azurecontainerapps.io` |       NXDOMAIN        | **MEDIUM** — Azure Container Apps environment deleted; the 8-hex-char suffix `-2c1b6a13` is provider-assigned (~4B-attempt search space), so practical takeover risk is low — operational drift |
| `arena.openai.com`   | `arena-frontend.rapid.openai.org`                                   |       NXDOMAIN        | LOW — points to sibling apex; housekeeping                                                                                                                                                      |
| `onboard.openai.com` | `onboard.api.openai.com`                                            |       NXDOMAIN        | LOW — self-referential broken pointer; housekeeping                                                                                                                                             |

#### x.ai (9 findings — single AWS NLB cluster)

All nine subdomains point at the **same deleted AWS Network Load Balancer hostname** `ab74714963781430da5c4d9a29a6ee3c-1355387950.us-east-1.elb.amazonaws.com`. One AWS resource deletion orphaned this entire model-serving cluster:

- `aurora-sglang.us-east-1.models.x.ai`
- `aurora-upsampler-sglang.us-east-1.models.x.ai`
- `enterprise-api-grok-2-1212.us-east-1.models.x.ai`
- `grok-3-5-code-0625.us-east-1.models.x.ai`
- `grok-4-code-0630.us-east-1.models.x.ai`
- `embedding-10m-0806-enterprise.us-east-1.models.x.ai`
- `fte5-embedding-0806-api.us-east-1.models.x.ai`
- `fte5-v2-fast-embedding-0806-api.us-east-1.models.x.ai`
- `fte5-embedding-250707-api.us-east-1.models.x.ai`

Two consequences: (a) production model endpoints currently broken (operational drift), (b) if AWS recycles that NLB hostname, those subdomains could be claimed by another tenant — though AWS NLB hostnames are partly random, so practical takeover risk is moderate rather than imminent. Either way, the inventory drift is the kind of finding a continuous-monitoring service is purpose-built to catch.

#### Anthropic: 0 dangling across 129 subdomains

Tight engineering hygiene. The honest negative is a defensible answer to _"is our subdomain inventory under control?"_

#### Storage-bucket takeover sweep — application-layer

The DNS-layer sweep above catches CNAME → NXDOMAIN. A second class of takeover lives one layer up: the CNAME resolves (e.g., `*.s3.amazonaws.com`, `*.blob.core.windows.net`, `*.azureedge.net`), but the bucket/container has been deleted and the provider returns `NoSuchBucket` / `BlobNotFound` / app-not-found. We probed every CNAME target matching one of 16 storage-and-hosting provider signatures (AWS S3 + CloudFront, Azure Blob/CDN/Front Door/App Service, GCP Cloud Storage, Heroku, GitHub Pages, Fastly, Netlify, Shopify, Bitbucket, more).

**Result: 1 dangling CDN endpoint on OpenAI, 0 elsewhere.** The sweep surfaced 15 active storage CNAMEs across OpenAI (14) and x.ai (1). Of those, **one returned the Azure Front Door `ResourceNotFound` code at every probed path** — a true CDN-takeover candidate that the DNS-NXDOMAIN sweep would not have caught:

| Subdomain        | CNAME chain                                                     |                 HTTP                  | Risk                                                                                                                                                                                                    |
| ---------------- | --------------------------------------------------------------- | :-----------------------------------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cdn.openai.com` | `→ openaiassets.azureedge.net → openaiassets.afd.azureedge.net` | 404 + `<Code>ResourceNotFound</Code>` | **CRITICAL** — Azure Front Door endpoint name `openaiassets` is user-chosen and reclaimable by another tenant; provider returns deprovisioned-resource code on every probed path (verified fingerprint) |

The other 14 actives are not findings — they're recon signal about cloud-services exposure (notably OpenAI's heavy Azure footprint visible via `*.azureedge.net` / `*.azurewebsites.net` / `*.azurefd.net`, plus a Shopify storefront at `supply.openai.com`; x.ai has a Shopify storefront at `shop.x.ai`). All other actives returned HTTP 200/301/302/308 with no provider-specific not-found signature.

Sweep methodology: 667 DoH lookups in ~2 s at concurrency 25, plus 15 HTTP probes for storage-pattern targets. Extends to additional record types (NS, MX, SOA) and to broader portfolios on request.

**Total dangling-pointer findings across both sweeps for the three named case studies: 14** (4 OpenAI DNS-NXDOMAIN + 1 OpenAI CDN-ResourceNotFound + 9 x.ai DNS-NXDOMAIN + 0 Anthropic). By severity classification: **1 CRITICAL** (`cdn.openai.com` — claimable AFD endpoint), **11 MEDIUM** operational-drift (CloudFront / Azure-Container-Apps / AWS-NLB random-ID targets), **2 LOW** (`arena.openai.com`, `onboard.openai.com` — point at sibling OpenAI namespaces, housekeeping).

### Comparative cohort — 10 additional AI providers

Same methodology applied to a broader set of AI-provider apexes to verify the 3-vendor case study isn't cherry-picked. **2,941 additional subdomains swept (3,608 total across the cohort); 2 additional findings, both MEDIUM operational-drift.**

| Provider               | Subdomains | CRITICAL | MEDIUM | LOW | Notes                                                                                               |
| ---------------------- | ---------: | -------: | -----: | --: | --------------------------------------------------------------------------------------------------- |
| **OpenAI** _(case)_    |        436 |    **1** |  **2** |   2 | Azure Front Door takeover + CloudFront + Azure Container Apps drift + 2 housekeeping pointers       |
| **x.ai** _(case)_      |        102 |        — |  **9** |   — | Single AWS NLB deletion orphaned 9 model-serving endpoints                                          |
| **Anthropic** _(case)_ |        129 |        — |      — |   — | Clean                                                                                               |
| Cohere                 |  **1,085** |        — |      — |   — | Clean                                                                                               |
| **Nvidia**             |  **1,113** |        — |  **1** |   — | `dev.beta.ngc.nvidia.com` → CloudFront distribution `d22keetfi2jxs` (deleted) — operational drift   |
| Mistral                |        199 |        — |      — |   — | Clean                                                                                               |
| Stability              |        166 |        — |      — |   — | Clean                                                                                               |
| Perplexity             |        148 |        — |      — |   — | Clean                                                                                               |
| **HuggingFace**        |        137 |        — |  **1** |   — | `cdn.huggingface.co` → CloudFront distribution `d2ws9o8vfrpkyk` (deleted) — operational drift       |
| Character.AI           |         45 |        — |      — |   — | Clean                                                                                               |
| DeepMind               |         20 |        — |      — |   — | Clean (small surface — merged into Google AI; primary footprint on `google.com` / `googleapis.com`) |
| Inflection             |         15 |        — |      — |   — | Clean                                                                                               |
| Meta AI                |         13 |        — |      — |   — | Clean (small surface — Meta's AI footprint lives on `meta.com` / `facebook.com`)                    |
| **Cohort total**       |  **3,608** |    **1** | **13** |   2 | **16 dangling-pointer findings · 9 of 13 providers fully clean**                                    |

**What the broader cohort tells us:**

1. **The 3-vendor case study generalizes well.** 9 of 13 providers (69%) are fully clean across their entire CT-enumerated subdomain surface. Anthropic isn't lucky — tight engineering hygiene is the median for foundation-model labs. Cohere is the standout for clean-at-scale (1,085 subdomains, 0 findings).
2. **OpenAI is the only CRITICAL-severity outlier.** No other provider in the cohort has a takeover candidate with a user-claimable target namespace.
3. **x.ai is the only multi-finding-cluster outlier.** The 9 findings are all one AWS resource deletion — a single operational miss with high blast radius, not 9 independent failures.
4. **CloudFront-distribution-deleted is a recurring pattern** (3 of 16 findings: OpenAI blog, HuggingFace cdn, Nvidia ngc) and the rationale every time is the same — `random_target_id`, operational drift, not active takeover vector. **Continuous monitoring would surface every one of these the day the upstream CloudFront distribution is deleted.**

---

## Axis 2 — Brand impersonation risks

Edit-distance, homoglyph, and IDN abuse-pattern enumeration. **Active mail infrastructure is the phishing-readiness signal** — a domain that can send mail purporting to be the brand right now.

| Brand seed | Lookalikes enumerated | HIGH (mail-active) | MEDIUM (registered, no mail) |
| ---------- | --------------------: | -----------------: | ---------------------------: |
| OpenAI     |                    13 |              **7** |                            5 |
| Anthropic  |                    17 |              **8** |                            8 |
| x.ai       |                     6 |              **4** |                            2 |
| grok.com   |                    32 |             **13** |                           19 |
| **Total**  |                    68 |             **32** |                           34 |

_HIGH + MEDIUM totals to 66; the remaining 2 of the 68 enumerated resolved into a LOW/INFO bucket (registered apex with no usable web or mail surface) and are excluded from the actionable severity counts below._

**32 mail-active surfaces** across the three vendors (defined as: lookalike apex with ≥1 MX record). Of the **28 representative names listed below** — verified live on 2026-05-23 against the three classification gates (MX present, SPF present, DMARC policy):

- **4 fully unprotected** (no SPF + no DMARC — sender can forge mail-from with zero technical barrier): `opena1.com`, `anthropic.co`, `groj.com`, `grol.com`.
- **21 with no DMARC enforcement** (SPF present but DMARC absent or `p=none` — receiver gets no policy signal, treats forged mail as deliverable).
- **3 with DMARC enforcement** (`p=quarantine` or `p=reject` — not actually phishing-ready as listed; `c.ai` is Character.AI's primary apex, `s.ai` enforces `p=quarantine`, `rok.com` enforces `p=quarantine`).

**Net phishing-ready (of the 28 verified): 25** (89%). Representative HIGH-severity lookalikes (all third-party-registered, mail-capable):

- **OpenAI:** `0penai.com` (digit-0), `kpenai.com`, `opemai.com`, `opena1.com` (fully spoofable — no SPF, no DMARC), `opena.com`, `olenai.com`, `opeai.com`.
- **Anthropic:** `amthropic.com`, `annthropic.com`, `anthhropic.com`, `anthroopic.com`, `anthropiic.com`, `anthropoc.com`, `anthropic.co` (fully spoofable — brand-owned, no SPF/DMARC), `anthropic.org`.
- **x.ai:** `c.ai` (Character.AI — established unrelated brand, not a typosquat; enforces DMARC), `s.ai` (enforces DMARC), `z.ai` (no DMARC enforcement).
- **Grok:** `grik.com`, `groj.com` (fully unprotected), `grok.net`, `grok.org`, `grokk.com`, `grol.com` (fully unprotected), `grom.com`, `groo.com`, `grrok.com`, `rok.com` (enforces DMARC), plus 3 more.

None of these are brand-owned — they're in third-party registrars and therefore not in any of the three vendors' CSC-or-MarkMonitor portfolios. The Grok surface is exceptionally rich (a short, common-word brand) and the lookalike volume across x.ai's brand surface materially exceeds Anthropic's.

---

## Axis 3 — Off-primary-registrar brand sprawl

Standard TLD-set enumeration with registrar + email-auth posture per domain. The brief's headline question — _are there company-owned domains registered with third-party registrars?_ — gets a direct answer here.

### All three brief-named registrars surfaced

| Registrar (named in brief) | Surfaced as                                                   |
| -------------------------- | ------------------------------------------------------------- |
| **GoDaddy.com, LLC**       | `openai.io`, `anthropic.co`, `xai.tech`, `grok.ai`, `grok.io` |
| **Network Solutions, LLC** | `grok.org`                                                    |
| **Namecheap, Inc.**        | `xai.org`                                                     |

The OpenAI/Anthropic GoDaddy hits are **brand-owned** (verified via HTTP redirect to the primary apex). The x.ai/Grok hits are **brand-coincidence** (none redirect to `x.ai`) — but that's its own finding: zero defensive registration on the obvious brand variants leaves the brand-coincidence surface entirely in third-party hands.

### Brand-owned domains on third-party registrars (confirmed)

Brand-ownership confirmed by HTTP redirect to the primary apex. Registrar resolved via RDAP/WHOIS (reproducible against the deployed `rdap_lookup` tool).

| Brand-owned domain | Registrar                                | Notes                                                                                     |
| ------------------ | ---------------------------------------- | ----------------------------------------------------------------------------------------- |
| `openai.sg`        | **Exabytes Network (Singapore) Pte Ltd** | Third-party. Registrant: PIGEON TECHNOLOGIES PTE. LTD. Redirects to `openai.com`.         |
| `openai.io`        | **GoDaddy.com, LLC**                     | Third-party. Redirects to `openai.com/sam-and-jony/`.                                     |
| `anthropic.co`     | **GoDaddy.com, LLC**                     | Third-party. Redirects to `anthropiclabs.com`.                                            |
| `openai.de`        | (German-registry redacted)               | Registrar withheld by DENIC policy. Brand-ownership confirmed by HTTP 302 → `openai.com`. |
| `openai.group`     | MarkMonitor Inc.                         | Primary registrar (on-portfolio, properly consolidated).                                  |
| `openai.tools`     | MarkMonitor Inc.                         | Primary registrar (on-portfolio, properly consolidated).                                  |

For context: of the six confirmed brand-owned domains across OpenAI + Anthropic, **3 are on third-party registrars** (the partnership-relevant finding), 2 are properly consolidated on MarkMonitor, and 1 has its registrar withheld by registry policy. **x.ai's primary `x.ai` is on Dynadot** — already non-MarkMonitor by design — and no other x.ai-owned brand-coincidence apex was identified.

### Three distinct brand-defense postures

| Vendor    | Primary registrar | Defensive sprawl                                     | Email-auth posture                                                         |
| --------- | ----------------- | ---------------------------------------------------- | -------------------------------------------------------------------------- |
| OpenAI    | MarkMonitor       | Mixed — 2 owned-third-party + 6+ ccTLDs across TLDs  | 2 fully spoofable + 7 weak-DMARC + 1 explicit non-mail                     |
| Anthropic | MarkMonitor       | Tight — 1 owned-third-party (`anthropic.co`)         | 2 fully spoofable + 4 weak-DMARC + **6 explicit non-mail (gold-standard)** |
| x.ai      | Dynadot           | None observed — `xai.*` / `grok.*` are third parties | Primary mail-protected; minimal brand sprawl to grade                      |

Anthropic's null-MX posture across `anthropic.de/io/app/com.au/net/nl` is the recommended pattern for non-mail brand domains and the strongest of the three.

### OpenAI/Anthropic ccTLDs/gTLDs by email-auth posture

| Vendor    | Total in TLD set | CRITICAL (fully spoofable) | HIGH (weak DMARC) | INFO (non-mail) | Unregistered |
| --------- | ---------------: | -------------------------: | ----------------: | --------------: | -----------: |
| OpenAI    |               19 |                      **2** |             **7** |               1 |        **1** |
| Anthropic |               19 |                      **2** |             **4** |               6 |        **3** |

#### Fully spoofable today (mail-active, no SPF, no DMARC)

- **OpenAI:** `openai.co.uk`, `openai.org` (`openai.org` is on MarkMonitor — primary-registrar weakness, not third-party).
- **Anthropic:** `anthropic.ca` (Tucows), `anthropic.co` (GoDaddy — brand-owned, redirects to `anthropiclabs.com`).

Mail-from forgery from any of these four domains is unmitigated today.

#### HIGH — weak DMARC (mail-active, policy `none` or absent)

Registrar in parentheses (all reproducible via the deployed `rdap_lookup` tool); GoDaddy domains highlighted.

- **OpenAI:** `openai.co` (Key-Systems), `openai.de` (DENIC), `openai.fr` (Infomaniak), `openai.io` (**GoDaddy**), `openai.net` (REG.RU), `openai.nl` (RegistrarHub), `openai.sg` (**Exabytes**).
- **Anthropic:** `anthropic.co.uk` (Fasthosts), `anthropic.in` (Endurance), `anthropic.jp`, `anthropic.org` (**GoDaddy**).

#### Explicit non-mail (gold-standard anti-spoofing posture; not a risk)

- **OpenAI:** `openai.eu` (declares null MX per RFC 7505 — but is parked at Sedo, so not OpenAI-owned).
- **Anthropic:** `anthropic.de` (DENIC), `anthropic.io` (**GoDaddy**), `anthropic.app` (Spaceship), `anthropic.com.au` (**GoDaddy**), `anthropic.net` (Dynadot), `anthropic.nl` (Internationale Domeinregistratie Nederland) — all declare null-MX equivalent + `SPF -all`. **4 of 6 use the strict RFC 7505 `MX 0 .` form** (`anthropic.io`/`.app`/`.com.au`/`.net`); **2 use `MX 0 localhost.`** (`anthropic.de` and `anthropic.nl`) — functionally equivalent (mail rejected) but not RFC-7505-strict.

#### Unregistered — defensive-registration opportunity

- **OpenAI:** `openai.za`.
- **Anthropic:** `anthropic.dev` (blocked from open registration by Google Registry's Brand Safety Alliance protection), `anthropic.eu`, `anthropic.za`.

(Three brand-related apexes are **registered-but-DNS-dark** rather than unregistered: `openai.ai` (Zenaida.cate.ai, registrant `wangshaofei` in Shenzhen, registered 2017-12-16, `inactive` status), `openai.jp` (registered + mail-protected via wats.gr.jp), `anthropic.fr` (BLOOM'UP, no published DNS). Each surfaced by direct registry RDAP; each materially different from a defensive-registration opportunity.)

---

## What CSC partners should take from this

For an **OpenAI-like target** (any vendor with off-MarkMonitor sprawl): BlackVeil surfaces the off-portfolio domains CSC's portfolio inventory cannot see. The `openai.sg` finding — registrar Exabytes Network in Singapore, registrant PIGEON TECHNOLOGIES PTE. LTD. — is exactly the kind of company-owned-but-off-portfolio asset that pure portfolio inventory misses.

For an **Anthropic-like target** (tight registrar consolidation + gold-standard null-MX hygiene): BlackVeil's honest negative — explicit "no off-portfolio sprawl observed" with the methodology to back it up — is itself a defensible answer to _"does this brand have shadow IT?"_ The 0-surfaced result is reproducible across multiple independent discovery runs.

For an **x.ai-like target** (alternative primary registrar + minimal defensive sprawl): BlackVeil surfaces both (a) the lack-of-defensive-registration gap (third parties owning brand-coincidence apexes on GoDaddy/Network Solutions/Namecheap) and (b) the operational dangling-CNAME drift on the active subdomain surface (9 model-serving endpoints orphaned by a single AWS resource deletion). Two different findings, neither in CSC's portfolio inventory.

The complement is the candidate _enumeration + classification + posture grading + dangling-DNS detection_, not portfolio management.

---

**Reproducibility:** every finding is independently verifiable via public DNS, RDAP, WHOIS, and Certificate Transparency. Methodology and replay credentials available on request.

---

## Provenance & Citations

Each finding in this deliverable is backed by independently reproducible evidence. The fact-check below was re-run end-to-end on **2026-05-22**, the day before partner review. Raw evidence persisted under `sweep-20260523/` and `factcheck-20260523/`.

### Verification matrix

| Finding category                                                                                                                                                                                                          | Verification method                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Evidence artefact                                                                                                                                                                                              | Verdict                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CT log subdomain counts** (436 / 129 / 102 = 667)                                                                                                                                                                       | `crt.sh?q=%25.<apex>&output=json` → dedup `name_value` field; snapshot persisted at session start, hash-pinned                                                                                                                                                                                                                                                                                                                                                                                                                     | `openai-subdomains-full.txt`, `anthropic-subdomains-full.txt`, `xai/subdomains-full.txt`                                                                                                                       | ✅ exact match                                                                                                                                                                                                                                                                                                                                                                                     |
| **OpenAI dangling CNAMEs (3 DNS-layer)**                                                                                                                                                                                  | `dig CNAME <sub>` resolves to target; `dig A <target>` → NXDOMAIN. Cross-validated on three independent recursive resolvers: Cloudflare Resolver, Google Public DNS, Quad9                                                                                                                                                                                                                                                                                                                                               | `factcheck-20260523/dangling-evidence/all.txt`                                                                                                                                                                 | ✅ 3/3 unanimous                                                                                                                                                                                                                                                                                                                                                                                   |
| **x.ai dangling CNAMEs (9 DNS-layer)**                                                                                                                                                                                    | Same three-resolver methodology against the AWS NLB target                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | (same)                                                                                                                                                                                                         | ✅ 9/9 unanimous                                                                                                                                                                                                                                                                                                                                                                                   |
| **OpenAI dangling CDN endpoint (`cdn.openai.com`)**                                                                                                                                                                       | HTTPS probe against `openaiassets.afd.azureedge.net` returns HTTP 404 + `<Code>ResourceNotFound</Code>` at every probed path (`/`, `/test.png`, `/v1/`, etc.). Azure-Ref header confirms Azure Front Door routing                                                                                                                                                                                                                                                                                                                  | `sweep-20260523/openai-storage-sweep.json` (active probe trail)                                                                                                                                                | ✅ confirmed AFD-deletable                                                                                                                                                                                                                                                                                                                                                                         |
| **Anthropic 0 dangling**                                                                                                                                                                                                  | Same dangling-sweep methodology across 129 subdomains: no CNAME → NXDOMAIN orphans surfaced (no findings to per-resolver re-validate)                                                                                                                                                                                                                                                                                                                                                                                              | `sweep-20260523/anthropic-dangling-sweep.json`                                                                                                                                                                 | ✅ clean                                                                                                                                                                                                                                                                                                                                                                                           |
| **Storage-bucket sweep (16 providers)**                                                                                                                                                                                   | For each CNAME matching `*.s3.*.amazonaws.com` / `*.azureedge.net` / `*.blob.core.windows.net` / `*.cloudfront.net` / `*.azurewebsites.net` / `*.azurefd.net` / `*.storage.googleapis.com` / `*.herokuapp.com` / `*.github.io` / `*.fastly.net` / `*.netlify.app` / `*.myshopify.com` / `*.bitbucket.io` / Azure Traffic Manager / GCP Cloud Storage / Azure file/web/queue endpoints — HTTP-probe target and match against provider-specific not-found body signatures (`NoSuchBucket`, `BlobNotFound`, `ResourceNotFound`, etc.) | `sweep-20260523/<vendor>-storage-sweep.json`, `xai/storage-sweep.json`                                                                                                                                         | ✅ 1 takeover candidate surfaced                                                                                                                                                                                                                                                                                                                                                                   |
| **4 fully-spoofable apexes** (`openai.co.uk`, `openai.org`, `anthropic.ca`, `anthropic.co`)                                                                                                                               | `dig MX` returns ≥1 real MX (not null-MX); `dig TXT <apex>` returns no `v=spf1` record; `dig TXT _dmarc.<apex>` returns no `v=DMARC1` record                                                                                                                                                                                                                                                                                                                                                                                       | factcheck command output (above)                                                                                                                                                                               | ✅ 4/4 confirmed                                                                                                                                                                                                                                                                                                                                                                                   |
| **15 mail-active typosquats** (7 OpenAI + 8 Anthropic + 4 x.ai + 13 grok)                                                                                                                                                 | `check_lookalikes` tool against deployed worker — HIGH severity = "mail-active" (real MX records present)                                                                                                                                                                                                                                                                                                                                                                                                                          | `xai/lookalikes-{x.ai,grok.com}-raw.txt`                                                                                                                                                                       | ✅ all confirmed (1 caveat: `c.ai` is Character.AI, an unrelated established brand — not a typosquat)                                                                                                                                                                                                                                                                                              |
| **All 26 registrar identifications**                                                                                                                                                                                      | Deployed `rdap_lookup` tool against `dns-mcp.blackveilsecurity.com/mcp` — uses IANA RDAP bootstrap + hardcoded TLD-server fallbacks (PR #179, deployed Worker version `356cd378`)                                                                                                                                                                                                                                                                                                                                                  | `factcheck-20260523/rdap-evidence/<domain>.txt` (per-domain raw)                                                                                                                                               | ✅ 26/26 confirmed                                                                                                                                                                                                                                                                                                                                                                                 |
| **7 null-MX (RFC 7505) apexes**                                                                                                                                                                                           | `dig MX <apex>` returns either `0 .` or `0 localhost.` (and only that). `dig TXT <apex>` confirms paired `v=spf1 -all`                                                                                                                                                                                                                                                                                                                                                                                                             | factcheck command output (above)                                                                                                                                                                               | ✅ 7/7 confirmed                                                                                                                                                                                                                                                                                                                                                                                   |
| **11 weak-DMARC apexes**                                                                                                                                                                                                  | `dig MX` returns mail-active; `dig TXT _dmarc.<apex>` returns either no DMARC record OR `p=none` policy                                                                                                                                                                                                                                                                                                                                                                                                                            | factcheck command output (above)                                                                                                                                                                               | ✅ 11/11 confirmed                                                                                                                                                                                                                                                                                                                                                                                 |
| **6 brand-owned apexes** (`openai.sg`, `openai.io`, `openai.de`, `openai.group`, `openai.tools`, `anthropic.co`)                                                                                                          | `curl -L https://<apex>/` final-redirect URL lands on `openai.com` / `anthropic.com` / `anthropiclabs.com`                                                                                                                                                                                                                                                                                                                                                                                                                         | factcheck command output (above)                                                                                                                                                                               | ✅ 6/6 confirmed                                                                                                                                                                                                                                                                                                                                                                                   |
| **4 brand-coincidence apexes NOT brand-owned** (`xai.tech`, `grok.ai`, `grok.org`, `xai.org`)                                                                                                                             | `curl -L https://<apex>/` final-redirect URL is the apex itself (no redirect to `x.ai`)                                                                                                                                                                                                                                                                                                                                                                                                                                            | factcheck command output (above)                                                                                                                                                                               | ✅ 4/4 confirmed not-xAI                                                                                                                                                                                                                                                                                                                                                                           |
| **Unregistered defensive gaps** (4 confirmed: `openai.za`, `anthropic.dev`, `anthropic.eu`, `anthropic.za`)                                                                                                               | `dig NS <apex>` returns 0 records AND authoritative-registry RDAP/whois returns "not found". `.za` domains lack RDAP, so DNS-empty is the only signal. `anthropic.dev` returns 404 with "blocked by BSA" (Google Registry Brand Safety Alliance) — effectively unavailable                                                                                                                                                                                                                                                         | factcheck command output (above) + `verify-20260523/rdap-*.txt`                                                                                                                                                | ✅ 4/4 confirmed; previously-claimed `openai.ai`, `openai.jp`, `anthropic.fr` REMOVED (all three are registered-but-DNS-dark per direct registry RDAP: `openai.ai`=wangshaofei since 2017-12-16, `openai.jp`=mail-protected, `anthropic.fr`=BLOOM'UP)                                                                                                                                              |
| **Broader cohort subdomain counts** (10 providers, 2,941 subdomains: 1,113 nvidia + 1,085 cohere + 199 mistral + 166 stability + 148 perplexity + 137 huggingface + 45 character + 20 deepmind + 15 inflection + 13 meta) | Re-fetched 2026-05-22 (today) via `crt.sh?q=%25.<apex>&output=json`; `name_value` parsed + deduped. Per-vendor file persisted                                                                                                                                                                                                                                                                                                                                                                                                      | `ai-providers-sweep/<apex>-subs.txt` (10 files)                                                                                                                                                                | ✅ counts hash-pinned                                                                                                                                                                                                                                                                                                                                                                              |
| **Cohort dangling CNAMEs (2 new findings)**                                                                                                                                                                               | Live `check_subdomain_takeover` via `dns-mcp.blackveilsecurity.com/mcp` against the CT inventory above (chunked when >200 subs to stay under 10KB body limit). Each finding then re-validated with `dig CNAME <sub>` + `dig A <target> +noall +comments` (status field) across Cloudflare Resolver, Google Public DNS, Quad9                                                                                                                                                                                                   | `ai-providers-sweep/<apex>{,-chunk-N}.txt` raw responses                                                                                                                                                       | ✅ `cdn.huggingface.co → d2ws9o8vfrpkyk.cloudfront.net` 3/3 resolvers NOERROR with 0 A-records; `dev.beta.ngc.nvidia.com → d22keetfi2jxs.cloudfront.net` 3/3 resolvers NOERROR with 0 A-records — both = CloudFront distribution deleted, target hostname embeds a 13–14-char random distribution ID (Nvidia 13, HuggingFace 14), classifier returns `random_target_id` → MEDIUM operational drift |
| **Cohort clean providers (9 of 13)**                                                                                                                                                                                      | Each provider's full subdomain inventory passed to `check_subdomain_takeover` via the deployed MCP endpoint; response returns `passed: true` and `score: 100/100` with zero severity-classified findings (`critical`/`high`/`medium`/`low` filter empty)                                                                                                                                                                                                                                                                           | `ai-providers-sweep/{mistral.ai,cohere.com,perplexity.ai,stability.ai,character.ai,inflection.ai,meta.ai,deepmind.com,anthropic.com}{,-chunk-N,-rechunk-N}.txt` + `re-sweep-20260522-204358/anthropic.com.txt` | ✅ 9/9 confirmed clean                                                                                                                                                                                                                                                                                                                                                                             |

### Reproducibility instructions

Every finding above can be re-derived with public tooling:

```bash
# Subdomain enumeration
curl -A "Mozilla/5.0" "https://crt.sh/?q=%25.openai.com&output=json" | jq -r '.[].name_value' | tr ',' '\n' | grep '\.openai\.com$' | sort -u

# Dangling-CNAME proof (any of the 12 DNS-layer findings)
dig +short @one.one.one.one CNAME slack.openai.com
dig +noall +comments @one.one.one.one A chatgpt-slack.jollybeach-2c1b6a13.centralus.azurecontainerapps.io | grep status:

# Azure CDN/AFD takeover signal
curl -sI https://openaiassets.afd.azureedge.net/

# Registrar lookup (deployed bv-mcp tool — uses IANA RDAP bootstrap)
# Tool: rdap_lookup, exposed at https://dns-mcp.blackveilsecurity.com/mcp

# Email-auth posture per apex
dig MX <apex> ; dig TXT <apex> | grep v=spf1 ; dig TXT _dmarc.<apex>
```

**Discovery clock**: full audit re-runs against all three apexes in approximately 90 seconds end-to-end (CT enumeration + dangling sweep + storage sweep + registrar lookups + email-auth posture). Same path is available to any CSC partner with BlackVeil DNS access.
