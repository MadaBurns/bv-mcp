# BlackVeil DNS — Complementary to CSC DomainSec

## AI-Vendor Case Study: OpenAI, Anthropic & x.ai

**The headline numbers, observable today from public DNS, RDAP, WHOIS, and Certificate Transparency:**

<div class="kpi-grid">
<div class="kpi"><span class="num">16</span><span class="lbl">dangling-pointer findings</span><span class="sub">across 13 AI providers · 3,608 subdomains · 1 CRITICAL · 13 MEDIUM · 2 LOW</span></div>
<div class="kpi"><span class="num">4</span><span class="lbl">fully-spoofable brand apexes</span><span class="sub">mail-active, no SPF, no DMARC</span></div>
<div class="kpi"><span class="num">3 of 3</span><span class="lbl">brief-named registrars surfaced</span><span class="sub">GoDaddy · Network Solutions · Namecheap</span></div>
<div class="kpi"><span class="num">3</span><span class="lbl">distinct brand-defense postures</span><span class="sub">MarkMonitor + sprawl · MarkMonitor + tight · Dynadot + minimal</span></div>
</div>

Each one is a defensible CSC-complement signal — a surface that CSC's portfolio-centric view does not enumerate today because it lives _outside_ a customer's managed registrar portfolio.

---

## Why these targets

Three of the highest-profile AI vendors in the enterprise security conversation, with deliberately different primary-registrar postures:

- **OpenAI** (`openai.com`) — primary registrar **MarkMonitor Inc.** (the dominant non-CSC enterprise registrar).
- **Anthropic** (`anthropic.com`) — primary registrar **MarkMonitor Inc.** (same).
- **x.ai** (`x.ai`) — primary registrar **Dynadot Inc.** Already non-MarkMonitor; primary apex is mail-protected (SPF + DMARC).

Same vertical, same general business posture, three measurably different observable risk profiles on the surface CSC's portfolio inventory does not cover. The full audit ran against all three targets entirely from public DNS, WHOIS, RDAP, and certificate-transparency surfaces. Any CSC customer with the appropriate BlackVeil integration would have the same observability against their own portfolio.

## How this complements CSC DomainSec

|                         | CSC DomainSec covers                                                                 | BlackVeil DNS adds                                                                             |
| ----------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| **Brand portfolio**     | Defensive registration inventory + registrar consolidation for the _managed_ surface | Off-portfolio enumeration: brand domains registered _outside_ the customer's primary registrar |
| **Monitoring**          | Brand-monitor + typosquat watch on the _managed_ portfolio                           | Active typosquat + homoglyph enumeration with mail-presence scoring (phishing-readiness)       |
| **DNS oversight**       | Registrar lock + DNS-change alerting                                                 | Per-apex posture grading: DMARC, DKIM, SPF, DNSSEC, MTA-STS, SSL + hardening categories        |
| **Subdomain inventory** | Not provided                                                                         | Certificate-transparency enumeration with dangling-DNS detection                               |

BlackVeil DNS is positioned as the **technical surface** CSC's portfolio-centric view does not cover — _not_ as a portfolio-management replacement.

## The three primary axes of this deliverable

1. **Subdomain enumeration + dangling-DNS sweep** — Certificate Transparency log enumeration: **436 OpenAI + 129 Anthropic + 102 x.ai = 667 unique subdomains** swept end-to-end across DNS (NXDOMAIN) + application (storage-provider not-found) layers. **14 dangling-pointer findings** (5 OpenAI + 9 x.ai + 0 Anthropic) — severity-classified by target-namespace claimability: 1 CRITICAL (Azure Front Door endpoint with user-claimable name), 11 MEDIUM operational-drift (CloudFront distribution IDs, Azure Container Apps env suffixes, AWS NLB IDs — all provider-assigned random IDs not practically reclaimable), 2 LOW housekeeping pointers. Internal model naming visible from public CT logs. **Methodology validated against a broader 10-provider cohort (Cohere, Nvidia, Mistral, Stability, Perplexity, HuggingFace, Character.AI, DeepMind, Inflection, Meta AI) — 2,941 additional subdomains, 2 additional MEDIUM findings; 9 of 13 providers fully clean.**
2. **Brand impersonation risks** — Edit-distance, homoglyph, and IDN abuse-pattern enumeration with mail-presence scoring. **32+ mail-active phishing-ready surfaces** across the three vendors (7 OpenAI + 8 Anthropic + 4 x.ai + 13 grok.com lookalikes) including digit substitutions and one-character variants.
3. **Off-primary-registrar brand sprawl + email-auth posture** — Standard TLD enumeration with registrar + email-auth posture per domain. **All three brief-named registrars surfaced** in the broader brand surface: **GoDaddy** (`openai.io`, `anthropic.co`, `xai.tech`, `grok.ai`, `grok.io`), **Network Solutions** (`grok.org`), **Namecheap** (`xai.org`). **4 critical fully-spoofable** apexes — mail-active, no SPF, no DMARC. **11 weak-DMARC** OpenAI/Anthropic apexes. Detailed defensive-gap inventory per vendor.

The page that follows has the full per-axis detail. Per-vendor Discovery Intel reports with confidence scores and provenance are available on request.
