# Brand Audit: Shadow IT & Provider Sprawl

**Generated:** 2026-05-14  
**Scope:** 11 targets, lookalike TLD variants discovered via SAN / NS / DMARC RUA / DKIM key reuse signals  
**Classification:** same-registrar-family-as-target = consolidated; different registrar + high confidence = shadow IT / sprawl; registry refuses to disclose (e.g. DENIC) = indeterminate; low confidence = impersonation.

## Headline

- **36** consolidated (same registrar as target, centrally managed)
- **2** shadow IT / provider sprawl (high-confidence brand signal on a different registrar)
- **3** indeterminate (registry redacts registrar by policy — e.g. DENIC)
- **3** likely impersonation / low-confidence noise

### Premise check: how many targets actually use BrandAudit?

| Target | Registrar family | On BrandAudit? |
|---|---|:---:|
| google.com | MarkMonitor (MarkMonitor Inc.) | — |
| amazon.com | MarkMonitor (MarkMonitor Inc.) | — |
| microsoft.com | MarkMonitor (MarkMonitor Inc.) | — |
| apple.com | Com Laude (Nom-iq Ltd. dba COM LAUDE) | — |
| disney.com | BrandAudit (BrandAudit Corporate Domains, Inc.) | ✓ |
| nike.com | MarkMonitor (MarkMonitor Inc.) | — |
| paypal.com | MarkMonitor (MarkMonitor Inc.) | — |
| stripe.com | SafeNames (SafeNames Ltd.) | — |
| walmart.com | BrandAudit (BrandAudit Corporate Domains, Inc.) | ✓ |
| github.com | MarkMonitor (MarkMonitor Inc.) | — |
| blackveilsecurity.com | Cloudflare (Cloudflare, Inc.) | — |

> **Only 2 of 11 are BrandAudit-managed (Disney, Walmart).** The original audit premise treated all 11 as BrandAudit; six are actually on MarkMonitor, Apple on Com Laude, Stripe on SafeNames, Blackveil on Cloudflare.

## Per-target detail

### google.com — primary: MarkMonitor (1 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `google.biz` | MarkMonitor, Inc. | NS | 1 |
| `google.ca` | MarkMonitor International Canada Ltd. | NS | 1 |
| `google.fr` | MARKMONITOR Inc. | NS | 1 |
| `google.info` | MarkMonitor Inc. | NS | 1 |
| `google.net` | MarkMonitor Inc. | NS | 1 |
| `google.org` | MarkMonitor Inc. | NS | 1 |
| `google.co` | MarkMonitor, Inc. | NS | 1 |
| `google.io` | MarkMonitor Inc. | NS | 1 |
| `google.me` | MarkMonitor Inc. | NS | 1 |
| `google.sh` | MarkMonitor Inc. | NS | 1 |
| `google.us` | MarkMonitor, Inc. | NS | 1 |

**Indeterminate** (registry refuses to disclose registrar — registrar may still be the same family):

| Domain | Source | Evidence | Confidence |
|---|---|---|---:|
| `google.de` | redacted | NS | 1 |

### amazon.com — primary: MarkMonitor (1 registrar families across portfolio)

_No candidate domains surfaced by discovery signals._

### microsoft.com — primary: MarkMonitor (1 registrar families across portfolio)

_No candidate domains surfaced by discovery signals._

### apple.com — primary: Com Laude (2 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `apple.ai` | Nom-iq Ltd. dba COM LAUDE | NS | 1 |
| `apple.app` | Nom-IQ Limited dba Com Laude | NS | 1 |
| `apple.biz` | Nom-iq Ltd. dba COM LAUDE | NS | 1 |
| `apple.fr` | COM LAUDE (NOM IQ LIMITED) | NS | 1 |
| `apple.info` | Nom-iq Ltd. dba COM LAUDE | NS | 1 |
| `apple.net` | Nom-iq Ltd. dba COM LAUDE | NS | 1 |
| `apple.uk` | Nom-IQ Limited t/a Com Laude | NS | 1 |
| `apple.co` | Nom-iq Ltd. dba COM LAUDE | NS | 1 |
| `apple.me` | Nom-iq Ltd. dba COM LAUDE | NS | 1 |
| `apple.us` | Nom-iq Ltd. dba COM LAUDE | NS | 1 |

**Shadow IT / Provider Sprawl** (high-confidence, different registrar):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `apple.ca` | Tucows.com Co. | NS | 1 |

**Indeterminate** (registry refuses to disclose registrar — registrar may still be the same family):

| Domain | Source | Evidence | Confidence |
|---|---|---|---:|
| `apple.de` | redacted | NS | 1 |

### disney.com — primary: BrandAudit (1 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `disney.org` | BrandAudit Corporate Domains, Inc. | NS | 1 |
| `maildisney.com` | BrandAudit Corporate Domains, Inc. | MARKOV GEN, NS | 1 |

### nike.com — primary: MarkMonitor (1 registrar families across portfolio)

_No candidate domains surfaced by discovery signals._

### paypal.com — primary: MarkMonitor (1 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `paypal.ai` | MarkMonitor Inc. | NS | 1 |
| `paypal.biz` | MarkMonitor, Inc. | NS | 1 |
| `paypal.ca` | MarkMonitor International Canada Ltd. | NS | 1 |
| `paypal.fr` | MARKMONITOR Inc. | NS | 1 |
| `paypal.co` | MarkMonitor, Inc. | NS | 1 |
| `paypal.me` | MarkMonitor Inc. | NS | 1 |

**Indeterminate** (registry refuses to disclose registrar — registrar may still be the same family):

| Domain | Source | Evidence | Confidence |
|---|---|---|---:|
| `paypal.de` | redacted | NS | 1 |

### stripe.com — primary: SafeNames (1 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `stripe.fr` | SAFENAMES LTD | NS | 1 |
| `stripe.net` | SafeNames Ltd. | NS | 1 |
| `stripe.uk` | Safenames Ltd | NS | 1 |
| `stripe.me` | SafeNames Ltd. | NS | 1 |
| `stripe.sh` | SafeNames Ltd. | NS | 1 |

### walmart.com — primary: BrandAudit (2 registrar families across portfolio)

**Shadow IT / Provider Sprawl** (high-confidence, different registrar):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `walmart.ca` | MarkMonitor International Canada Ltd. | NS | 1 |

**Impersonation / Low Confidence**:

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `walmart.app` | MarkMonitor Inc. | NS | 0.5 |
| `walmart.io` | MarkMonitor Inc. | NS | 0.5 |
| `walmart.org` | MarkMonitor Inc. | NS | 0.5 |

### github.com — primary: MarkMonitor (1 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `github.me` | MarkMonitor Inc. | NS | 0.5 |

### blackveilsecurity.com — primary: Cloudflare (1 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `blackveilsecurity.ai` | Cloudflare, Inc | DMARC RUA, NS | 1 |

## Cross-portfolio registrar distribution

Across all 44 candidate domains:

| Registrar | Candidates |
|---|---:|
| MarkMonitor Inc. | 12 |
| Nom-iq Ltd. dba COM LAUDE | 7 |
| MarkMonitor, Inc. | 5 |
| MarkMonitor International Canada Ltd. | 3 |
| Unknown | 3 |
| SafeNames Ltd. | 3 |
| MARKMONITOR Inc. | 2 |
| BrandAudit Corporate Domains, Inc. | 2 |
| Nom-IQ Limited dba Com Laude | 1 |
| COM LAUDE (NOM IQ LIMITED) | 1 |
| Nom-IQ Limited t/a Com Laude | 1 |
| Tucows.com Co. | 1 |
| SAFENAMES LTD | 1 |
| Safenames Ltd | 1 |
| Cloudflare, Inc | 1 |

## Methodology notes & caveats

- **ccTLDs without RDAP** (`.me/.co/.us/.sh/.io/.uk/.fr/.ca/...`) resolved via the bv-whois shim Worker (WHOIS-over-TCP/43 with IANA referral cache).
- **`.de` (DENIC) is short-circuited as redacted** — German law (BDSG) requires the registry to withhold the registrar field, and DENIC blocks Cloudflare Workers' egress IPs at port 43. The shim returns `source: redacted` instantly without contacting the network.
- **MarkMonitor / Com Laude / SafeNames** each appear under multiple string variants (case, regional subsidiary, dba); normalized to one family per provider.
- **Confidence threshold for shadow IT = 0.7** matches the original spec. Defensive registrations at conf=0.5 (e.g., `walmart.app/io/org`) fall into the impersonation bucket despite being likely Walmart-owned. Threshold tuning is a follow-up.
- **Candidate set is `<base>.<TLD>` for 15 hardcoded TLDs.** Subdomains under target (e.g., `mail.apple.com`) come from discovery signals separately.