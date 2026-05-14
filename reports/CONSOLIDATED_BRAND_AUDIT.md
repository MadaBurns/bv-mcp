# Brand Audit: Shadow IT & Provider Sprawl

**Generated:** 2026-05-14  
**Scope:** 11 targets, lookalike TLD variants discovered via SAN / NS / DMARC RUA / DKIM key reuse signals  
**Classification:** same-registrar-family-as-target = consolidated; different-or-unknown + high confidence = shadow IT / sprawl; low confidence = impersonation.

## Headline

- **23** consolidated (same registrar as target, centrally managed)
- **17** shadow IT / provider sprawl (high-confidence brand signal on a different or unknown registrar)
- **4** likely impersonation / low-confidence noise

### Premise check: how many targets actually use CSC?

| Target | Registrar family | On CSC? |
|---|---|:---:|
| google.com | MarkMonitor (MarkMonitor Inc.) | — |
| amazon.com | MarkMonitor (MarkMonitor Inc.) | — |
| microsoft.com | MarkMonitor (MarkMonitor Inc.) | — |
| apple.com | Com Laude (Nom-iq Ltd. dba COM LAUDE) | — |
| disney.com | CSC (CSC Corporate Domains, Inc.) | ✓ |
| nike.com | MarkMonitor (MarkMonitor Inc.) | — |
| paypal.com | MarkMonitor (MarkMonitor Inc.) | — |
| stripe.com | SafeNames (SafeNames Ltd.) | — |
| walmart.com | CSC (CSC Corporate Domains, Inc.) | ✓ |
| github.com | MarkMonitor (MarkMonitor Inc.) | — |
| blackveilsecurity.com | Cloudflare (Cloudflare, Inc.) | — |

> **Only 2 of 11 are CSC-managed (Disney, Walmart).** The original audit premise treated all 11 as CSC; six are actually on MarkMonitor, Apple on Com Laude, Stripe on SafeNames, Blackveil on Cloudflare.

## Per-target detail

### google.com — primary: MarkMonitor (2 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `google.biz` | MarkMonitor, Inc. | NS | 1 |
| `google.ca` | MarkMonitor International Canada Ltd. | NS | 1 |
| `google.fr` | MARKMONITOR Inc. | NS | 1 |
| `google.info` | MarkMonitor Inc. | NS | 1 |
| `google.net` | MarkMonitor Inc. | NS | 1 |
| `google.org` | MarkMonitor Inc. | NS | 1 |

**Shadow IT / Provider Sprawl** (high-confidence, different registrar):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `google.co` | Unknown | NS | 1 |
| `google.de` | Unknown | NS | 1 |
| `google.io` | Unknown | NS | 1 |
| `google.me` | Unknown | NS | 1 |
| `google.sh` | Unknown | NS | 1 |
| `google.us` | Unknown | NS | 1 |

### amazon.com — primary: MarkMonitor (1 registrar families across portfolio)

_No candidate domains surfaced by discovery signals._

### microsoft.com — primary: MarkMonitor (1 registrar families across portfolio)

_No candidate domains surfaced by discovery signals._

### apple.com — primary: Com Laude (3 registrar families across portfolio)

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

**Shadow IT / Provider Sprawl** (high-confidence, different registrar):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `apple.ca` | Tucows.com Co. | NS | 1 |
| `apple.co` | Unknown | NS | 1 |
| `apple.de` | Unknown | NS | 1 |
| `apple.me` | Unknown | NS | 1 |
| `apple.us` | Unknown | NS | 1 |

### disney.com — primary: CSC (1 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `disney.org` | CSC Corporate Domains, Inc. | NS | 1 |
| `maildisney.com` | CSC Corporate Domains, Inc. | MARKOV GEN, NS | 1 |

### nike.com — primary: MarkMonitor (1 registrar families across portfolio)

_No candidate domains surfaced by discovery signals._

### paypal.com — primary: MarkMonitor (2 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `paypal.ai` | MarkMonitor Inc. | NS | 1 |
| `paypal.biz` | MarkMonitor, Inc. | NS | 1 |
| `paypal.ca` | MarkMonitor International Canada Ltd. | NS | 1 |
| `paypal.fr` | MARKMONITOR Inc. | NS | 1 |

**Shadow IT / Provider Sprawl** (high-confidence, different registrar):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `paypal.co` | Unknown | NS | 1 |
| `paypal.de` | Unknown | NS | 1 |
| `paypal.me` | Unknown | NS | 1 |

### stripe.com — primary: SafeNames (2 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `stripe.fr` | SAFENAMES LTD | NS | 1 |
| `stripe.net` | SafeNames Ltd. | NS | 1 |
| `stripe.uk` | Safenames Ltd | NS | 1 |

**Shadow IT / Provider Sprawl** (high-confidence, different registrar):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `stripe.me` | Unknown | NS | 1 |
| `stripe.sh` | Unknown | NS | 1 |

### walmart.com — primary: CSC (3 registrar families across portfolio)

**Shadow IT / Provider Sprawl** (high-confidence, different registrar):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `walmart.ca` | MarkMonitor International Canada Ltd. | NS | 1 |

**Impersonation / Low Confidence**:

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `walmart.app` | MarkMonitor Inc. | NS | 0.5 |
| `walmart.io` | Unknown | NS | 0.5 |
| `walmart.org` | MarkMonitor Inc. | NS | 0.5 |

### github.com — primary: MarkMonitor (2 registrar families across portfolio)

**Impersonation / Low Confidence**:

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `github.me` | Unknown | NS | 0.5 |

### blackveilsecurity.com — primary: Cloudflare (1 registrar families across portfolio)

**Consolidated** (same registrar family as target):

| Domain | Registrar | Evidence | Confidence |
|---|---|---|---:|
| `blackveilsecurity.ai` | Cloudflare, Inc | DMARC RUA, NS | 1 |

## Cross-portfolio registrar distribution

Across all 44 candidate domains:

| Registrar | Candidates |
|---|---:|
| Unknown | 17 |
| MarkMonitor Inc. | 6 |
| Nom-iq Ltd. dba COM LAUDE | 4 |
| MarkMonitor International Canada Ltd. | 3 |
| MarkMonitor, Inc. | 2 |
| MARKMONITOR Inc. | 2 |
| CSC Corporate Domains, Inc. | 2 |
| Nom-IQ Limited dba Com Laude | 1 |
| COM LAUDE (NOM IQ LIMITED) | 1 |
| Nom-IQ Limited t/a Com Laude | 1 |
| Tucows.com Co. | 1 |
| SAFENAMES LTD | 1 |
| SafeNames Ltd. | 1 |
| Safenames Ltd | 1 |
| Cloudflare, Inc | 1 |

## Methodology notes & caveats

- **17 of 44 candidates returned `Unknown` registrar** — all ccTLDs (`.me/.de/.co/.us/.sh/.io`) where RDAP either lacks a server or returned 404. These get bucketed as shadow IT by default. Manual WHOIS would resolve them.
- **MarkMonitor appears under 4 legal entities** (`Inc.`, `MARKMONITOR Inc.`, `MarkMonitor, Inc.`, `MarkMonitor International Canada Ltd.`) — normalized to one family.
- **Com Laude appears under 4 string variants** (`Nom-iq Ltd. dba COM LAUDE`, `COM LAUDE (NOM IQ LIMITED)`, etc.) — normalized to one family.
- **Confidence threshold for shadow IT = 0.7** matches the original spec. Defensive registrations at conf=0.5 (e.g., `walmart.app/io/org`) fall into the impersonation bucket despite being likely Walmart-owned. Threshold tuning is a follow-up.
- **Candidate set is `<base>.<TLD>` for 15 hardcoded TLDs.** Subdomains under target (e.g., `mail.apple.com`) come from discovery signals separately.