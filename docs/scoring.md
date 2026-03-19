# Scoring Methodology

Canonical scoring reference for `scan_domain` results. Aligned with bv-web AI-Resilience v4.0.

## Category Importance Weights

Overall score is computed from category scores weighted by importance.

| Category | Importance | Notes |
| --- | ---: | --- |
| DMARC | 22 | |
| DKIM | 16 | |
| SPF | 10 | |
| SSL | 5 | |
| HTTP Security | 3 | |
| Subdomain Takeover | 3 | |
| DNSSEC | 2 | |
| MTA-STS | 2 | |
| MX | 2 | |
| DANE | 1 | |
| TLS-RPT | 1 | |
| NS | 0 | Informational |
| CAA | 0 | Informational |
| BIMI | 0 | Informational |
| Lookalikes | 0 | Informational |
| Shadow Domains | 0 | Informational |
| TXT Hygiene | 0 | Informational |
| MX Reputation | 0 | Informational |
| SRV | 0 | Informational |
| Zone Hygiene | 0 | Informational |

Scored total: **67** (+ up to 8 email bonus = 75 max denominator).

Source: `IMPORTANCE_WEIGHTS` in `src/lib/scoring-engine.ts`.

## Per-Finding Severity Penalties

Category score formula starts at `100` and deducts per finding:

- Critical: `-40`
- High: `-25`
- Medium: `-15`
- Low: `-5`
- Info: `0`

Source: `SEVERITY_PENALTIES` in `src/lib/scoring-model.ts`.

## Missing-Control Rule

For weighted categories, findings that indicate missing required controls (for example no record found) can force effective category contribution to `0`.

Source: `scoreIndicatesMissingControl()` in `src/lib/scoring-engine.ts`.

## Critical Gap Ceiling

Domains missing any critical foundational control are capped at a maximum score of **64** (grade D+), regardless of how well other categories score. This prevents a domain with no DMARC (or missing SPF, DKIM, SSL, or subdomain takeover protection) from receiving a passing grade.

Critical categories: `spf`, `dmarc`, `dkim`, `ssl`, `subdomain_takeover`.

DNSSEC is intentionally excluded: its importance weight (2) already reflects its proportional impact, and only ~30% of domains deploy it — capping the entire score at 64 for missing DNSSEC produces misleading results for well-configured domains.

The ceiling is applied after all other scoring (weighted average, email bonus, provider modifier, critical penalty). If any critical category has a missing-control finding, `overall = min(computed, 64)`.

Source: `CRITICAL_GAP_CEILING` and `computeScanScore()` in `src/lib/scoring-engine.ts`.

## Critical Finding Penalty

If any **verified**-confidence critical finding exists across the scan, an additional overall penalty is applied after weighted scoring.

- Verified critical present: `-15` overall points
- No verified critical findings: `0` additional penalty

This ensures verified critical risks (for example takeover or certificate failures) materially impact final grade even when they appear in low-importance categories.

Source: `CRITICAL_OVERALL_PENALTY` and `computeScanScore()` in `src/lib/scoring-engine.ts`.

## Email Bonus

Up to `+8` points are added when all of the following are true:

- SPF is present and strong (`score >= 57`)
- DKIM is present
- DMARC is present

DMARC score determines bonus tier:

- DMARC `>= 90`: `+8`
- DMARC `>= 70`: `+5`
- Otherwise: `+4`

Source: `EMAIL_BONUS_IMPORTANCE`, `SPF_STRONG_THRESHOLD`, and bonus logic in `computeScanScore()`.

## Provider Confidence Modifier

After base weighted scoring and email bonus, `scan_domain` applies a bounded confidence modifier derived from provider detection findings (`metadata.providerConfidence`).

- Confidence values are normalized to `[0, 1]`
- Average confidence is centered around `0.5`
- Overall score modifier range is approximately `-5` to `+5`
- If no provider confidence metadata is present, modifier is `0`

Provider confidence is currently attached by:

- Inbound provider detection in `check_mx`
- Outbound provider inference in `scan_domain` (from SPF include/redirect signals and DKIM selector hints)

Source: `computeProviderConfidenceModifier()` and `computeScanScore()` in `src/lib/scoring-engine.ts`.

## Grades

- A+: `90+`
- A: `85-89`
- B+: `80-84`
- B: `75-79`
- C+: `70-74`
- C: `65-69`
- D+: `60-64`
- D: `55-59`
- E: `50-54`
- F: `<50`

Source: `scoreToGrade()` in `src/lib/scoring.ts`.

## Scoring Profiles

`computeScanScore()` accepts an optional `DomainContext` that adapts weights based on detected domain purpose. Five profiles exist:

| Profile | When Detected | Key Differences |
| --- | --- | --- |
| `mail_enabled` | Has MX, no enterprise provider (default) | Today's weights unchanged |
| `enterprise_mail` | MX + enterprise provider + hardening signal | Email auth slightly higher, MTA-STS/TLS-RPT/BIMI elevated |
| `non_mail` | No MX, no web indicators | Email auth near-zero, DNSSEC/SubdomainTakeover elevated |
| `web_only` | No MX + CAA or SSL present | Email auth near-zero, SSL:12, CAA:5, DNSSEC:5 |
| `minimal` | >50% checks failed | Weights spread evenly, lower total |

### Profile Weight Table

| Category | mail_enabled | enterprise_mail | non_mail | web_only | minimal |
| --- | ---: | ---: | ---: | ---: | ---: |
| DMARC | 22 | 24 | 2 | 2 | 5 |
| DKIM | 16 | 18 | 1 | 1 | 3 |
| SPF | 10 | 12 | 1 | 1 | 3 |
| SSL | 5 | 5 | 8 | 12 | 5 |
| HTTP Security | 3 | 3 | 5 | 5 | 2 |
| Subdomain Takeover | 3 | 3 | 5 | 5 | 3 |
| DNSSEC | 2 | 3 | 5 | 5 | 5 |
| MTA-STS | 2 | 4 | 0 | 0 | 0 |
| MX | 2 | 2 | 0 | 0 | 1 |
| DANE | 1 | 2 | 0 | 0 | 0 |
| TLS-RPT | 1 | 2 | 0 | 0 | 0 |
| CAA | 0 | 0 | 3 | 5 | 1 |
| NS | 0 | 0 | 2 | 2 | 2 |
| BIMI | 0 | 1 | 0 | 0 | 0 |
| Lookalikes | 0 | 0 | 0 | 0 | 0 |
| Shadow Domains | 0 | 0 | 0 | 0 | 0 |
| TXT Hygiene | 0 | 0 | 0 | 0 | 0 |
| MX Reputation | 0 | 0 | 0 | 0 | 0 |
| SRV | 0 | 0 | 0 | 0 | 0 |
| Zone Hygiene | 0 | 0 | 0 | 0 | 0 |

- **Email bonus**: only for `mail_enabled` and `enterprise_mail`
- **Critical gap categories**: `mail_enabled`/`enterprise_mail` use `['spf', 'dmarc', 'dkim', 'ssl', 'subdomain_takeover']`; `non_mail`/`web_only` use `['ssl', 'subdomain_takeover', 'http_security']`; `minimal` uses `['ssl', 'subdomain_takeover']`

### Phase 1 (Current)

Auto-detection runs and is reported in the structured result (`scoringProfile`, `scoringSignals`), but `auto` mode uses `mail_enabled` weights (identical to pre-profile behavior). Only explicit `profile` parameter values activate different weights and cache keys (`cache:<domain>:profile:<profile>`).

Detection priority: `non_mail`/`web_only` (no MX or Null MX) → `mail_enabled` (MX DNS failure — safe fallback) → `enterprise_mail` (MX + provider + hardening) → `mail_enabled` (MX, default) → `minimal` (>50% failed override).

Source: `src/lib/context-profiles.ts`.

## Notes on `scan_domain`

`scan_domain` runs checks in parallel and includes non-mail-domain adjustment behavior when no MX records are present. Accepts an optional `profile` parameter (`auto`, `mail_enabled`, `enterprise_mail`, `non_mail`, `web_only`, `minimal`) to control scoring weights.

Source: `src/tools/scan-domain.ts`.
