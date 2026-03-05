# Scoring Methodology

Canonical scoring reference for `scan_domain` results.

## Category Importance Weights

Overall score is computed from category scores weighted by importance.

| Category | Importance |
| --- | ---: |
| DMARC | 22 |
| SPF | 19 |
| DKIM | 10 |
| SSL | 8 |
| DNSSEC | 3 |
| MTA-STS | 3 |
| NS | 0 |
| CAA | 0 |
| Subdomain Takeover | 0 |
| MX | 0 |

Source: `IMPORTANCE_WEIGHTS` in `src/lib/scoring.ts`.

## Per-Finding Severity Penalties

Category score formula starts at `100` and deducts per finding:

- Critical: `-40`
- High: `-25`
- Medium: `-15`
- Low: `-5`
- Info: `0`

Source: `SEVERITY_PENALTIES` in `src/lib/scoring.ts`.

## Missing-Control Rule

For weighted categories, findings that indicate missing required controls (for example no record found) can force effective category contribution to `0`.

Source: `scoreIndicatesMissingControl()` in `src/lib/scoring.ts`.

## Critical Finding Penalty

If any critical finding exists across the scan, an additional overall penalty is applied after weighted scoring.

- Critical present: `-15` overall points
- No critical findings: `0` additional penalty

This ensures critical risks (for example takeover or certificate failures) materially impact final grade even when they appear in low-importance categories.

Source: `CRITICAL_OVERALL_PENALTY` and `computeScanScore()` in `src/lib/scoring.ts`.

## Email Bonus

Up to `+5` points are added when all of the following are true:

- SPF is present and strong (`score >= 57`)
- DKIM is present
- DMARC is present

DMARC score determines bonus:

- DMARC `>= 90`: `+5`
- DMARC `>= 70`: `+3`
- Otherwise: `+2`

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

Source: `computeProviderConfidenceModifier()` and `computeScanScore()` in `src/lib/scoring.ts`.

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

## Notes on `scan_domain`

`scan_domain` runs checks in parallel and includes non-mail-domain adjustment behavior when no MX records are present.

Source: `src/tools/scan-domain.ts`.
