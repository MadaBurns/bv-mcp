# Scoring Methodology

Canonical scoring reference for `scan_domain` results. Aligned with scoring v2 three-tier model.

## Three-Tier Category Model

Categories are classified into three tiers with distinct scoring mechanics.

### Core (70% of score)

Controls whose absence creates direct, exploitable risk. Missing-control rule applies (confidence-gated).

| Category | Weight |
| --- | ---: |
| DMARC | 16 |
| DKIM | 10 |
| SPF | 10 |
| DNSSEC | 8 |
| SSL | 8 |

**Confidence gate**: `scoreIndicatesMissingControl()` only fires for `deterministic`/`verified` confidence findings. Heuristic "not found" results from selector probing do not zero the category.

### Protective (20% of score)

Active defenses against known attack vectors. Findings penalize but cannot trigger missing-control zeroing.

| Category | Weight |
| --- | ---: |
| Subdomain Takeover | 4 |
| HTTP Security | 3 |
| MTA-STS | 3 |
| MX | 2 |
| CAA | 2 |
| NS | 2 |
| Lookalikes | 2 |
| Shadow Domains | 2 |

### Hardening (10% of score)

Bonus-only defense-in-depth. Each passed category adds ~1.4 points. Never subtracts from the overall score. Uses `result.passed` (not raw score) to determine pass/fail — this means checks with `missingControl: true` metadata or `scoreIndicatesMissingControl()` detection do not contribute hardening bonus even if their numeric score is >= 50.

Categories: DANE, BIMI, TLS-RPT, TXT Hygiene, MX Reputation, SRV, Zone Hygiene.

Source: `CATEGORY_TIERS` and `computeScanScore()` in `src/lib/scoring-engine.ts`.

## Per-Finding Severity Penalties

Category score formula starts at `100` and deducts per finding:

- Critical: `-40`
- High: `-25`
- Medium: `-15`
- Low: `-5`
- Info: `0`

Source: `SEVERITY_PENALTIES` in `packages/dns-checks/src/types.ts` (re-exported via `src/lib/scoring.ts`).

## Missing-Control Rule

Two mechanisms detect missing controls and set `passed = false` in `buildCheckResult`:

1. **Confidence-gated detection** (`scoreIndicatesMissingControl()`): For findings matching missing-control text patterns (e.g., "no … record", "missing", "not found") with `critical`/`high` severity and `deterministic`/`verified` confidence. This prevents heuristic findings (e.g., DKIM selector probing) from falsely zeroing core categories.

2. **Explicit metadata** (`missingControl: true`): For hardening-tier checks where the control is absent but severity is below the confidence gate threshold (info/low/medium). Used by BIMI (no record or record present but DMARC not enforcing), DANE (no TLSA records), and TLS-RPT (record missing).

In the Core tier, `scoreIndicatesMissingControl()` zeros the category's weighted contribution. In the Hardening tier, `result.passed` determines whether a category contributes bonus points — checks with either detection active do not contribute.

Source: `scoreIndicatesMissingControl()` and `buildCheckResult()` in `packages/dns-checks/src/scoring/model.ts`.

## Critical Gap Ceiling

Domains missing any critical foundational control are capped at a maximum overall score. The ceiling is applied after all other scoring.

Source: `thresholds.criticalGapCeiling` in `packages/dns-checks/src/scoring/config.ts` and `computeScanScore()` in `packages/dns-checks/src/scoring/engine.ts`.

## Critical Finding Penalty

If any **verified**-confidence critical finding exists across the scan, an additional overall penalty is applied after weighted scoring.

- Verified critical present: `-15` overall points
- No verified critical findings: `0` additional penalty

Source: `thresholds.criticalOverallPenalty` in `packages/dns-checks/src/scoring/config.ts` and `computeScanScore()` in `packages/dns-checks/src/scoring/engine.ts`.

## Email Bonus

Added when all of the following are true:

- SPF is present and strong (`score >= 57`)
- DKIM is not deterministically missing
- DMARC is present

DMARC score determines bonus tier:

- DMARC `>= 90`: `+5`
- DMARC `>= 70`: `+3`
- Otherwise: `+2`

Source: `thresholds.emailBonusFull`/`emailBonusMid`/`emailBonusPartial`, `thresholds.spfStrongThreshold` in `packages/dns-checks/src/scoring/config.ts` and bonus logic in `computeScanScore()`.

## Provider-Informed DKIM

When a known DKIM-signing provider is detected (via MX/SPF analysis) but selector probing finds no records, the HIGH finding is downgraded to MEDIUM. This reduces false positives for domains whose provider manages DKIM selectors not discoverable via common probing.

Provider context is applied as a post-processing step after parallel checks complete in `scan_domain`.

Source: `src/tools/scan/post-processing.ts`.

## Provider Confidence Modifier

After base weighted scoring and email bonus, `scan_domain` applies a bounded confidence modifier derived from provider detection findings (`metadata.providerConfidence`).

- Confidence values normalized to `[0, 1]`
- Average confidence centered around `0.5`
- Overall score modifier range approximately `-5` to `+5`
- If no provider confidence metadata is present, modifier is `0`

Source: `computeProviderConfidenceModifier()` and `computeScanScore()` in `src/lib/scoring-engine.ts`.

## Grades

- A+: `92+`
- A: `87-91`
- B+: `82-86`
- B: `76-81`
- C+: `70-75`
- C: `63-69`
- D+: `56-62`
- D: `50-55`
- F: `<50`

Source: `scoreToGrade()` in `packages/dns-checks/src/scoring/engine.ts` (re-exported via `src/lib/scoring.ts`).

## Scoring Profiles

`computeScanScore()` accepts an optional `DomainContext` that adapts weights based on detected domain purpose. Five profiles exist:

| Profile | When Detected | Key Differences |
| --- | --- | --- |
| `mail_enabled` | Has MX, no enterprise provider (default) | Base three-tier weights |
| `enterprise_mail` | MX + enterprise provider + hardening signal | Email auth slightly higher, MTA-STS/TLS-RPT elevated |
| `non_mail` | No MX, no web indicators | Email auth near-zero, DNSSEC/SubdomainTakeover elevated |
| `web_only` | No MX + CAA or SSL present | Email auth near-zero, SSL elevated |
| `minimal` | >50% checks failed | Weights spread evenly, lower total |

- **Email bonus**: only for `mail_enabled` and `enterprise_mail`
- **Critical gap categories**: `mail_enabled`/`enterprise_mail` use core categories; `non_mail`/`web_only` use `['ssl', 'subdomain_takeover', 'http_security']`; `minimal` uses `['ssl', 'subdomain_takeover']`

### Phase 1 (Current)

Auto-detection runs and is reported in the structured result (`scoringProfile`, `scoringSignals`), but `auto` mode uses `mail_enabled` weights. Only explicit `profile` parameter values activate different weights and cache keys (`cache:<domain>:profile:<profile>`).

Detection priority: `non_mail`/`web_only` (no MX or Null MX) → `mail_enabled` (MX DNS failure — safe fallback) → `enterprise_mail` (MX + provider + hardening) → `mail_enabled` (MX, default) → `minimal` (>50% failed override).

Source: `src/lib/context-profiles.ts`.

## Maturity Staging

`computeMaturityStage()` classifies the domain into a maturity stage (0-4):

| Stage | Label | Criteria |
| --- | --- | --- |
| 0 | Unprotected | No SPF or no DMARC |
| 1 | Basic | SPF present, DMARC present |
| 2 | Configured | DMARC policy != none, MTA-STS present |
| 3 | Enforcing | DMARC policy = reject/quarantine, DNSSEC present. DKIM not required. |
| 4 | Hardened | Stage 3 + hardening signals: BIMI, DANE, MTA-STS strict, CAA, or DKIM-discovered |

Source: `src/tools/scan/maturity-staging.ts`.

## Notes on `scan_domain`

`scan_domain` runs checks in parallel and includes non-mail-domain adjustment behavior when no MX records are present. Accepts an optional `profile` parameter (`auto`, `mail_enabled`, `enterprise_mail`, `non_mail`, `web_only`, `minimal`) to control scoring weights.

Source: `src/tools/scan-domain.ts`.
