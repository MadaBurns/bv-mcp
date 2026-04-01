# Scoring Methodology

Canonical scoring reference for `scan_domain` results. Aligned with scoring v2 three-tier model.

## Three-Tier Category Model

Categories are classified into three tiers with distinct scoring mechanics.

### Core (70% of score)

Controls whose absence creates direct, exploitable risk. Missing-control rule applies (confidence-gated).

| Category | Weight |
| --- | ---: |
| DMARC | 22 |
| DKIM | 16 |
| SPF | 10 |
| DNSSEC | 7 |
| SSL | 5 |

> These are production weights set via `SCORING_CONFIG` env var. Code defaults (when `SCORING_CONFIG` is absent): DMARC 16, DKIM 10, SPF 10, DNSSEC 8, SSL 8.

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

**Tool Annotations**: Every tool definition includes `group`, `tier` (`core`, `protective`, or `hardening`), and a `scanIncluded` flag. These annotations align with the category tiers above and are included in `tools/list` responses for structured consumption by MCP clients.

Source: `CATEGORY_TIERS` and `computeScanScore()` (bridge) in `packages/dns-checks/src/scoring/engine.ts`.

## Generic Scoring Engine

The core scoring logic has been refactored into a **Generic Scoring Engine** (ported from `claude-code-py` architecture). This engine is decoupled from concrete DNS check types, allowing for arbitrary string-keyed categories and tiers.

- **String-keyed inputs**: Accepts `categoryScores` as a `Record<string, number>`, making it runtime-agnostic and easy to port to other languages.
- **Three-tier formula**: Implements the Core/Protective/Hardening tier logic as a pure functional transformation.
- **Single Source of Truth**: The `computeScanScore` function in the main package now serves as a thin bridge that maps `CheckResult[]` into the `GenericScoringContext`.

Source: `packages/dns-checks/src/scoring/generic.ts`.

## Per-Finding Severity Penalties

Category score formula starts at `100` and deducts per finding:

- Critical: `-40`
- High: `-25`
- Medium: `-15`
- Low: `-5`
- Info: `0`

**SPF `~all` Downgrade Rule**: SPF soft-fail (`~all`) findings are lowered to `info` severity (0 penalty) when the domain has an enforcing DMARC policy (`p=quarantine` or `p=reject`). Since DMARC enforcement already prevents spoofing from non-aligned sources, the RFC-recommended `~all` posture is no longer considered a risk in these environments.

**DMARC `pct` Parsing**: The `pct` (percentage) parameter is parsed from DMARC records to determine the true enforcement context. If `pct < 100`, the enforcement is considered partial, which may affect how related findings (like SPF trust surface) are weighed.

Source: `SEVERITY_PENALTIES` in `packages/dns-checks/src/scoring/model.ts` (re-exported via `src/lib/scoring.ts`).

## Missing-Control Rule

Two mechanisms detect missing controls in `buildCheckResult`:

1. **Confidence-gated detection** (`scoreIndicatesMissingControl()`): For findings matching missing-control text patterns (e.g., "no … record", "missing", "not found") with `critical`/`high` severity and `deterministic`/`verified` confidence. This prevents heuristic findings (e.g., DKIM selector probing) from falsely zeroing core categories.

2. **Explicit metadata** (`missingControl: true`): For checks where the control is entirely absent. Used across all tiers: CAA (no records), DNSSEC (not enabled), HTTP Security (site unreachable), MTA-STS (no record), MX (no records), SVCB-HTTPS (no record), NS (no records), Zone Hygiene (no NS/SOA), BIMI (no record), DANE (no TLSA), TLS-RPT (missing).

**Score zeroing**: When either mechanism fires, `score` is set to `0` (`hasMissingControl ? 0 : score`). Checks that fail due to low penalty-based score (e.g., two criticals → score 20, `passed=false`) retain their numeric score — only truly missing controls are zeroed. This prevents misleading displays like `✓ 95/100` for checks with no record at all.

**`passed` flag**: `score >= 50 && !hasMissingControl`. A check fails if the score is below 50 or if either missing-control mechanism fires.

In the Core tier, missing controls zero the category's weighted contribution. In the Hardening tier, `result.passed` determines whether a category contributes bonus points — checks with either detection active do not contribute.

Source: `scoreIndicatesMissingControl()` and `buildCheckResult()` in `packages/dns-checks/src/scoring/model.ts`.

## Critical Gap Ceiling

Domains missing any critical foundational control are capped at a maximum overall score. The ceiling is applied after all other scoring.

Source: `thresholds.criticalGapCeiling` in `packages/dns-checks/src/scoring/config.ts` and `computeScanScore()` (via generic engine) in `packages/dns-checks/src/scoring/engine.ts`.

## Critical Finding Penalty

If any **verified**-confidence critical finding exists across the scan, an additional overall penalty is applied after weighted scoring.

- Verified critical present: `-15` overall points
- No verified critical findings: `0` additional penalty

Source: `thresholds.criticalOverallPenalty` in `packages/dns-checks/src/scoring/config.ts` and `computeScanScore()` (via generic engine) in `packages/dns-checks/src/scoring/engine.ts`.

## Email Bonus

Added when all of the following are true:

- SPF is present and strong (`score >= 57`)
- DKIM is not deterministically missing
- DMARC is present

DMARC score determines bonus tier:

- DMARC `>= 90`: `+5`
- DMARC `>= 70`: `+3`
- Otherwise: `+2`

Source: `thresholds.emailBonusFull`/`emailBonusMid`/`emailBonusPartial`, `thresholds.spfStrongThreshold` in `packages/dns-checks/src/scoring/config.ts` and generic bonus logic in `packages/dns-checks/src/scoring/generic.ts`.


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
