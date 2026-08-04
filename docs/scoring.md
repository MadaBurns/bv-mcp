# Scoring Methodology

Canonical scoring reference for `scan_domain` results. Aligned with scoring v2 three-tier model.

## What this score measures — and what it does not

The score rates **externally observable DNS, email-authentication, and TLS configuration** for a domain. Everything it grades is published in DNS or served over TLS, so a scan is passive and needs no access to the organization being scanned.

Read the result as **brand-protection and deliverability posture**, because that is what the controls do. SPF, DKIM, and DMARC largely protect *recipients* — and your brand's reputation — from your domain being used to send mail it did not authorize. They are a third-party benefit before they are a self-protective one.

**Out of scope**, and therefore invisible to any grade here:

- Endpoint, identity, and application security; MFA posture; patch state
- Account takeover, and lateral business-email compromise sent from a legitimate internal mailbox — such mail authenticates correctly and passes DMARC
- Impersonation from an attacker-controlled *lookalike* domain, which carries its own valid SPF/DKIM/DMARC (we surface lookalikes separately; a domain's own grade cannot reflect them)
- Mail sent from free webmail providers, which authenticates under the provider's domain
- Response-based social engineering that carries no link or attachment
- Anything outside email and DNS entirely

**This score is not a breach-likelihood prediction.** No published dataset establishes a correlation between these DNS/email controls and incident rates, in either direction, and we do not claim one. A domain can hold an A+ here and be compromised through any of the vectors listed above.

Use it for what it supports: comparing posture across domains on a consistent basis, evidencing configuration for audit and compliance, and prioritizing concrete, fixable DNS and email-authentication defects.

## Three-Tier Category Model

Categories are classified into three tiers with distinct scoring mechanics.

### Core (70% of score)

Controls whose absence creates direct, exploitable risk. Missing-control rule applies (confidence-gated).

| Category | Weight (`mail_enabled`) |
| --- | ---: |
| DMARC | 16 |
| DKIM | 10 |
| SPF | 10 |
| DNSSEC | 10 |
| SSL | 8 |
| Authoritative DNS Infrastructure | 0 |

> **Core weights are per-profile.** The table shows the default `mail_enabled` values from `PROFILE_WEIGHTS` (`packages/dns-checks/src/scoring/profiles.ts`), which is the single source of weight values — `scan_domain` always scores through one of the six profile tables. Other profiles differ: DMARC is 20 in `enterprise_mail` and 0 in `web_only`, and DNSSEC ranges from 5 (`minimal`) to 20 (`authoritative_dns_infra`). A weight is only meaningful alongside the profile that selected it.
>
> **Correction (2026-08):** an earlier revision listed a different set here (DMARC 22, DKIM 16, DNSSEC 7, SSL 5) as "production weights set via `SCORING_CONFIG`". Those were a `coreWeights` override, and `coreWeights` is **not read on the `scan_domain` path**: `buildGenericContext()` consults it only in the branch taken when no domain context is supplied, and `scan_domain` always supplies one. Such an override parses, validates, and changes the effective-config hash while changing no score. Weight overrides must be expressed as `SCORING_CONFIG` → `profileWeights.<profile>`; `coreWeights`/`protectiveWeights` survive only because `ScoringConfig` is a published npm surface, and an inert key now emits a warning.
>
> The authoritative DNS category is core for classification and display, but it is weighted 0 in every profile except `authoritative_dns_infra` (where it is 40), so raw infrastructure evidence does not shift ordinary `scan_domain` scores unless the dedicated profile is selected.

**Confidence gate**: `scoreIndicatesMissingControl()` only fires for `deterministic`/`verified` confidence findings. Heuristic "not found" results from selector probing do not zero the category.

### Evidence sufficiency

A scan must complete at least **60%** of its attempted checks to receive a grade. Below
that, `scan_domain` returns `score: null` / `grade: null` with `evidenceInsufficient: true`
and a plain-English `evidenceNote`, rendered as `not measured`. Findings and per-category
scores for the checks that *did* run are still returned.

Every scan — graded or not — reports `evidence: { attempted, completed, ratio }` so a
reader can see the scan's own coverage. The threshold is a single constant
(`EVIDENCE_SUFFICIENCY_THRESHOLD` in `@blackveil/dns-checks`), overridable via
`SCORING_CONFIG` → `thresholds.evidenceSufficiency` and clamped to `[0, 1]`.

This is not a scoring cut-point: it changes only whether a grade is emitted, never what
an emitted grade means. Two states stay strictly separate — **inconclusive** ("we could
not measure it", `inconclusiveCategories`) and **not applicable** ("we measured, and it
genuinely does not apply", `notApplicableCategories`). As of dns-checks 1.7.0 those two
arrays are **disjoint**; read the union as the concatenation of both.

### Protective (20% of score)

Active defenses against known attack vectors.

> **Correction (2026-08):** an earlier revision of this line claimed Protective findings "cannot trigger missing-control zeroing." That was wrong. Three Protective checks — **HTTP Security** (site unreachable), **MX** (no records), and **NS** (no records) — do set explicit `missingControl: true` and therefore zero their category. See [Missing-Control Rule](#missing-control-rule) for the authoritative list of all six. What is true of the Protective tier is that a zeroed category costs at most its own weight (2–4 points) rather than the much larger Core-tier contribution.
>
> **MTA-STS was the fourth on that list and no longer is (scoring model 1.6.0).** Its absence now scores as a graded `medium` rather than zeroing the category. A 1,000-domain corpus scan (2026-08-03) measured `mta_sts` at a mean score of 3.3 with 96.5% of the 687 measured domains at exactly 0 — a control almost nobody deploys separates nobody, so it was acting as a flat constant penalty rather than a discriminator. A deployed-but-broken MTA-STS policy still produces its confident `high`/`medium` findings; only absence changed.

| Category | Weight |
| --- | ---: |
| Subdomain Takeover | 4 |
| HTTP Security | 3 |
| MTA-STS | 3 |
| Subdomailing | 3 |
| MX | 2 |
| CAA | 2 |
| NS | 2 |
| Lookalikes | 2 |
| Shadow Domains | 2 |

> These are the default `mail_enabled` protective weights; they happen to match the legacy flat `protectiveWeights` map (which sums to 23 and, like `coreWeights`, is not read on the scan path). Protective weights are per-profile too. `DANE-HTTPS` (2 in `mail_enabled`) and `SVCB-HTTPS` (1) are also protective-tier in `CATEGORY_TIERS`, but their weights are carried only in `PROFILE_WEIGHTS`, which is why they are absent from the flat map.

### Hardening (10% of score)

Bonus-only defense-in-depth. The 10-point tier is split evenly across the 10 hardening categories, so each passed category adds ~1 point (a category excluded as inconclusive drops out of the denominator, raising the value of the rest). Never subtracts from the overall score. A category counts as passed only when a result exists, `result.passed` is true, and `result.score >= 50` — so checks with `missingControl: true` metadata or `scoreIndicatesMissingControl()` detection do not contribute hardening bonus.

Categories: DANE, BIMI, TLS-RPT, TXT Hygiene, MX Reputation, SRV, Zone Hygiene, Brand Discovery, Reverse DNS (PTR/FCrDNS), DNSKEY Strength.

**Tool Annotations**: Every tool definition includes `group`, `tier` (`core`, `protective`, or `hardening`), and a `scanIncluded` flag. These annotations align with the category tiers above and are included in `tools/list` responses for structured consumption by MCP clients.

Source: `CATEGORY_TIERS` and `computeScanScore()` (bridge) in `packages/dns-checks/src/scoring/engine.ts`.

## Generic Scoring Engine

The core scoring logic has been refactored into a **Generic Scoring Engine**. This engine is decoupled from concrete DNS check types, allowing for arbitrary string-keyed categories and tiers.

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

**SPF Trust-Surface Corroboration Rule**: an SPF `include:`/`redirect=` naming a known multi-tenant sending platform is reported at `info` severity (0 penalty) by default — shared sending infrastructure is common and not a misconfiguration in itself. The per-platform finding is raised to `medium`, and the "N shared platforms" summary (emitted only when more than one cataloged platform matches) to `high`, only when the domain's DMARC corroborates the exposure: enforcement short of `p=reject` at `pct=100` **and** relaxed alignment (`aspf`/`adkim` not both `s`). A missing DMARC record counts as corroborating; a failed DMARC lookup does not.

Scoring model 1.7.0 added Mailjet to the platform catalog. A record whose only recognized shared sender is Mailjet previously produced no catalog match and therefore always read `info`; it now follows the same corroboration rule as the other cataloged platforms, so on a domain with weak DMARC enforcement and relaxed alignment it grades `medium` (the ordinary −15 on `spf`). Domains whose DMARC does not corroborate are unaffected. The affected population has not been measured against the scoring corpus.

Source: `SEVERITY_PENALTIES` in `packages/dns-checks/src/scoring/model.ts` (re-exported via `src/lib/scoring.ts`); `analyzeTrustSurface()` and `MULTI_TENANT_PLATFORMS` in `packages/dns-checks/src/checks/spf-trust-surface.ts`.

## Missing-Control Rule

Two mechanisms detect missing controls in `buildCheckResult`:

1. **Confidence-gated detection** (`scoreIndicatesMissingControl()`): For findings matching missing-control text patterns (e.g., "no … record", "missing", "not found") with `critical`/`high` severity and `deterministic`/`verified` confidence. This prevents heuristic findings (e.g., DKIM selector probing) from falsely zeroing core categories.

2. **Explicit metadata** (`missingControl: true`): For checks where the control is entirely absent. Used by exactly six checks: HTTP Security (site unreachable), MX (no records), NS (no records), Zone Hygiene (no NS/SOA), BIMI (no record), DANE (no TLSA). **CAA, MTA-STS, SVCB-HTTPS, and TLS-RPT deliberately do NOT** set `missingControl` — absence is a graded finding, not a category-zeroing missing control. **DNSSEC "not enabled" also does NOT** — per NIST SP 800-81r3 it's a baseline integrity control in defense-in-depth, so absence is a `high` Core penalty with a fixed `penaltyOverride: 40` (category lands at 60, not 0). DNSSEC's broken-chain / validation-failing cases (distinct from "not enabled") DO fire `missingControl: true`.

   **MTA-STS joined the deliberately-not-setting list in scoring model 1.6.0** (it was previously the seventh setting check). Rationale: measured over a 1,000-domain corpus on 2026-08-03, the `mta_sts` category had a mean score of 3.3 with 96.5% of the 687 measured domains at exactly 0. A control that near-nobody passes is a constant penalty against ~3 of the ~80 base points, not a discriminator, and no documented incident is attributable to a missing MTA-STS policy. Its weight (3, Protective) and finding severities are unchanged — only the zeroing behaviour. A **deployed-but-broken** policy (bad `version:`, missing `mode:`, uncovered MX set, unfetchable policy file) still emits its confident `high`/`medium` findings, which never carried `missingControl` in the first place.

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

Source: `computeProviderConfidenceModifier()` and `computeScanScore()` in `packages/dns-checks/src/scoring/engine.ts`.

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

### Two grade scales, by role (v3.26.0+)

The 9-band scale above is the **internal / SSOT** scale — used by `compare_baseline` ordering, the `/badge` SVG, `analyze_drift`, `map_compliance`, `generate_fix_plan`, cohort-percentile math, golden tests, and `ScanScore.grade`.

The **customer-facing display scale is a NIST-aligned 6-band** (`nistScoreToGrade()`, also in `engine.ts`), shown by `scan_domain`, `batch_scan`, and `compare_domains` ONLY — recomputed from the same 0–100 score at the `format-report.ts` `displayGradeFor` chokepoint (an ungraded scan stays `null` — there is no grade sentinel):

- A+: `≥95`
- A: `≥90`
- B: `≥80`
- C: `≥70`
- D: `≥60`
- F: `<60`

Scores are unchanged by the display scale — only the letter differs. bv-web-prod displays the same NIST letter everywhere so a domain shows one grade across web + MCP.

## Scoring Profiles

`computeScanScore()` accepts an optional `DomainContext` that adapts weights based on detected domain purpose. Six profiles exist:

| Profile | When Detected | Key Differences |
| --- | --- | --- |
| `mail_enabled` | Has MX, no enterprise provider (default) | Base three-tier weights |
| `enterprise_mail` | MX + enterprise provider + hardening signal | Email auth slightly higher, MTA-STS/TLS-RPT elevated |
| `non_mail` | No MX, no web indicators | Email auth near-zero, DNSSEC/SubdomainTakeover elevated |
| `web_only` | No MX + CAA or SSL present | Email auth near-zero, SSL elevated |
| `minimal` | >50% of measured checks failed | Weights spread evenly, lower total |
| `authoritative_dns_infra` | Explicit infrastructure assessment profile | Mail/web controls are non-scoring; authoritative DNS infra, DNSSEC, NS, and zone hygiene dominate |

- **Email bonus**: only for `mail_enabled` and `enterprise_mail`
- **Critical gap categories**: `mail_enabled`/`enterprise_mail` use core categories; `non_mail`/`web_only` use `['ssl', 'dnssec', 'http_security', 'subdomain_takeover', 'dane_https']`; `minimal` uses `['ssl', 'dnssec', 'subdomain_takeover']`
- **Authoritative DNS infra profile**: uses `['authoritative_dns_infra', 'dnssec', 'ns', 'zone_hygiene']` as critical gap categories and disables the email bonus.

### Phase 1 (Current)

Auto-detection runs, is reported in the structured result (`scoringProfile`, `scoringSignals`), and selects the weight table the domain is scored against: `scan_domain` always supplies a `DomainContext`, so weights come from `profileWeights` (defaults derived from `PROFILE_WEIGHTS`) on both the auto and the explicit path — never from `config.coreWeights`/`config.protectiveWeights`, which the scan path does not read at all. An explicit `profile` parameter overrides detection and adds a per-profile cache key (`cache:v<server-version>-dc<dns-checks-version>:<domain>:profile:<profile>`); the auto path uses the same key without the profile suffix.

Detection priority: `non_mail`/`web_only` (no MX or Null MX) -> `mail_enabled` (MX DNS failure safe fallback) -> `enterprise_mail` (MX + provider + hardening) -> `mail_enabled` (MX, default) -> `minimal` (>50% failed override). The `authoritative_dns_infra` profile is explicit-only.

Source: `packages/dns-checks/src/scoring/profiles.ts`.

### Authoritative DNS Infrastructure Profile

The `authoritative_dns_infra` category covers hostname and root-server evidence that normal DoH-only scans cannot observe directly: UDP/TCP 53 reachability, AA flag behavior, recursion refusal, zone-transfer refusal, direct DNSSEC material, EDNS0/TCP fallback behavior, abuse-resistance signals, IPv4/IPv6 parity, BGP origin/RPKI state, anycast/vantage evidence, PTR consistency, and root-server set conformance.

Two MCP tools populate this category:

- `check_authoritative_dns_infra` checks a hostname's authoritative DNS infrastructure posture.
- `check_root_server_set` checks the DNS root-server set against official root hints and, when available, live root evidence.

Both tools return structured partial results when `BV_INFRA_PROBE` is not configured. In that worker-only mode, raw DNS, BGP/RPKI, and vantage-dependent capabilities are marked inconclusive; `check_root_server_set` still returns the embedded official root-server names.

Source: `src/tools/check-authoritative-dns-infra.ts`, `src/tools/check-root-server-set.ts`, and `src/lib/authoritative-dns-infra/`.

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

`scan_domain` runs checks in parallel and includes non-mail-domain adjustment behavior when no MX records are present. Accepts an optional `profile` parameter (`auto`, `mail_enabled`, `enterprise_mail`, `non_mail`, `web_only`, `minimal`, `authoritative_dns_infra`) to control scoring weights. The `authoritative_dns_infra` profile runs only the authoritative infrastructure checks and merges their findings into one category result.

Source: `src/tools/scan-domain.ts`.

## Score Stability

### Per-request determinism

Given identical DNS and HTTPS inputs, the scoring engine is fully deterministic — the same inputs always produce the same score, grade, and findings. The scoring logic itself has zero non-determinism.

### Cross-request variance

Repeat scans of the same domain may occasionally produce different scores due to transient upstream failures:

- **DNS query timeouts** on slow authoritative servers
- **TLS handshake variance** (certificate fetches, DANE probes)
- **HTTP fetch failures** from CDN edge nodes, WAFs, or rate limiters
- **CDN header variance** across edge nodes serving different security header sets

### Stability mitigations in place

The scanner includes several layers of protection against transient variance:

1. **DNSSEC AD flag confirmation**: When the primary resolver reports "DNSSEC validation failing", a confirmation probe is fired to Google DoH. If Google confirms AD=true, the check re-runs with the corrected flag. See `src/tools/check-dnssec.ts`.
2. **HTTP security dual-fetch**: Two parallel HEAD requests are fired per domain, and the security headers are merged using union semantics before analysis. If a header appears in either response, it is counted as present. See `src/tools/check-http-security.ts`.
3. **Transient zero retry**: Any check that returns `score=0` with `checkStatus='error'` (a thrown DNS or HTTPS exception caught by `safeCheck()`) is retried once with a fresh DNS cache. Up to 3 retries per scan, capped at 3 seconds of the 15-second scan budget (`SCAN_TIMEOUT_MS`, env-overridable and clamped to 5–30 s). See `src/tools/scan-domain.ts`.

### Observed stability

Measured across 200 domains × 3 consecutive scans with `force_refresh`:

| Sample size | Concurrency | Drift rate |
|-------------|-------------|------------|
| 20          | 5           | 0%         |
| 50          | 3           | 0%         |
| 100         | 3           | ~5%        |
| 200         | 3           | ~8%        |

When drift occurs, it is typically ≤5 points in magnitude. Larger swings (15+ points) were observed only when multiple checks zeroed simultaneously due to transient failures — the retry fallback addresses this case.

### Remaining variance sources

A small percentage of scans will still drift due to:

- **Cross-request CDN header flap**: When a CDN serves different security headers to different requests over time (not just different edges within one request), the dual-fetch cannot fully compensate.
- **Finding-set drift on borderline checks**: Low-severity findings whose triggering conditions sit near a threshold.
- **Non-retryable deterministic checks**: Checks that internally swallow DNS errors and return an authoritative "not found" result cannot be distinguished from real absence, so they are not retried.

If consistent scoring is critical for your use case, run scans at concurrency ≤3 and prefer reading cached results (5-minute TTL) over forcing refresh on every query.
