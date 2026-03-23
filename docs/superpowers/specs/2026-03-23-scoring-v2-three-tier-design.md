# Scoring v2: Three-Tier Category Model

**Date**: 2026-03-23
**Status**: Approved
**Breaking**: Yes — score values change for all domains. Semver major bump (v2.0).

## Problem

The current scoring system answers "how close to perfect hardening?" when users expect "how secure is this domain?" This produces indefensible results: Amazon.com scores 58/D despite strong email auth, because aspirational controls (DNSSEC, DANE, BIMI, MTA-STS) that ~90% of the internet lacks drag down the composite score. Five systemic issues:

1. **DKIM selector probing false positives** — heuristic "No DKIM records found" zeros out DKIM (weight 16) and blocks the email bonus via `scoreIndicatesMissingControl()`, costing ~24 points for our own detection blind spot
2. **HTTP security headers contaminating email score** — missing CSP (weight 3, HIGH finding) penalizes email security grade for an unrelated web concern
3. **DNSSEC triple-counted** — 3 findings (HIGH + HIGH + MEDIUM = -65) for a single condition: "DNSSEC not enabled"
4. **Maturity staging too binary** — requires DKIM discovery + 2 hardening signals for Stage 4; Amazon lands at "Stage 1 — Basic"
5. **Score conflates risk with aspiration** — no distinction between "missing a critical defense" and "missing a nice-to-have hardening layer"

## Design

### Three-Tier Category Model

All 20 categories are classified into three tiers with distinct scoring mechanics, reflecting the 2026 threat landscape where AI has collapsed the cost of exploitation:

**Core (70% of score)** — Controls whose absence creates direct, exploitable risk:

| Category | Weight | Rationale |
|----------|--------|-----------|
| DMARC | 22 | Email auth — direct spoofing defense |
| DKIM | 16 | Email auth — message integrity |
| SPF | 10 | Email auth — sender authorization |
| DNSSEC | 7 | Trust anchor for all DNS-based controls. Without it, SPF/DMARC/DKIM can be undermined at the DNS layer via cache poisoning — now AI-automatable at scale |
| SSL | 5 | Transport security baseline |

Weighted accumulation: each category contributes `(score / 100) x weight` to `core_earned`. `core_max` is computed dynamically as the sum of the profile's Core weights (60 for `mail_enabled`, varies for other profiles). Allocation: `(core_earned / core_max) x 70`. The 70-point allocation is fixed; the denominator adapts to the profile.

`scoreIndicatesMissingControl()` applies within Core but only for `deterministic`/`verified` confidence findings (see Confidence Gate below).

**Protective (20% of score)** — Active defenses against known attack vectors. Mild penalty when absent, normal penalty for misconfiguration:

| Category | Weight | Rationale |
|----------|--------|-----------|
| Subdomain Takeover | 4 | AI-automated dangling CNAME exploitation at scale |
| HTTP Security | 3 | AI-crafted XSS/injection against headerless sites |
| MTA-STS | 3 | Active TLS downgrade prevention on inbound mail |
| MX | 2 | Mail routing integrity and redundancy |
| CAA | 2 | Certificate issuance control — prevents AI-driven misissuance |
| NS | 2 | DNS infrastructure integrity — foundation for everything |
| Lookalikes | 2 | AI-generated brand impersonation at scale |
| Shadow Domains | 2 | Alternate-TLD spoofing, automatable at scale |

`protective_max` is computed dynamically as the sum of the profile's Protective weights (20 for `mail_enabled`, varies for other profiles). Same weighted accumulation. No `scoreIndicatesMissingControl()` override — absence reduces points proportionally but never zeros out.

**Hardening (10% of score)** — Defense-in-depth signals. Bonus-only — can add points, never subtract:

| Category |
|----------|
| DANE |
| BIMI |
| TLS-RPT |
| TXT Hygiene |
| MX Reputation |
| SRV |
| Zone Hygiene |

Binary pass/fail per category. Each passed category (score >= 50) contributes `10 / hardening_count` points, where `hardening_count` is the number of Hardening categories (currently 7). 0 passed = 0 bonus, all passed = 10 bonus. The denominator must be dynamic so future Hardening category additions don't require formula changes.

### Score Formula

```
core_max       = sum(profile.coreWeights)                        (dynamic per profile)
protective_max = sum(profile.protectiveWeights)                  (dynamic per profile)
hardening_n    = count(hardening_categories)                     (currently 7)

core_pct       = core_earned / core_max                          (0.0 - 1.0)
protective_pct = protective_earned / protective_max              (0.0 - 1.0)
hardening_pts  = (passed_hardening_count / hardening_n) * 10     (0 - 10)

base = (core_pct * 70) + (protective_pct * 20) + hardening_pts

overall = clamp(base + email_bonus + provider_modifier - critical_penalty, 0, 100)
```

`core_max` and `protective_max` are computed from the active profile's weight tables — not hardcoded constants. The 70/20/10 point allocations are fixed; the denominators adapt so that a `web_only` profile with Core sum of 20 still allocates the full 70 points across its Core categories.

**70/20/10 split rationale:**
- Perfect Core alone → 70 (C+). Strong email auth gets you past failing but not to "good"
- Perfect Core + Perfect Protective → 90 (A). Well-secured domain threshold
- Hardening is the difference between A and A+ — never makes or breaks

**Email bonus** (simplified): Eligible when SPF score >= 57, DKIM not deterministically missing, DMARC present. Bonus is added directly to `overall` (no denominator expansion trick). Max possible = 105, clamped to 100. Three new config fields replace the single `emailBonusImportance`:

| Config field | Default | When |
|-------------|---------|------|
| `emailBonusFull` | 5 | DMARC score >= 90 |
| `emailBonusMid` | 3 | DMARC score >= 70 |
| `emailBonusPartial` | 2 | DMARC present but score < 70 |

The old `emailBonusImportance` field is **deprecated**. If present in a `SCORING_CONFIG` env var without the new fields, `parseScoringConfig()` maps it to: `emailBonusFull = emailBonusImportance`, `emailBonusMid = ceil(emailBonusImportance * 0.6)`, `emailBonusPartial = ceil(emailBonusImportance * 0.4)`. This preserves backward compatibility for existing custom configs.

**Critical gap ceiling**: Fires at 64, but only for SPF, DMARC, DKIM, and SSL with deterministic/verified confidence. DNSSEC is Core for weight but exempt from ceiling trigger. Protective and Hardening never trigger ceiling.

**Interaction penalties**: Same post-scoring layer as today (`category-interactions.ts`). The existing `strong_auth_no_dnssec` rule (DNSSEC = 0 AND DMARC >= 80 → -3) is **replaced** by a broader rule: `weak_dnssec_enforcing_dmarc` (DNSSEC <= 40 AND DMARC >= 80 → -3 penalty). This covers both "not enabled" (score ~85 after consolidation) and "broken chain" (score ~75) cases. The old rule is removed to prevent double-counting.

**Provider confidence modifier**: The existing `computeProviderConfidenceModifier()` function is preserved unchanged. It reads `finding.metadata.providerConfidence` (a per-finding 0-1 value set at runtime) and applies a ±5 point adjustment to `overall`. This is distinct from the new `providerDkimConfidence` config (a static per-provider trust table used during DKIM assessment).

### Confidence Gate

The core mechanical fix. `scoreIndicatesMissingControl()` currently regex-matches any high/critical finding containing "not found" and zeros the category. Changed to require deterministic/verified confidence:

```typescript
function scoreIndicatesMissingControl(findings: Finding[]): boolean {
    return findings.some(f => {
        const isMissingPattern = MISSING_CONTROL_REGEX.test(f.detail);
        const confidence = f.metadata?.confidence ?? inferFindingConfidence(f);
        return isMissingPattern
            && (f.severity === 'critical' || f.severity === 'high')
            && (confidence === 'deterministic' || confidence === 'verified');
    });
}
```

Heuristic DKIM "not found" no longer zeros the category or blocks email bonus. The category contributes whatever score was actually computed.

**Implementation note**: The confidence gate must NOT rely solely on `inferFindingConfidence()` text matching. All findings that represent heuristic detection must carry explicit `metadata.confidence: 'heuristic'` set at the source (`check-dkim.ts`). The `inferFindingConfidence()` fallback remains for legacy/third-party findings, but first-party findings must set confidence explicitly. Specifically, the "No DKIM records found among tested selectors" finding in `check-dkim.ts` must add `confidence: 'heuristic'` to its metadata object.

### Provider-Informed DKIM Detection

Cross-reference existing provider detection (`provider-signatures.ts`) with DKIM assessment:

**Provider-implied DKIM confidence**: When a provider known to sign DKIM is detected (via MX/SPF) but selector probing finds nothing:

| Provider signing confidence | DKIM finding | Category score |
|----------------------------|-------------|---------------|
| High (SES, SendGrid, Mailgun, Postmark) | Replace HIGH with `medium` finding — "DKIM selector not discovered; [provider] signs by default". Score: 85/100 (single medium = -15). Confidence: `heuristic` | 85/100 |
| Medium (Proofpoint, Mimecast) | Replace HIGH with `medium` finding + `low` finding — "DKIM selector not discovered; [provider] likely signs". Score: 80/100 (-15 + -5). Confidence: `heuristic` | 80/100 |
| None / unknown provider | Keep `high` finding (heuristic confidence). Score: 75/100 (-25). Not zeroed by confidence gate | 75/100 |

**Corroboration signal**: When a domain has DMARC at `quarantine`/`reject` with `rua=` reporting AND a known DKIM-signing provider, DKIM is treated as present-but-unverified. Operationally implausible to enforce DMARC without working DKIM.

### DNSSEC Finding Consolidation

Three findings for one condition (DNSSEC not enabled) consolidated:

| Condition | Finding | Severity |
|-----------|---------|----------|
| No DNSKEY + No DS + No AD (not enabled) | "DNSSEC not enabled" | MEDIUM |
| DNSKEY present but no DS (broken chain) | "DNSSEC chain of trust incomplete" | HIGH |
| DNSKEY + DS present but AD not set (failing) | "DNSSEC validation failing" | HIGH |

Rationale: Absence is the default state (~90% of domains). The weight (7) handles impact. Broken/failing deployments are worse than not starting and keep HIGH.

### Maturity Staging Redesign

| Stage | Criteria | Change |
|-------|----------|--------|
| 0 — Unprotected | `!hasSpf \|\| !hasDmarc` | No change |
| 1 — Basic | `hasSpf && hasDmarc && dmarcPolicyNone && !hasRua` | Narrowed — specifically "deployed but not watching" |
| 2 — Monitoring | `hasSpf && hasDmarc && dmarcPolicyNone && hasRua` | No change |
| 3 — Enforcing | `hasSpf && hasDmarc && (quarantine \|\| reject)` | **DKIM discovery no longer required**. Enforcement implies DKIM is working |
| 4 — Hardened | Enforcing + 2 of: DNSSEC, MTA-STS, DKIM discovered, CAA, BIMI, DANE | **Expanded signal list** — CAA and discovered DKIM added |

**"DKIM discovered"** means `foundSelectors.length > 0` in `check-dkim.ts` — at least one DKIM selector was found and its public key retrieved. This is distinct from the confidence gate (which affects scoring). Provider-implied DKIM does NOT count as "discovered" for maturity purposes — only actual selector verification qualifies.

### Scoring Profiles

Profiles adjust weights within tiers. The 70/20/10 point allocation is fixed across all profiles; the weight sums (denominators) vary per profile.

**`mail_enabled`** (default): Weights as documented above. Core sum = 60, Protective sum = 20.

**`enterprise_mail`**: Amplifies email auth and infrastructure controls.

| Tier | Weights | Sum |
|------|---------|-----|
| Core | DMARC 26, DKIM 18, SPF 10, DNSSEC 9, SSL 5 | 68 |
| Protective | Subdomain Takeover 5, HTTP Security 3, MTA-STS 4, MX 2, CAA 2, NS 2, Lookalikes 2, Shadow Domains 2 | 22 |

**`non_mail`**: Redistributes email auth weight to web/infrastructure controls.

| Tier | Weights | Sum |
|------|---------|-----|
| Core | SPF 2, DMARC 4, DKIM 2, SSL 8, DNSSEC 7 | 23 |
| Protective | Subdomain Takeover 6, HTTP Security 6, MTA-STS 1, MX 1, CAA 3, NS 3, Lookalikes 2, Shadow Domains 2 | 24 |

**`web_only`**: Zero email auth, maximizes web security controls.

| Tier | Weights | Sum |
|------|---------|-----|
| Core | SPF 0, DMARC 0, DKIM 0, SSL 12, DNSSEC 8 | 20 |
| Protective | Subdomain Takeover 6, HTTP Security 8, MTA-STS 0, MX 0, CAA 3, NS 3, Lookalikes 2, Shadow Domains 2 | 24 |

**`minimal`**: Minimal expectations — only transport security matters.

| Tier | Weights | Sum |
|------|---------|-----|
| Core | SPF 1, DMARC 1, DKIM 1, SSL 5, DNSSEC 2 | 10 |
| Protective | Subdomain Takeover 2, HTTP Security 2, MTA-STS 1, MX 1, CAA 1, NS 1, Lookalikes 1, Shadow Domains 1 | 10 |

Hardening tier categories and pass/fail mechanic are identical across all profiles.

**Ceiling triggers per profile:**
- `mail_enabled` / `enterprise_mail`: SPF, DMARC, DKIM, SSL
- `non_mail` / `web_only`: SSL, HTTP Security, Subdomain Takeover
- `minimal`: SSL

**Email bonus**: Only eligible in `mail_enabled` and `enterprise_mail`.

### Grade Boundaries

Recalibrated for the new score distribution. E grade removed.

| Grade | Score |
|-------|-------|
| A+ | >= 92 |
| A | >= 87 |
| B+ | >= 82 |
| B | >= 76 |
| C+ | >= 70 |
| C | >= 63 |
| D+ | >= 56 |
| D | >= 50 |
| F | < 50 |

### Projected Scores

| Domain | Old Score | Old Grade | New Score | New Grade |
|--------|----------|-----------|-----------|-----------|
| blackveilsecurity.com | 96 | A+ | ~95 | A+ |
| anthropic.com | 90 | A+ | ~84 | B+ |
| amazon.com | 58 | D | ~83 | B+ |
| cloudflare.com | 76 | B | ~80 | B+ |
| SPF+DMARC reject only | ~65 | C | ~55 | D |
| Nothing configured | ~15 | F | ~12 | F |

### ScoringConfig Extensibility

All new parameters are overridable via the `SCORING_CONFIG` env var:

```jsonc
{
  "tierSplit": { "core": 70, "protective": 20, "hardening": 10 },
  "coreWeights": { "dmarc": 22, "dkim": 16, "spf": 10, "dnssec": 7, "ssl": 5 },
  "protectiveWeights": { "subdomain_takeover": 4, "http_security": 3, ... },
  "grades": { "aPlus": 92, "a": 87, "bPlus": 82, "b": 76, ... },
  "providerDkimConfidence": { "amazonses": 0.8, "sendgrid": 0.8, ... }
}
```

### ScoringConfig Migration

The `SCORING_CONFIG` env var schema changes. `parseScoringConfig()` must handle both old and new shapes:

| Old field | New field(s) | Migration |
|-----------|-------------|-----------|
| `weights` (flat, all 20 categories) | `coreWeights` + `protectiveWeights` | If `weights` is present and `coreWeights`/`protectiveWeights` are absent, partition `weights` into Core/Protective based on the tier classification. Categories not in Core or Protective are ignored (Hardening is bonus-only). |
| `emailBonusImportance` (single number) | `emailBonusFull`, `emailBonusMid`, `emailBonusPartial` | If old field present without new fields: `full = value`, `mid = ceil(value * 0.6)`, `partial = ceil(value * 0.4)` |
| `profileWeights` (flat per profile) | `profileWeights` (structured per tier per profile) | If old flat shape detected, partition same as `weights` |
| (new) `tierSplit` | — | Defaults to `{ core: 70, protective: 20, hardening: 10 }`. Must sum to 100. |
| `grades.e` | Removed | Silently ignored if present |

### Post-Processing Interaction with Tiers

`adjustForNonMailDomain()` in `post-processing.ts` currently downgrades SPF/DMARC/DKIM/MTA-STS findings to `info` severity for non-mail domains. Under the three-tier model:

- For `non_mail`/`web_only` profiles: `adjustForNonMailDomain()` still fires, but its impact is naturally reduced because SPF/DMARC/DKIM have minimal Core weights (2/4/2 and 0/0/0 respectively). The downgrade remains useful to prevent even those small weights from penalizing non-mail domains.
- For `mail_enabled` with no MX detected: The auto-detection logic in `detectDomainContext()` should switch to `non_mail` profile before scoring, which redistributes weights appropriately. `adjustForNonMailDomain()` then applies as a secondary defense-in-depth measure.
- No structural changes to `adjustForNonMailDomain()` needed — it operates on findings, not weights.

### Exports and Backward Compatibility

- `IMPORTANCE_WEIGHTS` in `scoring-engine.ts`: **Deprecated and renamed** to `LEGACY_IMPORTANCE_WEIGHTS`. Kept as a read-only export for any external consumers. New code uses `CORE_WEIGHTS`, `PROTECTIVE_WEIGHTS`, and `CATEGORY_TIERS` exports.
- `scoreToGrade()`: Remove the `E` grade branch and the `grades.e` field from `ScoringConfig`. Scores 50-54 now map to `D` instead of `E`.
- `computeScanScore()`: Signature unchanged — still accepts `(results, context?, config?)`. Internal mechanics change but the return type `ScanScore` is preserved.

### Test Impact

Tests requiring full revision:

| Test file | Changes |
|-----------|---------|
| `test/scoring-engine.spec.ts` | All score expectations change. Add tests for: three-tier accumulation, confidence gate on `scoreIndicatesMissingControl()`, dynamic `core_max`/`protective_max` per profile, hardening bonus calculation, email bonus new fields, E grade removal |
| `test/scoring-profiles.spec.ts` | All profile weight assertions change to new tier-structured tables |
| `test/maturity-staging.spec.ts` | Remove "DKIM required for Stage 3" assertion. Add: "DKIM not required for Stage 3 with DMARC enforce", "CAA counts as Stage 4 hardening signal", "DKIM discovered counts as Stage 4 hardening signal" |
| `test/check-dkim.spec.ts` | Add: provider-implied DKIM tests (SES detected → medium finding, no provider → high heuristic), confidence metadata explicitly set |
| `test/check-dnssec.spec.ts` | Consolidated finding tests: "not enabled" → single MEDIUM, "broken chain" → HIGH, "failing" → HIGH |
| `test/category-interactions.spec.ts` | Replace `strong_auth_no_dnssec` with `weak_dnssec_enforcing_dmarc`, verify no double-count |
| `test/scoring-config.spec.ts` | Add: old `weights` → new `coreWeights`/`protectiveWeights` migration, `emailBonusImportance` → three-field migration, `tierSplit` validation (must sum to 100) |
| `test/scan-domain.spec.ts` | Score expectations change for all scan test cases |

## Files to Modify

| File | Change |
|------|--------|
| `src/lib/scoring-engine.ts` | Three-tier formula, new `computeScanScore()`, updated `scoreIndicatesMissingControl()` with confidence gate, `CORE_WEIGHTS`/`PROTECTIVE_WEIGHTS`/`CATEGORY_TIERS` exports, deprecate `IMPORTANCE_WEIGHTS` → `LEGACY_IMPORTANCE_WEIGHTS`, remove E grade from `scoreToGrade()`, replace `strong_auth_no_dnssec` interaction |
| `src/lib/scoring-model.ts` | Tier classification type (`CategoryTier: 'core' | 'protective' | 'hardening'`), updated `CATEGORY_DISPLAY_WEIGHTS` with tier metadata |
| `src/lib/scoring-config.ts` | New config fields: `tierSplit`, `coreWeights`, `protectiveWeights`, `emailBonusFull/Mid/Partial`, `providerDkimConfidence`. Deprecation migration for `weights`, `emailBonusImportance`, `profileWeights`. Remove `grades.e`. Updated `DEFAULT_SCORING_CONFIG` and `parseScoringConfig()` |
| `src/lib/context-profiles.ts` | Profile weights restructured per tier (complete tables for all 5 profiles). `PROFILE_CRITICAL_CATEGORIES` updated |
| `src/lib/category-interactions.ts` | Replace `strong_auth_no_dnssec` with `weak_dnssec_enforcing_dmarc` (DNSSEC <= 40 AND DMARC >= 80 → -3) |
| `src/tools/check-dkim.ts` | Provider-informed DKIM inference. Explicit `metadata.confidence: 'heuristic'` on "not found" finding. Severity downgrade for provider-implied presence |
| `src/tools/check-dnssec.ts` + `dnssec-analysis.ts` | Finding consolidation — single MEDIUM for "not enabled", HIGH for broken/failing |
| `src/tools/scan-domain.ts` | Pass provider detection results to DKIM assessment |
| `src/tools/scan/maturity-staging.ts` | Redesigned stage criteria. Remove DKIM requirement for Stage 3. Add CAA and DKIM-discovered as Stage 4 signals |
| `src/tools/scan/post-processing.ts` | Verify `adjustForNonMailDomain()` works correctly with tier-based weights (no structural change expected) |
| `src/handlers/tool-schemas.ts` | Remove E grade from schema descriptions |
| `CLAUDE.md` | Updated scoring documentation — tier model, new weights, grade boundaries, maturity criteria |
| `README.md` | Updated grade table, remove E grade |
| `docs/scoring.md` | Full scoring v2 documentation |
| Tests | See Test Impact section above for complete list |
