---
name: bv-mcp-scoring
description: "Use when changing the bv-mcp / blackveil-dns scoring model — category weights, profiles, grade thresholds, the passed/missing-control rule, or the score computation in packages/dns-checks/src/scoring. Symptoms: a category scores 0 unexpectedly, a grade boundary is off, profileWeights mismatch errors, or an inconclusive check zeroing a score."
---

# bv-mcp Scoring Changes

Scoring lives in `packages/dns-checks/src/scoring/` (runtime-agnostic core, published separately). The model is three-tier and a single weight change must stay consistent across **5 files** or `config`/`profiles` audits fail.

## ⚠️ Cross-repo SoT — bv-web-prod consumes this package

`@blackveil/dns-checks` (the check classifiers + scoring engine) is the cross-repo source of truth for **bv-web-prod too** — it consumes the package rather than reimplementing it, so the two scanners can't diverge. Changing a classifier (or the scoring config) is therefore a **cross-repo change**:

1. **bv-mcp is canonical — land + deploy here first.** Never let bv-web-prod ship a scoring change ahead of bv-mcp (else it emits findings bv-mcp doesn't → fresh divergence).
2. **Until `@blackveil/dns-checks` is published, bv-web-prod pins a vendored tarball** (`vendor/blackveil-dns-checks-1.3.16.tgz` as of 2026-06; pinned to the exact version old bv-web ran for score parity at cutover). After a scoring change: in `packages/dns-checks/` run `npm run build && npm pack`, copy the `.tgz` into bv-web-prod `vendor/`, repoint its `file:` dep, `npm install`, then run bv-web-prod's parity guard `shared/lib/scan/parity.contract.test.ts` (it asserts the consumed package against its own exported `*_PARITY_FIXTURES`; mirrors bv-mcp's `parity-corpus.contract.test.ts`). bv-web-prod `vendor/README.md` has the recipe. Skipping the re-vendor silently drifts the repos apart — the parity guard only fires once it re-installs.
3. **bv-web-prod consumes the FULL package**: `shared/lib/scan/scan-engine.server.ts` is a thin orchestrator that runs the package's check functions and folds results through `computeProfileAwareScanScore` — do not reimplement scoring there. (The old "only DMARC wired" partial-delegation state and its divergence-matrix spec belonged to retired bv-web; the spec was not carried into bv-web-prod's `docs/superpowers/specs/`.) Note: async, DNS-dependent findings (e.g. DMARC RUA-authorization) live in the bv-mcp check *wrapper*, not the pure classifier — a documented bounded-non-parity consumers can't reproduce. Also note the customer-facing grade is now consolidated to **ONE letter — the NIST 6-band scale (A+≥95, A≥90, B≥80, C≥70, D≥60, F<60)** — across BOTH repos (bv-web #759 + bv-mcp #461/v3.26.0, LIVE 2026-06-29). `@blackveil/dns-checks` 1.4.0+ exports `nistScoreToGrade`/`NIST_GRADE_THRESHOLDS` (additive) alongside the canonical 9-band `scoreToGrade` (`shared/lib/score/bands.ts`). The 9-band is **retained for non-display only** — engine contract, golden tests, cohort/MCP-benchmark, `compare_baseline` ordering, `/badge`, drift/compliance/fix-plan — so do NOT delete it. A package bump must move `PARITY_CORPUS_VERSION` (bv-mcp `parity-fixtures.ts`) AND bv-web's `VENDORED_VERSION` (`parity.contract.test.ts`) in lockstep, and bv-web's `nist-grade-parity.contract.test.ts` drift-guard asserts both repos' NIST cut-points stay identical.

## The three tiers (`computeScanScore`)

- **Core (70%)**: DMARC 16, DKIM 10, SPF 10, DNSSEC 10, SSL 8 (representative `mail_enabled` profile — every core weight is per-profile; e.g. DNSSEC 5–20, SSL 7–14).
- **Protective (20%)**: Subdomain Takeover 4, HTTP Security 3, MTA-STS 3, MX 2, CAA 2, NS 2, Lookalikes 2, Shadow Domains 2.
- **Hardening (10%, bonus-only)**: DANE, BIMI, TLS-RPT, TXT Hygiene, MX Reputation, SRV, Zone Hygiene (~1.4 pts each).

`CATEGORY_DISPLAY_WEIGHTS` (defined in `types.ts`, re-exported from `model.ts`) is **display-only** — changing it does not change the score. The live `scan_domain` score comes from **`PROFILE_WEIGHTS`** (`profiles.ts`, selected by `detectDomainContext`); the no-context fallback uses `config.coreWeights`/`config.protectiveWeights`. `IMPORTANCE_WEIGHTS` (`engine.ts`) is **not** score-bearing — it only ranks findings in `generate_fix_plan`. Keep all three consistent so the metadata doesn't drift from the live weight.

## Changing a weight — touch all of these (create a TodoWrite item each)

1. `types.ts` — `CheckCategory` union + `CATEGORY_DISPLAY_WEIGHTS` (display); model.ts only re-exports these.
2. `engine.ts` — `IMPORTANCE_WEIGHTS` (fix-plan finding ordering, NOT the score) + the `@deprecated` `CORE_WEIGHTS`.
3. `config.ts` — `DEFAULT_SCORING_CONFIG`: `weights`, `profileWeights` (**all 6 profiles**), `baselineFailureRates`.
4. `profiles.ts` — `PROFILE_WEIGHTS` (**all 6 profiles**: `mail_enabled`, `enterprise_mail`, `non_mail`, `web_only`, `minimal`, `authoritative_dns_infra`).
5. Grade thresholds, if touched, in the grades config.

Runtime override path: `SCORING_CONFIG` env (JSON: `weights`, `profileWeights`, `thresholds`, `grades`, `baselineFailureRates`), parsed via memoized `parseScoringConfigCached()`. Don't bypass it.

## Rules that bite (verify against these, don't reinvent)

- **`passed` = `score >= 50 && !hasMissingControl`.** A missing control zeroes the category. Checks that emit `missingControl: true`: CAA, DNSSEC, HTTP Security, MTA-STS, MX, SVCB-HTTPS, NS, Zone Hygiene, BIMI, DANE, TLS-RPT.
- **Confidence gate** — `scoreIndicatesMissingControl()` fires only for `deterministic`/`verified`. A *heuristic* DKIM "not found" must NOT zero the category.
- **Inconclusive ≠ failure.** Timeout/error checks (`checkStatus`) are **excluded** from the score (collected as `transientFailures`, score renormalized) and shown `n/a`. A category absent from `categoryScores` means "couldn't measure", not 0. Don't "fix" this by scoring it 0.
- **Severity penalties**: C −40, H −25, M −15, L −5, Info 0.
- **Grades**: A+ 92+, A 87–91, B+ 82–86, B 76–81, C+ 70–75, C 63–69, D+ 56–62, D 50–55, F <50.
- **Email bonus**: SPF ≥57, DKIM not deterministically missing, DMARC present → +5/+3/+2 by DMARC score.
- **Maturity staging** (`computeMaturityStage`, 0–4): score caps stage — F → ≤2, D/D+ → ≤3. Stage 3 doesn't require DKIM.

## Adaptive weights (optional layer)

EMA per profile+provider via `ProfileAccumulator` DO, blended only past `MATURITY_THRESHOLD = 200` samples; falls back to static weights if the DO is unavailable. Don't assume adaptive weights are active in tests.

## Verify

```bash
npx vitest run packages/dns-checks   # scoring unit tests
npm test                              # config/profiles parity audits live in the full suite
```

If you changed a weight, expect golden/snapshot score assertions to move — review the diff rather than blindly updating snapshots. All four scoring spec families (`model`, `profiles`, `config`, `engine`) keep their snapshots + assertions **once** in `packages/dns-checks/src/__tests__/scoring/scoring-<name>.suite.ts` (run against both the SOURCE and BUILT module via thin `.spec.ts` wrappers in that dir and in `test/`) — edit the `.suite.ts`, not the wrappers.

## Red flags

- Changed `CATEGORY_DISPLAY_WEIGHTS` and expected the score to move → that's display-only; change `IMPORTANCE_WEIGHTS` + config.
- Updated `weights` but not `profileWeights` in all 6 profiles → parity audit fails.
- An inconclusive/timeout check showing as a 0 in your output → it should be `n/a` and excluded; you broke renormalization.

## Provenance

Moved here from the fleet-global `bv-cc` skills library (`~/.claude/skills/`) on 2026-08-03. It is bv-mcp-specific, so as a global skill its description competed for context in every session on every repo — including repos it can never apply to. Scoping it to this repo is the "scope skills to specific paths so they only activate in the relevant part" rule from Anthropic's large-codebase guidance.

Keep it here. If a fact in it turns out to be cross-repo (a seam bv-web-prod also depends on), the cross-repo half belongs in `fleet-architecture`, not back in the global library.
