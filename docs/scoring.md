# Scoring Methodology

Canonical scoring reference for `scan_domain` results. Describes scoring model 2.0.0 (see [Scoring model 2.0.0](#scoring-model-200)).

## Scoring model 2.0.0

Scoring model 2.0.0 is a major version because score semantics change. What changed:

- The tier split is core 75 / protective 25. The hardening tier is empty, and every former hardening category is protective with an explicit per-profile importance.
- The hardening pass-rate pool is removed.
- The flat critical-finding overall penalty is removed from the default model (default 0; the config key remains for explicit overrides).
- The email bonus is removed from the default model (default 0; the config keys remain for explicit overrides).
- The MCP-only interaction-penalty layer is removed from `scan_domain`; `interactionEffects` is retained in output and is always `[]`.

What did not change: the critical-gap ceiling (64), the partial-enforcement ceiling (94), the evidence gate, null/UNGRADED abstention, and profile detection.

Direction of grade movement, qualitatively: domains that previously relied on the email bonus or on a large hardening pass count to lift their score will generally grade lower, since those lifts are gone. Domains that were pulled down by the flat critical penalty or by interaction penalties will generally grade higher. Domains with strong core controls and no critical gaps move least. A domain missing DMARC still caps at 64. Scores from before and after 2.0.0 are not directly comparable; compare scans only within one scoring model version.

## What this score measures — and what it does not

The score rates **externally observable DNS, email-authentication, and TLS configuration** for a domain. Everything it grades is published in DNS or served over TLS, so a scan is passive and needs no access to the organization being scanned.

Read the result as **brand-protection and deliverability posture**, because that is what the controls do. SPF, DKIM, and DMARC largely protect _recipients_ — and your brand's reputation — from your domain being used to send mail it did not authorize. They are a third-party benefit before they are a self-protective one.

**Out of scope**, and therefore invisible to any grade here:

- Endpoint, identity, and application security; MFA posture; patch state
- Account takeover, and lateral business-email compromise sent from a legitimate internal mailbox — such mail authenticates correctly and passes DMARC
- Impersonation from an attacker-controlled _lookalike_ domain, which carries its own valid SPF/DKIM/DMARC (we surface lookalikes separately; a domain's own grade cannot reflect them)
- Mail sent from free webmail providers, which authenticates under the provider's domain
- Response-based social engineering that carries no link or attachment
- Anything outside email and DNS entirely

**This score is not a breach-likelihood prediction.** No published dataset establishes a correlation between these DNS/email controls and incident rates, in either direction, and we do not claim one. A domain can hold an A+ here and be compromised through any of the vectors listed above.

Use it for what it supports: comparing posture across domains on a consistent basis, evidencing configuration for audit and compliance, and prioritizing concrete, fixable DNS and email-authentication defects.

## Category Tier Model (scoring model 2.0.0)

Categories are classified into tiers. The default `tierSplit` is **core 75 / protective 25 / hardening 0**. The hardening tier is empty (see below).

### Core (75% of score)

Controls whose absence creates direct, exploitable risk. Missing-control rule applies (confidence-gated).

Importance by profile (generated from `PROFILE_WEIGHTS`):

| Category                  | `mail_enabled` | `enterprise_mail` | `non_mail` | `web_only` | `minimal` | `authoritative_dns_infra` |
| ------------------------- | -------------: | ----------------: | ---------: | ---------: | --------: | ------------------------: |
| `dmarc`                   |             16 |                20 |          3 |          3 |         1 |                         0 |
| `dkim`                    |             10 |                12 |          2 |          0 |         1 |                         0 |
| `spf`                     |             10 |                10 |          2 |          2 |         1 |                         0 |
| `dnssec`                  |             10 |                13 |         12 |         14 |         5 |                        20 |
| `ssl`                     |              8 |                 8 |         10 |         14 |         7 |                         0 |
| `authoritative_dns_infra` |              0 |                 0 |          0 |          0 |         0 |                        40 |

> **Core weights are per-profile.** The values come from `PROFILE_WEIGHTS` (`packages/dns-checks/src/scoring/profiles.ts`), which is the single source of weight values — `scan_domain` always scores through one of the six profile tables. A weight is only meaningful alongside the profile that selected it.
>
> **Correction (2026-08):** an earlier revision listed a different set here (DMARC 22, DKIM 16, DNSSEC 7, SSL 5) as "production weights set via `SCORING_CONFIG`". Those were a `coreWeights` override, and `coreWeights` is **not read on the `scan_domain` path**: `buildGenericContext()` consults it only in the branch taken when no domain context is supplied, and `scan_domain` always supplies one. Such an override parses, validates, and changes the effective-config hash while changing no score. Weight overrides must be expressed as `SCORING_CONFIG` → `profileWeights.<profile>`; `coreWeights`/`protectiveWeights` survive only because `ScoringConfig` is a published npm surface, and an inert key now emits a warning.
>
> The authoritative DNS category is core for classification and display, but it is weighted 0 in every profile except `authoritative_dns_infra` (where it is 40), so raw infrastructure evidence does not shift ordinary `scan_domain` scores unless the dedicated profile is selected.

**Confidence gate**: `scoreIndicatesMissingControl()` only fires for `deterministic`/`verified` confidence findings. Heuristic "not found" results from selector probing do not zero the category.

### Evidence sufficiency

A scan must complete at least **60%** of its attempted checks to receive a grade. Below
that, `scan_domain` returns `score: null` / `grade: null` with `evidenceInsufficient: true`
and a plain-English `evidenceNote`, rendered as `not measured`. Findings and per-category
scores for the checks that _did_ run are still returned.

Every scan — graded or not — reports `evidence: { attempted, completed, ratio }` so a
reader can see the scan's own coverage. The threshold is a single constant
(`EVIDENCE_SUFFICIENCY_THRESHOLD` in `@blackveil/dns-checks`), overridable via
`SCORING_CONFIG` → `thresholds.evidenceSufficiency` and clamped to `[0, 1]`.

This is not a scoring cut-point: it changes only whether a grade is emitted, never what
an emitted grade means. Two states stay strictly separate — **inconclusive** ("we could
not measure it", `inconclusiveCategories`) and **not applicable** ("we measured, and it
genuinely does not apply", `notApplicableCategories`). As of dns-checks 1.7.0 those two
arrays are **disjoint**; read the union as the concatenation of both.

A probe that never reached the origin is inconclusive, never a missing control: a WAF that
blocks or challenges the MTA-STS policy fetch, and a check that exhausts its total time
budget before reading a response, both exclude their category from the score and let the
remaining weights renormalize, rather than zeroing it as a measured absence. The reported
detail says only what was observed. In particular it does **not** claim that real sending
MTAs are unaffected by an edge rule that stopped this scanner: a sending MTA is an
automated, non-browser client of the same shape, so a rule aimed at automated clients as a
class would stop it too. Whether a given rule targets this scanner specifically or
automated clients generally is not observable from outside, and is left stated as open.

Coverage is surfaced wherever a grade is: `scan_domain` prints a `Checks completed: N/M`
line, and the `/badge` SVG appends `partial` to the letter — with the exact ratio in its
hover/aria title — when a graded scan did not complete every check. A badge embedded in a
README carries no surrounding prose to qualify it, so a bare letter there would invite a
partial measurement to be read as a complete one. The grade and its colour are unchanged by
partial coverage: coverage and posture are different axes, and dimming the badge would
assert a worse result than was actually measured.

### Protective (25% of score)

Active defenses against known attack vectors, plus the former hardening categories (see below).

> **Correction (2026-08):** an earlier revision of this line claimed Protective findings "cannot trigger missing-control zeroing." That was wrong. Protective checks can set explicit `missingControl: true` and therefore zero their category: today **MX** (no MX and no SPF), **NS** (no records), **Shadow Domains** (a variant with MX but no SPF and no DMARC) and **MTA-STS** (a deployed policy failing conformance). HTTP Security, named here in that earlier revision, no longer sets it. See [Missing-Control Rule](#missing-control-rule) for the authoritative list. What is true of the Protective tier is that a zeroed category costs at most its own weight (2–4 points) rather than the much larger Core-tier contribution.
>
> **MTA-STS was the fourth on that list and no longer is (scoring model 1.6.0).** Its absence now scores as a graded `medium` rather than zeroing the category. A 1,000-domain corpus scan (2026-08-03) measured `mta_sts` at a mean score of 3.3 with 96.5% of the 687 measured domains at exactly 0 — a control almost nobody deploys separates nobody, so it was acting as a flat constant penalty rather than a discriminator. A deployed-but-broken MTA-STS policy still produces its confident `high`/`medium` findings; only absence changed.

Importance by profile (generated from `PROFILE_WEIGHTS` and `CATEGORY_TIERS`; categories with importance 0 in every profile are listed below the table):

| Category             | `mail_enabled` | `enterprise_mail` | `non_mail` | `web_only` | `minimal` | `authoritative_dns_infra` |
| -------------------- | -------------: | ----------------: | ---------: | ---------: | --------: | ------------------------: |
| `subdomain_takeover` |              4 |                 5 |          6 |          6 |         2 |                         0 |
| `http_security`      |              3 |                 3 |          6 |          8 |         2 |                         0 |
| `mta_sts`            |              3 |                 4 |          1 |          0 |         1 |                         0 |
| `mx`                 |              2 |                 2 |          1 |          1 |         1 |                         0 |
| `caa`                |              2 |                 2 |          3 |          3 |         1 |                         0 |
| `ns`                 |              3 |                 3 |          3 |          3 |         1 |                        15 |
| `dane`               |              2 |                 2 |          0 |          0 |         0 |                         0 |
| `tlsrpt`             |              2 |                 2 |          0 |          0 |         0 |                         0 |
| `zone_hygiene`       |              0 |                 0 |          0 |          0 |         0 |                        10 |
| `dane_https`         |              2 |                 2 |          2 |          2 |         0 |                         0 |
| `svcb_https`         |              1 |                 1 |          1 |          1 |         0 |                         0 |
| `subdomailing`       |              3 |                 4 |          1 |          0 |         1 |                         0 |
| `dnskey_strength`    |              0 |                 0 |          0 |          0 |         0 |                         2 |

Importance 0 in every profile: `lookalikes`, `shadow_domains`, `ptr`, `bimi`, `txt_hygiene`, `mx_reputation`, `srv`, `brand_discovery`, and the non-scoring categories (`web_content`, `csp_quality`, `hsts_preload`, `http_redirect`, `security_txt`, `cert_posture`). `lookalikes` and `shadow_domains` were nonzero before 2.0.0; neither scan roster submits them, so a nonzero weight was a latent coupling.

> Protective weights are per-profile; the legacy flat `protectiveWeights` map is not read on the scan path. The normalised tier share is 25 of 100 by default (`tierSplit`), and the engine normalises the tier by its actual weight sum.

### Hardening (empty since 2.0.0)

The Hardening tier no longer scores anything: its default `tierSplit` share is `0`. Before 2.0.0 it was a binary, pass-count bonus pool divided across the hardening roster, so adding or dropping one check re-divided every other check's share. Every former hardening category (DANE, BIMI, TLS-RPT, TXT Hygiene, MX Reputation, SRV, Zone Hygiene, Brand Discovery, Reverse DNS, DNSKEY Strength) is now a **Protective** category with an explicit per-profile importance. The `hardening` value stays in the published `CategoryTier` type and the `tierSplit` config key for compatibility.

Most former hardening categories carry importance `0` in the scan profiles. Only TLS-RPT and DANE weigh anything (2 each, in the two mail profiles). Reverse DNS and DNSKEY Strength are `0` in the mail profiles so the MCP scan, which submits those two checks, grades a domain the same as a roster that does not. `authoritative_dns_infra` keeps Zone Hygiene at 10 and weighs DNSKEY Strength at 2.

**Tool Annotations**: Every tool definition includes `group`, `tier` (`core` or `protective`; `hardening` is still a valid value but no category uses it), and a `scanIncluded` flag. These annotations align with the category tiers above and are included in `tools/list` responses for structured consumption by MCP clients.

Source: `CATEGORY_TIERS` in `packages/dns-checks/src/types.ts`; `computeScanScore()` (bridge) in `packages/dns-checks/src/scoring/engine.ts`.

## Generic Scoring Engine

The core scoring logic has been refactored into a **Generic Scoring Engine**. This engine is decoupled from concrete DNS check types, allowing for arbitrary string-keyed categories and tiers.

- **String-keyed inputs**: Accepts `categoryScores` as a `Record<string, number>`, making it runtime-agnostic and easy to port to other languages.
- **Tier formula**: Implements the Core/Protective tier logic (the Hardening tier is empty since 2.0.0) as a pure functional transformation.
- **Single Source of Truth**: The `computeScanScore` function in the main package now serves as a thin bridge that maps `CheckResult[]` into the `GenericScoringContext`.

Source: `packages/dns-checks/src/scoring/generic.ts`.

## Per-Finding Severity Penalties

Category score formula starts at `100` and deducts per finding:

- Critical: `-40`
- High: `-25`
- Medium: `-15`
- Low: `-5`
- Info: `0`

**SPF `~all` Severity Rule** (scoring model 1.24.0, #927): the severity of an SPF soft-fail (`~all`) finding is set by the domain's DMARC policy. With an explicit `p=none` (or a DMARC record that omits the `p=` tag, which `check_spf` reads as `none`), `~all` is `info` (0 penalty) — soft fail is the expected interim posture while legitimate senders are inventoried from aggregate reports. With an enforcing policy (`p=quarantine` or `p=reject`, any `pct`), `~all` is `low` (−5) with a recommendation to move to `-all` once senders and forwarding paths are validated: DMARC enforcement guides receiver handling but does not guarantee rejection, so `-all` remains the recommended terminator. With no DMARC record (or an unreadable one), `~all` is `low` (−5). The earlier rule that lowered `~all` to `info` _under_ DMARC enforcement was inverted and has been removed (#909).

**DMARC `pct` Parsing**: The `pct` (percentage) parameter is parsed from DMARC records to determine the true enforcement context. If `pct < 100`, the enforcement is considered partial, which may affect how related findings (like SPF trust surface) are weighed.

**SPF Trust-Surface Corroboration Rule**: an SPF `include:`/`redirect=` naming a multi-tenant sending platform is reported at `info` severity (0 penalty) — shared sending infrastructure is common and not a misconfiguration in itself. The **per-platform findings are always informational**; the scored signal for the whole trust surface is the single "N shared platforms" summary finding (emitted only when more than one shared sender matches), which is raised to `high` when the domain's DMARC corroborates the exposure: enforcement short of `p=reject` at `pct=100` **and** relaxed alignment (`aspf`/`adkim` not both `s`). A missing DMARC record counts as corroborating; a failed DMARC lookup does not.

Two kinds of delegation count toward that total. A target matching the **catalog** of known multi-tenant platforms is named by brand; a target the catalog does not recognize still counts when its hostname carries an `spf` / `_spf` / `spfNN` label — a naming convention that identifies a shared SPF-delegation endpoint regardless of provider — and is named by host, marked `(unrecognized)`. First-party hosts such as `mail.example.com` do **not** match and are never counted, which is why the rule keys on the label rather than on "any external include".

Scoring model 1.10.0 brought the published `@blackveil/dns-checks` package into line on that count (issue #572, part 2). The analyzer exists in two copies — the core package and a worker-side wrapper — and only the worker copy had been counting uncataloged `spf`-labelled senders. The two therefore disagreed about `platformCount` and about whether the scored summary finding fired at all, so a domain delegating to one cataloged platform plus one uncataloged sender was a two-platform trust surface to `scan_domain` and a one-platform, un-summarized one to anything calling the package directly. The core now applies the same rule.

This is the one trust-surface change that can move a score **downward**, and by at most one severity step. Because the per-platform findings carry no penalty, an uncataloged sender can only matter by pushing the total across the two-delegation threshold — so the affected shape is exactly one cataloged platform plus at least one uncataloged `spf`-labelled include, or two or more uncataloged ones. Where weak DMARC also corroborates, the summary is `high`, taking the `spf` category from 100 to 75: measured at ≈3 points of overall score on a healthy 19-category `mail_enabled` roster (97 → 94). Uncorroborated, the summary is `info` and the score does not move at all. Domains already at two or more cataloged platforms gain a larger `platformCount` and longer prose but no new penalty, and domains with no shared senders are untouched. **What share of real-world domains matches the affected shape has not been measured** — it was not characterized against the 1,000-domain corpus. No weight, tier, grade band, severity penalty, missing-control rule or corroboration rule changed, and no score is recomputed retroactively: a domain re-grades on its next scan.

Scoring model 1.8.0 removed a **double count** here (issue #637). The per-platform findings used to be raised to `medium` (−15 each) alongside the summary's `high` (−25) — two penalties for one condition, stacking linearly with the number of includes. A domain delegating to six platforms paid −115 and its `spf` category clamped to **0, the same score a domain with no SPF record at all receives**, so the category could not discriminate between a well-run complex sender profile and a missing control. Only the summary is scored now. The per-platform findings remain present and fully detailed — the same corroboration prose and `dmarcCorroborated` / `dmarcPolicy` / `dmarcAlignmentMode` metadata — so a report still shows exactly which platforms are authorized and why each matters. Measured impact on the `spf` category, all **upward**: 0 / +15 / +30 / +60 / +75 points at 0 / 1 / 2 / 4 / 6 corroborated shared platforms, with every multi-platform domain converging on 75 for the trust surface alone. No weight, tier, grade band, severity penalty, missing-control rule or corroboration rule changed, and a domain that publishes no SPF record still scores 0.

Scoring model 1.7.0 added Mailjet to the platform catalog, so a record whose only recognized shared sender is Mailjet now counts toward the platform total instead of producing no catalog match at all. Under 1.8.0 that affects the `platformCount` on the summary finding rather than a per-platform penalty.

Source: `SEVERITY_PENALTIES` in `packages/dns-checks/src/scoring/model.ts` (re-exported via `src/lib/scoring.ts`); `analyzeTrustSurface()`, `MULTI_TENANT_PLATFORMS` and `GENERIC_SHARED_SENDER_RE` in `packages/dns-checks/src/checks/spf-trust-surface.ts`. The current model version and a per-version record of what each change moved are kept in `SCORING_MODEL_VERSION` in `src/lib/scoring-version.ts`.

## Missing-Control Rule

Two mechanisms detect missing controls in `buildCheckResult`:

1. **Confidence-gated detection** (`scoreIndicatesMissingControl()`): For findings matching missing-control text patterns (e.g., "no … record", "missing", "not found") with `critical`/`high` severity and `deterministic`/`verified` confidence. This prevents heuristic findings (e.g., DKIM selector probing) from falsely zeroing core categories.

2. **Explicit metadata** (`missingControl: true`): For checks that measured the control and found it absent, or absence-equivalent. Set by eleven scored categories — and several of them on a condition that is _not_ plain absence:

   | Category                  | Fires when                                                                                                                                                                       |
   | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
   | SPF                       | No valid `v=spf1` TXT record at all.                                                                                                                                             |
   | MX                        | No MX **and** no SPF. An SPF publishing `-all` is the correct non-mail posture and does **not** fire.                                                                            |
   | NS                        | No NS records (the domain cannot resolve).                                                                                                                                       |
   | Zone Hygiene              | No NS records, or no SOA record.                                                                                                                                                 |
   | DANE                      | No TLSA for the MX SMTP port, or none for the HTTPS endpoint.                                                                                                                    |
   | BIMI                      | A record that is **published but ineffective** — present, with DMARC not enforcing. Not absence.                                                                                 |
   | DMARC                     | **Multiple** DMARC records. Per RFC 9989 receivers then apply no policy at all, so this is absence-equivalent.                                                                   |
   | DNSSEC                    | **Broken chain or failing validation only** — never "not enabled" (see below).                                                                                                   |
   | `authoritative_dns_infra` | Capability failures: missing AA flag, exposed recursion, root-hint or root-server-set mismatch, route leak/hijack signal.                                                        |
   | MTA-STS                   | A **deployed** policy failing RFC 8461 conformance (missing/invalid `version:`, `mode:`, `mx:`, or `max_age:`). Not absence — bare absence stays graded, not zeroed (see below). |
   | Shadow Domains            | "Shadow domain fully spoofable": a variant with MX but no SPF and no DMARC (SQ-74). Other rungs stay graded.                                                                     |

   **HTTP Security is not on this list.** It set the flag until #646 and #662 removed its last path, and now sets it on none: a probe that never reached the origin (WAF block, 401, connection failure, budget timeout) emits `inconclusive: true` with an `errorKind` instead, because asserting absence from a measurement that never completed is a claim of fact the scan did not establish. **CAA, SVCB-HTTPS, and TLS-RPT deliberately do NOT** set `missingControl` — absence is a graded finding, not a category-zeroing missing control. Nor does bare MTA-STS **absence** (see the paragraph below) — only its deployed-but-broken conformance findings do, as of SQ-74.

   > This list was derived from the call sites and verified on 2026-08-14 (SPF and MTA-STS's conformance rows added SQ-74, migrating each from prose-only zeroing to an explicit declaration — no score moved, since every finding these cover already zeroed on its own prose beforehand). A bare `grep -rn 'missingControl: true'` **over-reports** it: the grep also matches the comments explaining why a check declines to set the flag, which is how HTTP Security reads as an emitter when it is not. Strip comments before counting, as `test/audits/measured-vs-unmeasured-metadata.audit.test.ts` does. **DNSSEC "not enabled" also does NOT** — per NIST SP 800-81r3 it's a baseline integrity control in defense-in-depth, so absence is a `high` Core penalty with a fixed `penaltyOverride: 40` (category lands at 60, not 0). DNSSEC's broken-chain / validation-failing cases (distinct from "not enabled") DO fire `missingControl: true`.

   **MTA-STS _absence_ joined the deliberately-not-setting list in scoring model 1.6.0** (it was previously the seventh setting check). Rationale: measured over a 1,000-domain corpus on 2026-08-03, the `mta_sts` category had a mean score of 3.3 with 96.5% of the 687 measured domains at exactly 0. A control that near-nobody passes is a constant penalty against ~3 of the ~80 base points, not a discriminator, and no documented incident is attributable to a missing MTA-STS policy. Its weight (3, Protective) and finding severities are unchanged — only the zeroing behaviour. A **deployed-but-broken** policy (bad `version:`, missing `mode:`, uncovered MX set, unfetchable policy file) still emits its confident `high`/`medium` findings; these zeroed on prose alone until SQ-74 gave them the same explicit `missingControl: true` declaration (no score change — they already zeroed).

**Score zeroing**: When either mechanism fires, `score` is set to `0` (`hasMissingControl ? 0 : score`). Checks that fail due to low penalty-based score (e.g., two criticals → score 20, `passed=false`) retain their numeric score — only truly missing controls are zeroed. This prevents misleading displays like `✓ 95/100` for checks with no record at all.

**`passed` flag**: `score >= 50 && !hasMissingControl`. A check fails if the score is below 50 or if either missing-control mechanism fires.

Missing controls zero the category's weighted contribution, in the Core and Protective tiers alike. The former Hardening tier, where `result.passed` decided bonus points, no longer exists as a scoring mechanism.

Source: `scoreIndicatesMissingControl()` and `buildCheckResult()` in `packages/dns-checks/src/scoring/model.ts`.

### Reading category scores in bulk

Two consequences for anyone computing adoption or coverage statistics from `categoryScores`
across many domains.

**DNSSEC does not zero on absence — an adoption test must use `dnssec > 60`.** Because
"DNSSEC not enabled" is a fixed `penaltyOverride: 40` rather than a missing control, an
unsigned zone scores exactly **60**, not 0. A `dnssec > 0` test therefore counts every
unsigned domain as signed: measured across a 2,123-domain national corpus, the raw `dnssec`
values were `{0: 44, 55: 1, 60: 1942, >60: 136}` — 6.4% signed and 91.5% unsigned sitting at
exactly 60, where a `> 0` test reports 95–100% adoption. Country-level signed rates measured
the same day ranged from 3.3% to 16.5%. Every _other_ scored category zeroes on absence, so a
uniform "score is 0" test across categories is correct everywhere except DNSSEC, and must
special-case it.

**A category absent from `categoryScores` was not measured.** It was excluded as inconclusive
(see [Evidence sufficiency](#evidence-sufficiency)) and renormalized out of the score, so it
belongs out of the _denominator_ of a coverage rate — counting it as a failure overstates the
failure rate. Reach varies by category and by network path: in the same corpus `http_security`
was measured on 1,579 domains and `ssl` on 1,741, while pure-DNS categories completed on every
domain; in another country's corpus `ssl` failed on 72.5% of domains. That skew is a property
of reachability, not a scanner timeout — scans containing a failed check completed _faster_
than clean ones (median 1,969 ms vs 2,250 ms), which is what an unreachable or refusing host
looks like. A check exhausting its time budget would be slower, not faster.

## Critical Gap Ceiling

Domains missing any critical foundational control are capped at a maximum overall score. The ceiling is applied after all other scoring.

Source: `thresholds.criticalGapCeiling` in `packages/dns-checks/src/scoring/config.ts` and `computeScanScore()` (via generic engine) in `packages/dns-checks/src/scoring/engine.ts`.

## Critical Finding Penalty (default off since 2.0.0)

The flat overall penalty for a **verified**-confidence critical finding is **removed from the default model**: `thresholds.criticalOverallPenalty` defaults to `0`. Critical findings still count through the per-finding category deduction and the critical-gap ceiling above. The config key and code path remain, so an explicit `SCORING_CONFIG` override (for example `criticalOverallPenalty: 15`) still applies the penalty after weighted scoring.

Source: `thresholds.criticalOverallPenalty` in `packages/dns-checks/src/scoring/config.ts` and `computeScanScore()` (via generic engine) in `packages/dns-checks/src/scoring/engine.ts`.

## Email Bonus (default off since 2.0.0)

The email bonus is **removed from the default model**: `thresholds.emailBonusFull`, `emailBonusMid` and `emailBonusPartial` default to `0`. The keys and the eligibility logic remain, so an explicit `SCORING_CONFIG` override still grants a bonus when all of the following are true:

- SPF is present and strong (`score >= 57`)
- DKIM is observed active (`controlPresent.dkim === true`). Only when DKIM presence is undetermined does the older rule apply: DKIM not deterministically missing
- DMARC is present

DMARC score selects the tier: `>= 90` uses `emailBonusFull`, `>= 70` uses `emailBonusMid`, otherwise `emailBonusPartial`.

Source: `thresholds.emailBonusFull`/`emailBonusMid`/`emailBonusPartial`, `thresholds.spfStrongThreshold` in `packages/dns-checks/src/scoring/config.ts` and generic bonus logic in `packages/dns-checks/src/scoring/generic.ts`.

## Interaction penalties (removed in 2.0.0)

`scan_domain` no longer applies a post-scoring, MCP-only interaction-penalty layer. The overall score and grade it returns equal the `@blackveil/dns-checks` package output for the same inputs. The `interactionEffects` field is retained in `scan_domain` and `batch_scan` output for contract compatibility but is always `[]`.

## Provider-Informed DKIM

When a known DKIM-signing provider is detected (via MX/SPF analysis) but selector probing finds no records, the HIGH finding is downgraded to MEDIUM. This reduces false positives for domains whose provider manages DKIM selectors not discoverable via common probing.

Provider context is applied as a post-processing step after parallel checks complete in `scan_domain`.

Source: `src/tools/scan/post-processing.ts`.

## Provider Confidence Modifier

A bounded modifier is derived from provider detection findings (`metadata.providerConfidence`), but it is **computed and returned for analytics only and is never applied to the overall score**.

- Confidence values normalized to `[0, 1]`
- Average confidence centered around `0.5`, clamped to `-2` to `+2`
- If no provider confidence metadata is present, modifier is `0`

Source: `computeProviderModifier()` in `packages/dns-checks/src/scoring/generic.ts`.

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

The 9-band scale above is the **internal / SSOT** scale — used by `compare_baseline` ordering, `analyze_drift`, `map_compliance`, `generate_fix_plan`, cohort-percentile math, golden tests, and `ScanScore.grade`.

The **customer-facing display scale is a NIST-aligned 6-band** (`nistScoreToGrade()`, also in `engine.ts`), shown by `scan_domain`, `batch_scan`, `compare_domains`, and the `/badge` SVG — recomputed from the same 0–100 score at the `displayGradeFor` chokepoint in `src/lib/ungraded-display.ts` (an ungraded scan stays `null` — there is no grade sentinel, since substituting a letter would publish an `F` for a domain that was never measured):

- A+: `≥95`
- A: `≥90`
- B: `≥80`
- C: `≥70`
- D: `≥60`
- F: `<60`

Scores are unchanged by the display scale — only the letter differs. bv-web-prod displays the same NIST letter everywhere so a domain shows one grade across web + MCP.

The failure mode this guards against is not the two scales coexisting; it is two **customer-visible** surfaces reading different scales and disagreeing on screen about one domain. That shipped twice, and both are fixed: the maturity-stage cap read the 9-band while the report showed the 6-band, printing grade D beside a "Hardened" label; and `/badge` rendered the internal letter, so a domain scoring 67 showed **C** on its badge and **D** in its report. Every customer-visible letter now routes through the one `displayGradeFor` chokepoint, and an audit test pins that wiring.

## Scoring Profiles

`computeScanScore()` accepts an optional `DomainContext` that adapts weights based on detected domain purpose. Six profiles exist:

| Profile                   | When Detected                              | Key Differences                                                                                   |
| ------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| `mail_enabled`            | Has MX, no enterprise provider (default)   | Base weights                                                                                      |
| `enterprise_mail`         | MX + enterprise provider + DMARC enforcing | Email auth slightly higher, MTA-STS elevated (3 → 4)                                              |
| `non_mail`                | No MX, no web indicators                   | Email auth near-zero, DNSSEC/SubdomainTakeover elevated                                           |
| `web_only`                | No MX + CAA or SSL present                 | Email auth near-zero, SSL elevated                                                                |
| `minimal`                 | >50% of measured checks failed             | Weights spread evenly, lower total                                                                |
| `authoritative_dns_infra` | Explicit infrastructure assessment profile | Mail/web controls are non-scoring; authoritative DNS infra, DNSSEC, NS, and zone hygiene dominate |

- **Email bonus**: zero by default in every profile since 2.0.0; an explicit config override applies only to `mail_enabled` and `enterprise_mail`
- **Critical gap categories**: `mail_enabled`/`enterprise_mail` use `['spf', 'dmarc', 'dkim', 'ssl', 'dnssec', 'subdomain_takeover']`; `non_mail`/`web_only` use `['ssl', 'dnssec', 'http_security', 'subdomain_takeover', 'dane_https']`; `minimal` uses `['ssl', 'dnssec', 'subdomain_takeover']`
- **Authoritative DNS infra profile**: uses `['authoritative_dns_infra', 'dnssec', 'ns', 'zone_hygiene']` as critical gap categories and has no email bonus.

### Phase 1 (Current)

Auto-detection runs, is reported in the structured result (`scoringProfile`, `scoringSignals`), and selects the weight table the domain is scored against: `scan_domain` always supplies a `DomainContext`, so weights come from `profileWeights` (defaults derived from `PROFILE_WEIGHTS`) on both the auto and the explicit path — never from `config.coreWeights`/`config.protectiveWeights`, which the scan path does not read at all. An explicit `profile` parameter overrides detection and adds a per-profile cache key (`cache:v<server-version>-dc<dns-checks-version>:<domain>:profile:<profile>`); the auto path uses the same key without the profile suffix.

Detection priority: `non_mail`/`web_only` (no MX or Null MX) -> `mail_enabled` (MX DNS failure safe fallback) -> `enterprise_mail` (MX + provider + DMARC enforcing) -> `mail_enabled` (MX, default) -> `minimal` (>50% failed override). The `authoritative_dns_infra` profile is explicit-only.

Source: `packages/dns-checks/src/scoring/profiles.ts`.

### Authoritative DNS Infrastructure Profile

The `authoritative_dns_infra` category covers hostname and root-server evidence that normal DoH-only scans cannot observe directly, measured over direct DNS-over-TCP/53 from a single vantage: TCP/53 reachability, the AA flag, recursion exposure, SOA serial consistency across nameservers, DNSKEY/RRSIG presence (not validation), IPv4/IPv6 answer parity, unsupported-query handling, and root-server set conformance; for authenticated callers, also zone-transfer refusal and CHAOS `version.bind`/`id.server` disclosure. It does not measure, and reports as inconclusive: UDP/53 reachability, amplification, EDNS large-response/truncation, DNS cookies/RRL, BGP origin, RPKI, route-leak signals, anycast diversity, vantage latency, and RIR/RDAP.

Two MCP tools populate this category:

- `check_authoritative_dns_infra` checks a hostname's authoritative DNS infrastructure posture.
- `check_root_server_set` queries a rotating sample of 3 root servers per call and compares the priming NS set, glue, SOA serials, and cross-root consistency with the embedded official hints.

Both tools return structured partial results when `BV_INFRA_PROBE` is not configured. In that worker-only mode, every live-probe capability is marked inconclusive; `check_root_server_set` still returns the embedded official root-server names.

Source: `src/tools/check-authoritative-dns-infra.ts`, `src/tools/check-root-server-set.ts`, and `src/lib/authoritative-dns-infra/`.

## Maturity Staging

`computeMaturityStage()` classifies the domain into a maturity stage (0-4):

| Stage | Label       | Criteria                                                                                                                               |
| ----- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | Unprotected | No SPF or no DMARC                                                                                                                     |
| 1     | Basic       | SPF present, DMARC present (`p=none` without `rua=`)                                                                                   |
| 2     | Monitoring  | SPF + DMARC `p=none` with `rua=` reporting                                                                                             |
| 3     | Enforcing   | SPF + DMARC `p=quarantine` or `p=reject`. DNSSEC and DKIM not required.                                                                |
| 4     | Hardened    | Stage 3 + at least 2 of {MTA-STS, DNSSEC, BIMI, verified DANE, CAA, DKIM-discovered}, at least one of which is DNSSEC, MTA-STS or DANE |

These are the mail-ladder labels. `web_only` and `non_mail` domains use a second ladder (Unprotected, Basic, Transport-Hardened, Defensive, Comprehensive).

The stage is then capped by the **displayed** (NIST 6-band) grade, so the letter and the maturity label on a report can never contradict each other: displayed grade `F` (score < 60) caps the stage at 2, displayed grade `D` (score 60-69) caps it at 3, and a displayed `C` or better is uncapped. A capped stage is labelled `... (score-capped)`, using the wording of the ladder that produced it — a mail domain reads `Enforcing (score-capped)` / `Monitoring (score-capped)`, a `web_only` or `non_mail` domain reads `Defensive (score-capped)` / `Transport-Hardened (score-capped)`.

Source: `src/tools/scan/maturity-staging.ts`.

## Notes on `scan_domain`

`scan_domain` runs checks in parallel and includes non-mail-domain adjustment behavior when no MX records are present. Accepts an optional `profile` parameter (`auto`, `mail_enabled`, `enterprise_mail`, `non_mail`, `web_only`, `minimal`, `authoritative_dns_infra`) to control scoring weights. The `authoritative_dns_infra` profile runs only the authoritative infrastructure checks and merges their findings into one category result.

Source: `src/tools/scan-domain.ts`.

## Version stamps and reproducibility

Every `scan_domain` / `batch_scan` result carries three stamps in three **different namespaces**. They are not comparable to one another:

| Field                     | Tracks                                                                                                                                | Moves when                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| `scoringModelVersion`     | The scoring **policy** — weights, profile weights, grade thresholds, severity penalties, the missing-control rule, profile detection. | A change alters scores or grades. Rarely. |
| `dnsChecksPackageVersion` | The `@blackveil/dns-checks` **engine package** bundled by the running build.                                                          | Every package release.                    |
| `scoringConfigHash`       | The **effective scoring configuration** that produced this result, including any `SCORING_CONFIG` override.                           | The effective config differs.             |

`scoringModelVersion` is independent of the npm package version and is normally lower — model `1.10.0` alongside package `1.18.0` is expected, not a version gap, and does not imply that a vendored copy of the package scores differently from the hosted service. Both are emitted side by side precisely so that the difference is visible without prior knowledge.

**Cite `scoringConfigHash` when you publish a score.** Neither version number identifies the configuration a result was produced under; the hash does, so two results carrying the same hash were graded by the same rules.

Source: `src/lib/scoring-version.ts`, `src/lib/dns-checks-version.ts`.

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
| ----------- | ----------- | ---------- |
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
