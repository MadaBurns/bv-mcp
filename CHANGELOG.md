# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [3.8.0] - 2026-06-03

Scoring-honesty release: profile detection now keys on observed controls rather than a `passed` flag or finding prose, and a SERVFAIL apex is reported as a distinct "DNS resolution broken" state instead of a fabricated low score. These **do** shift some per-domain scores (bounded ~±2 pts via profile reselection), so `SCORING_MODEL_VERSION` advances to `1.1.0`.

### Fixed

- **Profile detection now keys on an active control, not a bare `passed`/finding prose.** `detectDomainContext` (which selects the per-profile scoring weight table) inferred a control as "present" from `result.passed === true` for MTA-STS/BIMI/SSL/CAA and a brittle text regex for DKIM/MX. But `passed` is `true` for an absent-but-not-penalized control (e.g. MTA-STS on a non-mail domain), so most domains were mis-read as having hardening present. Checks now emit a structured `controlPresent` tri-state on `CheckResult` — `true` (active record observed: real mail MX, non-revoked DKIM key, MTA-STS policy record, DMARC-enforcing BIMI, reachable HTTPS, CAA records), `false` (definitively absent/inactive: no/null MX, all-revoked DKIM, non-enforcing BIMI), `undefined` (lookup failed) — and detection reads that instead. **Measured effect** on a 90-domain portfolio sample: `enterprise_mail` over-classification dropped from **87% → 62%** (the residual reflects the enterprise definition — provider + any one active control — which Google Workspace/M365 satisfy by auto-provisioning DKIM), with a **bounded per-domain score impact (~±2 pts, mean +0.69)** on the dominant `enterprise_mail ↔ mail_enabled` transition, since the profile only selects a weight table — scoring math is unchanged. `SCORING_MODEL_VERSION` → `1.1.0`. Sets `controlPresent` in the six checks `detectDomainContext` consumes (`mx`, `dkim`, `mta_sts`, `bimi`, `ssl`, `caa`); `buildCheckResult` gains an optional `controlPresent` argument. (Supersedes the reverted prose-matching attempt.) (#348)
- **`controlPresent` preserved through scan_domain post-processing.** Two post-processing rebuilds fed the score-bearing profile detection but used a 2-arg `buildCheckResult` that silently dropped `controlPresent`: `mergeTlsFinding` (a legacy-TLS-but-reachable host had its `ssl` `controlPresent` flipped `true → undefined`, flipping `sslPass` false and shifting the detected profile in prod) and `applyProviderDkimContext`. Both now thread the original `controlPresent` through. (#348)
- **SERVFAIL apex now reported as a distinct "DNS resolution broken" state.** A domain whose apex returns SERVFAIL (RCODE 2) previously fell through to the full check matrix and was scored as if it resolved, producing a misleadingly low grade for what is actually an unmeasurable state. `scanDomain` now surfaces a dedicated broken-resolution result; a `cd=1` (checking-disabled) retry distinguishes a DNSSEC-bogus apex (clears with validation off) from a genuinely broken delegation. The query-cache key stays byte-identical for existing callers (the `:cd1` suffix is appended only when checking is disabled). (#349)

## [3.7.0] - 2026-06-03

Scoring-output transparency and DNS-integrity severity refinement. No domain scores or grades change in this release: the DNSSEC reclassification adjusts a severity *label* only (the −40 score penalty is preserved), and the new scan-output fields are additive.

### Added

- **Scan output now carries a scoring-model version + config fingerprint.** Every structured scan result includes `scoringModelVersion` (a semver for the scoring *policy*, distinct from the package/server version — bump it whenever weights, thresholds, severities, or the `passed` rule change) and `scoringConfigHash` (a deterministic FNV-1a fingerprint of the effective `SCORING_CONFIG`, so an override is captured). The full human-readable report gains a `Scoring model: v<X>` footer. This makes "the numbers moved between two scans" explainable by design — a dated report records exactly which scoring policy produced it. Inaugural version: `1.0.0`. (`src/lib/scoring-version.ts`)
- **`resolves` is now exposed on the structured (wire) output.** The non-resolving short-circuit's `resolves: false` marker (previously internal-only) is now an additive-optional field on `StructuredScanResult`, so downstream consumers can exclude non-resolving domains from aggregates without inferring it from `grade === 'N/A'`.

### Changed

- **Adaptive-weights `scoringNote` no longer implies a score effect.** Adaptive weighting is telemetry-only (not score-bearing), but the note read like *"DNSSEC carried less weight because similar domains rarely have issues there"* — describing a reweighting that never touched the returned score. The note is now framed as an explicit non-scoring/experimental observation and states plainly it did not affect the scan's score. Wording-only; no scoring math changed.
- **DNSSEC-absent severity decoupled from its score penalty.** A fully unsigned public zone now surfaces as a **`high`** finding instead of `critical` — DNSSEC is one of several DNS integrity controls, not a sole baseline, so it doesn't warrant the top triage tier. The score impact is unchanged: a new numeric `penaltyOverride` on finding metadata (honored by `computeCategoryScore`) keeps the heavy −40 deduction the prior `critical` label carried, so the `dnssec` category still scores **60** (grade and overall score are unaffected). This corrects the severity-distribution inflation where DNSSEC alone drove ~94% of audited domains to carry a `critical`, without weakening the score-side stance grounded in NIST SP 800-81r3 / RFC 9364 (BCP 237). (#345)

### Fixed

- **`scan_domain` no longer fabricates a posture for domains that don't exist.** A domain whose apex returns NXDOMAIN (RCODE 3) was run through the full check matrix and scored ~56/D+ from "absence = missing control" findings — a misleading grade for an unregistered name. `scanDomain` now probes the apex `NS` record first and short-circuits to a dedicated non-resolving result (`grade: 'N/A'`, `resolves: false`, no fabricated findings or per-category scores; maturity "Does not resolve"). The probe is **fail-open**: only a confirmed NXDOMAIN short-circuits — timeouts/network errors and SERVFAIL/NOERROR fall through to the normal matrix, so a transient or DNSSEC-bogus failure is never mistaken for "does not exist". The `NS` lookup is shared with the `ns` check via the scan's query cache (no extra round trip on resolving domains). Aggregators should exclude `resolves === false` results. Standalone `check_*` tools are unaffected (scan-orchestration scope only). (#345)

### Documentation

- **Corrected the `CLAUDE.md` rate-limit note to HTTP 429.** The contributor guide stated rate-limit/quota responses were "HTTP 200 + JSON-RPC `code: -32029` — not 429"; in fact every rate-limit and per-tier quota path in `src/mcp/execute.ts` returns `httpStatus: 429` with the JSON-RPC `-32029` error carried in the response body and a `retry-after` header (as asserted by `test/index.spec.ts`). Documentation only — no runtime behavior changed. (#343)

## [3.6.0] - 2026-06-02

### Changed

- **Dependency refresh — no runtime or scoring impact.** Semver-compatible npm bumps: `wrangler` 4.96.0, `zod` 4.4.3, `vitest` 4.1.8, `@cloudflare/vitest-pool-workers` 0.16.11, `@cloudflare/workers-types` 4.20260602.1, `tldts` 7.4.2, `tsup` 8.5.1, `typescript-eslint` 8.60.1; plus Cargo patch bumps for `bv-wasm-core` (`wasm-bindgen` 0.2.122, `serde_json` 1.0.150, `memchr` 2.8.1, `bumpalo` 3.20.3). `npm audit` clean. (#335)
- **Toolchain upgraded to TypeScript 6.0 and ESLint 10 (major).** `typescript` 5.9.3 → 6.0.3 (root + `@blackveil/bv-whois`), `eslint` 9.39.3 → 10.4.1. **`engines.node` raised to `>=22.13.0`** (ESLint 10's floor on the 22.x line) — self-hosters must build on Node ≥ 22.13. ESLint flat config and the strict tsconfig needed no changes. (#336)
- **`@blackveil/dns-checks` type declarations are now generated by `tsc` instead of tsup's bundler.** TypeScript 6.0 promotes deprecated compiler options to hard errors (`TS5101`), and tsup's DTS path unconditionally injects a deprecated `baseUrl`. The package now emits per-file `.d.ts` via `tsc --emitDeclarationOnly` (the `.`, `./scoring`, `./whois` export entry points are unchanged); the root worker/CLI build, which ships no public types, no longer emits declarations. No published runtime behavior changes. (#338)

### Fixed

- **`scan_domain` no longer fails catastrophically when the scoring path throws.** The post-processing fallback in `scanDomain` re-ran the same `computeProfileAwareScanScore` call, so a failure inside the scoring path (e.g. a `ReferenceError` from a stale/mismatched bundle) threw a second time and — with no outer guard — crashed the entire scan into a generic "unexpected error" for every domain, also taking down `batch_scan`, `compare_domains`, `generate_fix_plan`, and `map_compliance`. The fallback scoring is now guarded: on a scoring failure the scan returns the completed check findings and per-category scores with the overall score/grade marked unavailable (`grade: 'N/A'`, maturity `Unscored`) instead of failing the whole tool.
- **`check_authoritative_dns_infra` and `check_root_server_set` degrade gracefully when the infra probe is unavailable.** Called standalone (not via `scan_domain`'s `safeCheck` wrapper), a non-OK/5xx response or network error from the infrastructure probe surfaced as a hard client error (`Invalid infra probe response: … returned HTTP 503`). They now return an inconclusive `CheckResult` (`checkStatus: 'error'`, excluded from scoring, with an info-level "probe unavailable" finding) — matching the binding-absent path and the recon-tool fail-soft convention. The probe-available path (production) is unchanged.
- **Disambiguated the two `baseline` parameters.** `compare_baseline` (policy/requirements **object** for compliance enforcement) and `analyze_drift` (prior-scan **string** reference — a ScanScore JSON or `"cached"`) both expose a param named `baseline` with different shapes. Their `inputSchema` descriptions and tool JSDoc now state the distinction explicitly, and passing a string to `compare_baseline` returns an `Invalid baseline: …` error that points the caller to `analyze_drift`. No accepted types changed.

## [3.5.1] - 2026-06-01

Patch release formalizing the 2026-06-01 production deploy (`@blackveil/dns-checks` 1.3.12): cache-key correctness, workerd body-discipline in the HTTP-reading checks, and scoring-documentation reconciliation. No score changes.

### Fixed

- **Profile-aware overall scoring is now the canonical package path.** `computeProfileAwareScanScore()` exposes the profile-detected overall-score assembly from the package root and scoring subpath, and `scan_domain` now uses it for default `auto` scoring so web-only/non-mail domains are not scored through the mail-enabled no-context path. (`@blackveil/dns-checks` 1.3.12 → 1.3.13)
- **Cache keys now thread the `@blackveil/dns-checks` version.** Scan/check results were keyed by `SERVER_VERSION` only, so a scoring-only `@blackveil/dns-checks` deploy that didn't bump `SERVER_VERSION` kept serving pre-deploy scores until the cache TTL expired. Keys are now `cache:v<serverVersion>-dc<dnsChecksVersion>:…` (`src/lib/cache.ts`), so bumping **either** version cold-starts the cache. (`@blackveil/dns-checks` 1.3.11 → 1.3.12)
- **workerd body-discipline in HTTP-reading checks.** `check_bimi`, `check_mta_sts`, `check_http_security` (including the GET fallback), and subdomain-takeover analysis read only response headers on some redirect / `!ok` / oversize paths without consuming or cancelling the response body, producing "stalled HTTP response was canceled" workerd log noise. Added `response.body?.cancel()` on every unread path.

### Docs

- Reconciled the documented DNSSEC Core weight to the live value (**10**) across `IMPORTANCE_WEIGHTS`, the `@deprecated` `CORE_WEIGHTS`, the flat `DEFAULT_SCORING_CONFIG.weights` map, and the `CLAUDE.md` scoring headline — all non-score-bearing surfaces, no score change. Clarified in `docs/scoring.md` that `auto` mode scores via `config.coreWeights` (not the `mail_enabled` profile), which matters under the production `SCORING_CONFIG` override (where the `auto` path's DNSSEC weight is 7).

## [3.5.0] - 2026-05-31

Scoring-contract recalibration aligning email-authentication and DNS-integrity severities with NIST SP 800-81r3, plus a new impersonation-aware DMARC escalation. Scores and finding severities shift for some domains — see notes below.

### Changed

- **DMARC and SPF severities recalibrated down to reflect standalone risk.** "No DMARC record found" is now **high** (was critical) and "DMARC policy set to none" is now **medium** (was high); SPF "Too many DNS lookups" (>10 lookups → `PermError`) is now **high** (was critical). These reflect the true standalone impact of each gap — a missing DMARC record on a domain with no active impersonation is a serious monitoring gap, not an in-progress compromise. The critical rating is now reserved for the corroborated impersonation case (below).
- **DNSSEC absence no longer zeroes the DNSSEC category.** Per NIST SP 800-81r3, DNSSEC is a baseline DNS-data-**integrity** control within a defense-in-depth model, not a category-defining missing control like an absent SPF on a mail domain. "DNSSEC not enabled" remains a **high**-severity Core finding (the category takes a proportionate penalty → ~75) but no longer sets `missingControl: true`, which previously zeroed the whole DNSSEC category. DNSSEC stays a weighted Core control; absence is now scored as a real-but-proportionate integrity gap rather than a catastrophic zero.

### Added

- **Impersonation-aware DMARC escalation in `scan_domain`.** When a mail-sending domain (has MX, not a no-send policy) has weak or absent DMARC **and** active lookalike/impersonation domains are detected (a medium-or-higher `lookalikes` finding), the demoted DMARC finding is re-escalated to **critical** in post-processing (`escalateDmarcForImpersonation`). This restores the critical rating precisely for the brand-justified case — weak DMARC enforcement plus a real spoofing channel — rather than applying it to every domain with a DMARC gap.
- **`impersonation_weak_dmarc` category-interaction rule** (`src/lib/category-interactions.ts`): the score-penalty counterpart to the label escalation, firing on the same signal (`lookalikes ≤ 85` + post-escalation `dmarc ≤ 60` → −8 overall). Keeping the label escalation and the score penalty on the same signal ensures a critical DMARC label never ships without a matching score consequence.

### Fixed

- **Webhook alert delivery is now time-bounded.** `sendAlert()` in `src/lib/alerting.ts` issued its webhook `POST` with no `AbortSignal`, so a stalled alert endpoint could hang the 15-minute cron. Added `signal: AbortSignal.timeout(5000)` (fail-open via the existing try/catch), matching the timeout discipline of every other outbound `fetch`.

### Changed

- **CI deploy jobs are explicitly fenced off.** `publish.yml` and `deploy-hook.yml` deployed the public `wrangler.jsonc` without the private-config injection that `npm run deploy:prod` performs, so an enabled CI deploy would have shipped a worker missing all KV/D1/R2/Analytics/service bindings. Both deploy jobs now fail loudly directing operators to the manual deploy path (private bindings live in the gitignored `.dev/` overrides, unavailable in CI).
- **`server.json` version is auto-synced on release.** The `publish.yml` version-bump job now updates `server.json` and includes it in the committed file set, closing a manual, forgettable step.

### Docs

- Documented the Cloudflare Workers subrequest ceiling (Free 50 / Paid 1000) in `CLAUDE.md` for BSL self-hosters; noted why `@vitest/coverage-v8` cannot run under the workers-pool runtime.

## [3.4.0] - 2026-05-30

### Added

- **`check_dnskey_strength` — DNSKEY signing-algorithm strength audit (RFC 8624).** New scored tool (hardening tier, included in `scan_domain`) that grades each published DNSKEY algorithm — flagging deprecated RSA/SHA-1 and DSA, rewarding ECDSA P-256 / Ed25519 — independent of whether the DNSSEC chain validates. Tool count 77 → 78.

## [3.3.29] - 2026-05-29

### Fixed

- **Tool-quality batch (5 issues found running tools against a live, well-configured domain).** Version bump busts the version-keyed KV cache so stale outputs are evicted on deploy.
  - **`generate_spf_record` no longer emits a mail-breaking empty record.** Previously, for a domain with a healthy `-all` SPF (e.g. ip4 blocks + includes) and no `include_providers` argument, the generator detected zero mechanisms — because the underlying SPF check only attaches `includeDomains` metadata to `~all`-style findings — and returned `v=spf1  -all` (double space, zero mechanisms) with an empty `warnings` array. Publishing that would hard-fail ALL of the domain's legitimate mail. Now the generator reads the live SPF record directly and preserves **every** authorizing mechanism verbatim (ip4, ip6, a, mx, include, exists, redirect=), layers in any `include_providers`, and — as a hard safety net — refuses to emit a bare `v=spf1 -all`: if no mechanisms are detected and none are supplied, it returns a neutral `v=spf1 ?all` placeholder plus a loud warning. Double-space defect fixed (single-space join). DNS-lookup-limit counting now correctly excludes ip4/ip6.
  - **`generate_mta_sts_policy` now auto-detects MX from DNS.** The schema documents "Omit to detect from DNS", but the tool only parsed MX hosts out of MTA-STS check findings and otherwise emitted a `mail.example.com` placeholder with a "No MX hosts found" warning even when the domain clearly had MX records. It now queries MX directly (sorted by priority, null-MX `.` ignored), falling back to finding-text parsing, and only warns when the domain genuinely has no MX.
  - **`explain_finding` returns specific content for severity-status findings.** The `EXPLANATIONS` map is keyed inconsistently (`_PASS/_FAIL/_WARNING/_MISSING` for SPF/DMARC/DNSSEC; `_HIGH/_MEDIUM/_LOW/_INFO` for MX/SSL), but real scan findings carry severity statuses (e.g. DNSSEC + `high`), so the literal `TYPE_STATUS` lookup missed the FAIL-style entries and fell through to the generic "Security Check Complete" stub. A status-class fallback ladder now maps failing statuses → FAIL/MISSING/CRITICAL/HIGH, warning statuses → WARNING/MEDIUM/LOW, and healthy statuses → PASS/INFO. Added minimal entries for `DANE`, `TLSRPT`, and `BIMI` (previously only `DANE_HTTPS` existed).
  - **`check_authoritative_dns_infra` no longer reports a probe-side reachability failure as a HIGH domain finding.** When the BV_INFRA_PROBE cannot reach the target at all (UDP/53 `false` with every other capability inconclusive), that reflects a probe/vantage limitation, not the domain refusing service. UDP/53 and TCP/53 reachability failures are now demoted to inconclusive unless the probe proved contact another way (e.g. TCP answered while UDP was blocked, or an authoritative response was observed) — in which case they remain HIGH.
  - **`check_nsec_walkability` no longer false-positives on unsigned zones.** NSEC/NSEC3 records only exist in DNSSEC-signed zones, but the tool reported any domain without an NSEC3PARAM record as "fully walkable" (HIGH) — including unsigned zones that have no NSEC chain at all. The check now gates on DNSSEC being enabled (DNSKEY, with DS as a backstop): unsigned zones return an info "walkability N/A — zone not DNSSEC-signed" finding, and the HIGH walkable finding only fires when the zone IS signed but publishes no NSEC3PARAM.

## [3.3.28] - 2026-05-29

### Removed

- **Spamhaus ZEN dropped unconditionally from the RBL/DNSBL provider sets.** bv-mcp queries DNSBLs through shared public resolvers, where Spamhaus ZEN returns rate-limit/refused codes (`127.255.255.252/.254/.255`) that are indistinguishable from a real `127.0.0.x` listing — producing false "clean"/"listed" verdicts. The previous gate (`hasReliableSpamhausPath`, driven by `BV_DOH_TOKEN`) was a no-op for ZEN: the secondary-resolver token only drives empty-result confirmation in the DoH transport, it never reroutes the ZEN lookup, so the token can never make ZEN reliable here. ZEN is therefore removed entirely — neither queried nor counted:
  - `check_rbl`: `RBL_ZONES` 8 → 7 (`zen.spamhaus.org` removed); "clean on N RBLs" and `zones` metadata reflect 7. Dead Spamhaus quota/return-code decoding removed.
  - `check_mx_reputation` / `buildDnsblZones()`: ZEN excluded; the `hasReliableSpamhausPath` parameter/branch dropped. Tool description updated to "7 DNS-based Real-time Blocklists".
  - `hasReliableSpamhausPath()` and `SPAMHAUS_ZEN_ZONE` removed from `src/lib/dns-types.ts` (now unreferenced).
  - Version bump busts the version-keyed KV cache so stale ZEN-inclusive results are evicted on deploy.

## [3.3.27] - 2026-05-28

### Fixed

- **`map_supply_chain` PUBLIC_SUFFIX_SECOND_LEVEL: missing Japanese 2LDs.** `rakuten.co.jp` reported `ad.jp` as a "DNS hosting provider" — `ad.jp` is a JPRS-managed registry suffix for network-administration entities, not a provider. The original set covered `co/ac/ne/or/go.jp` but missed `ad.jp` / `ed.jp` (primary+secondary education) / `gr.jp` (groups) / `lg.jp` (local government), so any NS at a 3-label JP host collapsed to the registry suffix instead of the operator's registrable domain. Added the four. Surfaced by a second-round 8-domain sweep. (#290)

### Added

- **`map_supply_chain` catalog batch 2: Symantec Email Security.cloud + Campaign Monitor.**
  - **Symantec Email Security.cloud (MessageLabs)** — enterprise email gateway (same product class as Proofpoint/Mimecast/Trellix). MX `*.messagelabs.com` and SPF `spf.messagelabs.com` now resolve to "Symantec Email Security.cloud" instead of raw critical rows. Observed on bbc.co.uk.
  - **Campaign Monitor** — newsletter/transactional ESP. SPF `*.createsend.com` now resolves to "Campaign Monitor". Observed on netflix.com. (#290)

## [3.3.26] - 2026-05-28

### Fixed

- **CodeQL alerts uncovered by v3.3.25's scope tightening — fix the code, not the rule.** Scoping CodeQL to the deployed surface (#288) surfaced 12 pre-existing real alerts that test-file noise had been hiding. All fixed at the source so they auto-resolve on the next `main` analysis:
  - **`js/polynomial-redos`** in `packages/dns-checks/src/checks/caa-analysis.ts` — the single CAA-record regex `/^(\d+)\s+(\S+)\s+"?([^"]*)"?\s*$/` had `[^"]*` overlapping the trailing `\s*$`, giving polynomial backtracking (CWE-1333). Split into an anchored prefix match `/^(\d+)\s+(\S+)\s+/` plus a slice-and-strip step — no adjacent unbounded quantifiers; all 26 CAA + scoring + check-caa tests still pass.
  - **`js/polynomial-redos`** in `packages/dns-checks/src/scoring/model.ts` `MISSING_CONTROL_REGEX` — the `no\s+.+\s+record` gap had two overlapping unbounded quantifiers. Replaced with a bounded gap `[^\r\n]{1,64}` (well above any real finding phrase).
  - **`js/regex/missing-regexp-anchor`** in `src/tenants/discovery/mx-platform-detector.ts` (4 alerts) — `platform()` was substring-matching MX exchange hosts on a joined string (would match `protection.outlook.com.evil.example`). Replaced with per-record host extraction and proper suffix matching (`host === suffix || host.endsWith('.' + suffix)`) — eliminates the regexes entirely and is strictly more precise.
  - **`actions/missing-workflow-permissions`** (5 alerts) — `ci.yml`, `ci-contract.yml`, `repo-hygiene.yml`, `security.yml` lacked an explicit `permissions:` block, so `GITHUB_TOKEN` defaulted to repo-wide read+write. Added top-level `permissions: contents: read` to each (verified no job uses write operations beyond CodeQL, which keeps its own elevated job-level `permissions:`).

## [3.3.25] - 2026-05-28

### Added

- **`map_supply_chain`: Microsoft first-party SPF infra (`*.msft.net`).** `_spf-ssg-a.msft.net` (used by microsoft.com's own SPF) surfaced as a raw critical row; the Microsoft 365 SPF pattern now also matches `*.msft.net` so it resolves to Microsoft 365. Last raw-hostname residual from the catalog sweep.

### Changed

- **CodeQL scoped to the deployed surface (`src/` + `packages/`).** New `.github/codeql/codeql-config.yml` adds `paths-ignore` for `test/`, `scripts/`, and `**/*.{spec,test}.ts`, wired into `security.yml`'s `init`. The `security-extended` suite was flagging ~30 false positives in non-shipping code — `js/incomplete-url-substring-sanitization` on Vitest mock-fetch routers and plain substring assertions, `js/file-access-to-http` on the chaos harness, `js/regex/missing-regexp-anchor` on fixtures — which produced a perpetual red "CodeQL" check on every PR. Production URL/regex handling in `src/`/`packages/` is still fully scanned; the pre-existing test/script alerts auto-resolve on the next main analysis.

## [3.3.24] - 2026-05-28

### Added

- **`map_supply_chain` provider catalog batch (#286) — raw hostnames now resolve to vendor names.** A 16-domain sweep found many well-known SPF/MX/NS hosts surfacing as raw `critical`/`high` rows instead of a vendor. Added/extended `DETECTION_RULES`:
  - **Google (C1/C2):** MX now also matches `*.googlemail.com`; SPF now also matches Google's `_netblocks{,2,3}.google.com` internal includes — both previously surfaced as raw rows alongside the detected Google Workspace.
  - **SPF senders (C3):** Zendesk (`mail.zendesk.com`), Marketo (`mktomail.com`), Statuspage (`stspg-customer.com`), Salesforce Marketing Cloud (`*.exacttarget.com`), Salesforce Pardot (`*.pardot.com`), Qualtrics (`*.qualtrics.com`), SparkPost (`*.sparkpost.com`), Alibaba Mail (`*.aliyun.com`); Mailchimp Transactional now also matches `spf.mandrillapp.com` (was `*.mcsv.net` only).
  - **NS hosts (C4):** Azure DNS (`*.azure-dns.{com,net,org,info}` — collapses 4 rows → 1), Netlify DNS, Vercel DNS, Oracle Cloud DNS (`*.oraclecloud.net`), Salesforce DNS, Alibaba DNS.
  - **MX hosts (C5):** Trellix Email Security now also matches MX `*.fireeyecloud.com` (was SPF-only); Cloudflare Email Security (`*.cf-emailsecurity.net`).
  - **SPF macros (M1):** Proofpoint SPF selectors/macros (`*.pphosted.com`, incl. `%{…}.spf.has.pphosted.com`) and Valimail (`*.vali.email`, incl. macro forms) resolve to the vendor instead of the raw macro string — the suffix match handles both static and macro includes. (#286)

## [3.3.23] - 2026-05-28

### Fixed

- **`map_supply_chain` shadow_service signal — three correctness fixes (surfaced by a 16-domain fact-check sweep).**
  - **MX corroboration (B2):** the shadow_service check considered only TXT-verification + SPF providers, so a service discovered via MX + SRV (e.g. Microsoft 365 SIP, Google Workspace) was falsely flagged "undocumented or unauthorized". It now also corroborates against MX-detected providers. (Observed: nytimes.com flagged "Google Workspace discovered via SRV…" while Google Workspace was its MX provider.)
  - **Self-hosted SRV (B3):** a SRV record whose target is on the scan's own registrable domain is the org's own service, not a third party — no longer flagged. (Observed: microsoft.com→`sipdog3.microsoft.com`, paypal.com→`xmpp.paypal.com`, oracle.com→`vcse.dtvlb.oracle.com`.)
  - **Dedup (B1):** the same provider discovered across multiple SRV prefixes now emits a single signal (mirrors the #261 dedup for stale_integration / security_tooling). (Observed: oracle.com emitted the `vcse.dtvlb.oracle.com` shadow_service twice.)
  - SRV targets are now normalized (trailing dot stripped, lowercased) and the originating target is carried so the self-domain check works. (#285)

## [3.3.22] - 2026-05-28

### Added

- **`map_supply_chain`: email-RECEIVING providers from MX.** The tool passed `mxHosts: []` to `detectProviders`, so the MX operator that receives all inbound mail — one of the most material third-party dependencies — was invisible. MX is now queried and attributed via a new `matchProviderForMxHost` (mirrors the SPF/NS match helpers, shared `DETECTION_RULES` SSOT); unrecognized exchanges collapse to their registrable parent (skipping self-hosted), via a new `addUnrecognizedHostsByParent` helper that also de-dups the NS path. New source `mx` → role `email-receiving`, trust `critical`. (#283)
- **`map_supply_chain`: web CDN attributed as a dependency (#283).** The CDN fronting the primary web property (detected elsewhere as `scan.cdnProvider`) was never joined into the dependency map, so a domain's entire web edge — e.g. AWS CloudFront fronting kiwibank.co.nz — was invisible. The tool now attributes it as a `critical` dependency via the shared, bounded, fail-soft `detectCdnFromAsn` (apex A-record → origin ASN; DoH-only, no HTTP probe — keeps the standalone tool probe-light). An optional `precomputedCdn` option lets a future scan-integration caller pass the richer header-derived value and skip the ASN lookup; header-based attribution stays exclusively in the scan path. Closes #283. (#283)
- **`map_supply_chain`: low-trust cloud-hosting ASN tier (noise-guarded).** New `ASN_TO_HOSTING` map (AWS/GCP/Azure/OVH/DigitalOcean/Hetzner/Vultr) + `mapAsnToHosting` + `detectHostingFromAsn`, kept strictly distinct from the CDN tier (cloud ASNs host arbitrary compute and must never drive CDN attribution — AS16509 stays out of `ASN_TO_CDN`). A cloud-hosting dependency is attributed **only when no CDN fronts the origin** (the CDN is the meaningful edge dependency; the origin host behind it is shared infra), emitted at **`low`** trust with a `shared_hosting` caveat signal so every EC2-hosted site doesn't get a critical AWS row. `detectCdnFromAsn`/`detectHostingFromAsn` now share a private `detectFromAsn(ips, doh, map)` skeleton. (#283)

### Fixed

- **Stale comment in `check-http-security.ts`.** The Cloudflare-detection docblock claimed "True CF customers now go undetected" — outdated since the v3.3.20 ASN tier closes the CF case (apex A-record → AS13335 → "Cloudflare", immune to the `server:` rewrite; verified live on discord.com / 1password.com). Comment corrected to point at the ASN tier; no behavior change. (#283)

## [3.3.21] - 2026-05-28

### Fixed

- **KV cache now versioned by `SERVER_VERSION` — deploys auto-bust stale results.** `check_*` and `scan_domain` results were cached by domain only, so after a deploy stale pre-deploy results kept serving until the TTL expired (the recurring "scan a fresh domain to verify the fix is live" workaround all session). New `buildCheckCacheKey` / `buildScanCacheKey` helpers in `src/lib/cache.ts` prepend `v${SERVER_VERSION}`; wired at all four cache-key sites (`handlers/tools.ts` ×2, `scan-domain.ts` ×2). Deliberate trade-off documented inline: a deploy cold-starts the cache (all keys change) — correct behavior; stale-after-deploy was the bug. (#281)
- **`check_spf`: flag SPF TXT RRsets that risk UDP truncation (#250).** Estimates the full TXT RRset wire size (`estimateTxtRrsetBytes` in `spf-analysis.ts`: `sum(12 + utf8Len(rec) + ceil(utf8Len/255))` per record) and emits a finding when it approaches (>450B, low `SPF_RRSET_LARGE`) or exceeds (>512B, medium) the 512-byte UDP limit — TCP fallback required, which legacy resolvers / restrictive middleboxes may not perform, silently breaking SPF. RFC 7208 §3.4. Reuses the already-fetched full TXT array (no new query). Closes #250. (#281)
- **`check_http_security`: CDN detection now sees vendor-specific signals across the full redirect chain (#262).** Previously only the final captured response's headers were inspected, so `x-amz-cf-id` / `via: …cloudfront` on an intermediate hop was missed (e.g. origins that redirect through an intermediate before the CDN-fronted final). The redirect follower now unions vendor-specific CDN headers across all hops; `MAX_REDIRECT_HOPS` raised 3→5. The `server` header is explicitly excluded from the carried set (v3.3.12 invariant — CF Worker egress rewrites it; a dedicated test asserts an intermediate `server: cloudflare` still yields null). Closes #262. (#281)
- **`check_lookalikes`: shared RDAP registrant org as a second same-entity signal (#263).** A domain's own defensive registrations / regional subsidiaries that use a *different* DNS provider than the parent (so the existing shared-NS check missed them) were flagged as high/medium phishing threats (e.g. scanning xero.com flagged xero.co.nz). When a flagged lookalike shares the scan domain's RDAP registrant organisation, it's now downgraded to an `info` "likely same-entity defensive registration" finding. Net cost: one extra RDAP fetch (the scan domain's), only when ≥1 candidate reaches medium/high; candidate orgs ride the existing enrichment fetch. Fail-soft — RDAP failure keeps the calibrated threat severity (never suppresses a real threat). Cert/DKIM same-entity signals deferred. Closes #263 (focused; the cross-domain-NS supply-chain case remains open). (#281)

## [3.3.20] - 2026-05-28

### Added

- **CDN attribution: new ASN-based fallback tier closes the Akamai false-negative.** `detectCdnProvider` only caught Akamai via the optional `x-akamai-transformed` / `x-check-cacheable` headers — Akamai sites that don't send those (e.g. mit.edu, `Server: AkamaiGHost` only) returned `cdnProvider: null`. Same root cause as the Cloudflare saga (v3.3.7→v3.3.12): CF Worker egress rewrites the response `server` header to `cloudflare`, so the reliable server signal is dead from inside the Worker, and the Akamai-specific headers are optional. The new tier resolves each A-record IP to its origin ASN via team-cymru DoH (`<reversed-ip>.origin.asn.cymru.com`) and maps the ASN to a CDN provider — an origin-set signal (derived from the resolved IP, not a header) that's immune to the CF-Worker rewrite and generalizes to every CDN via one `ASN_TO_CDN` table (Akamai, Cloudflare, Fastly, Imperva, Edgecast, CDN77). **AS16509 (AWS) is deliberately excluded** — it covers all EC2/ELB, not CDN-exclusively; mapping it would false-positive every EC2-hosted app (CloudFront stays caught by the `x-amz-cf-id` header). New `src/lib/cdn-asn-detection.ts`; bounded at 3 lookups with short-circuit-on-first-match and fail-soft on DoH errors; reuses the existing DoH TXT resolver (no new dependency). Tier order in scan post-processing: header vendor-specific (primary) → Cloudflare NS+IP+cert heuristic (v3.3.17) → ASN lookup. The ASN tier runs only when prior tiers produce no attribution. Findings carry `metadata: { cdnProvider, confidence: 'heuristic', source: 'asn-lookup', asn }`. (#279)
- **`map_supply_chain`: AutoSPF catalog entry.** SPF includes matching `*.autospf.email` (AutoSPF SPF-flattening service) now resolve to `AutoSPF` instead of the raw include hostname. Surfaced by mit.edu (`include:_s00430413.autospf.email`). Same drift class as the v3.3.16 batch. (#279)

## [3.3.19] - 2026-05-28

### Added

- **Cloudflare CDN attribution: the v3.3.17 cert-issuer signal is now live (no longer dormant).** `scan_domain` post-processing sources the most-recent cert's issuer DN from bv-certstream-worker's new `/cert-meta` endpoint (via the existing `BV_CERTSTREAM` service binding) and threads it into `detectCloudflareFallback`'s 2-of-3 rule. Cloudflare customers whose attribution needs the cert signal — external DNS provider + Cloudflare edge IP + Cloudflare-issued cert = 2 signals — now correctly report `cdnProvider: "Cloudflare"` instead of `null`. The lookup is best-effort with a 5s cap: any failure/timeout (or absent binding, or a bv-certstream-worker not yet deployed with `/cert-meta`) falls back to `certIssuer: null`, degrading to the v3.3.15 NS+IP-only gate — no regression. The CDN finding's `metadata.source` now distinguishes `ns-ip-and-cert` (cert participated) from `ns-and-ip-range`, and carries `metadata.certIssuer` for transparency. Requires bv-certstream-worker deploy (bv-web PR #621) for live value; ships safely in either order. (#277)

## [3.3.18] - 2026-05-28

### Fixed

- **`check_mx_reputation` no longer produces high-severity false-positive "MX server IP listed on zen.spamhaus.org" findings when Spamhaus returns its public-resolver refusal code.** Pre-fix, any A-record answer from a DNSBL query was treated as "listed" — including Spamhaus's `127.255.255.254` operational code, which means "public/open resolver — query refused", NOT "this IP is listed". The scanner runs through Workers' DoH (a public resolver), so Spamhaus refused every query and the scanner consistently surfaced false-positive listings on shared-mail-platform IPs (most visibly the SMX NZ shared IP that every NZ domain inheriting that infra got flagged for). New 3-state classifier `classifyDnsblAnswers(answers)` distinguishes real listings (`127.0.0.2-11`) from operational codes (`127.255.255.252` typo / `127.255.255.254` public-resolver refusal / `127.255.255.255` rate-limit) and from anomalous values (loopback `127.0.0.0-1`, non-127.x). Inconclusive results emit info-severity findings with the raw return codes and explicit "verify out-of-band at check.spamhaus.org" guidance — no high-severity false positive. Real listings still surface even when other zones are inconclusive (mixed-state). Same drift class as the v3.3.13 GSC / OneTrust dedup and v3.3.8 M365 fix: a heuristic that treated "got data back" as "got the data I assumed" without parsing the actual value. (#275)

### API change

- `analyzeDnsblResults` signature widened: `{ zone, listed: boolean }[]` → `{ zone, status: DnsblStatus, returnCodes?: string[] }[]`. New exports from `src/tools/mx-reputation-analysis.ts`: `classifyDnsblAnswers`, `DnsblStatus`, `DnsblZoneResult`.

## [3.3.17] - 2026-05-28

### Added

- **`map_supply_chain`: Foundation DNS multi-TLD collapse.** New `DETECTION_RULES` entry treats `*.foundationdns.{com,net,org}` NS hosts as one `Foundation DNS` provider row rather than three. Same drift class as v3.3.13 UltraDNS / v3.3.15 NS1+Dyn / v3.3.16 Google Cloud DNS — additive, surfaced by the post-v3.3.16 fact-check on shopify.com. (#273)
- **`detectCloudflareFallback` — new 2-of-3 signal rule for Cloudflare CDN attribution.** Replaces v3.3.15's strict-AND `detectCloudflareViaNsAndIp` (kept as `@deprecated` wrapper to preserve the old NS+IP-only contract for any downstream consumers). Three signals: (A) NS all on `*.ns.cloudflare.com`; (B) at least one A-record IP in a published Cloudflare range; (C) TLS cert issuer matches `/cloudflare/i` (catches `Cloudflare Inc ECC CA-3`, `Cloudflare Origin SSL ECC Issuer ECC`). Two of three required → low false-positive risk, catches Cloudflare customers using external DNS providers. (#273)

### Known limitation

- **Cert-issuer signal is wired but DORMANT in production.** Cloudflare Workers' `fetch()` API does not expose peer-cert metadata, and `checkSsl` in `@blackveil/dns-checks` is a thin HTTPS-reachability + HSTS wrapper that does not capture cert issuer. The scan_domain call site for `detectCloudflareFallback` invokes with `certIssuer: null`, so attribution still degrades to NS+IP-only behavior (same as v3.3.15) for live scans. The 2-of-3 logic is fully unit-tested (12 new specs) and ready to activate when a cert source is plumbed — likely future work via a separate infra probe (crt.sh / certificate-transparency lookup). When that lands, Cloudflare customers like shopify.com (Foundation DNS for NS, Cloudflare for CDN) will start showing `cdnProvider: "Cloudflare"` automatically — no further code change required. (#273)

### Changed

- **`detectCloudflareViaNsAndIp` short-circuit semantics preserved in the deprecated wrapper, NOT in the new function.** Old wrapper returns `null` on empty `nsHosts` or empty `aRecords`. New `detectCloudflareFallback` treats empty inputs as "signal absent (0)" under the 2-of-3 rule, so `(NS=CF, A=[], certIssuer=CF)` attributes via 2 signals. Defensible semantics under the new rule; locked in by regression test. The wrapper preserves the old contract.

## [3.3.16] - 2026-05-28

### Added

- **`map_supply_chain`: four new `DETECTION_RULES` entries surfaced by the spotify.com fact-check round.** Same drift class as v3.3.13/v3.3.15 catalog work — additive, no behavior change for domains that don't match. The v3.3.13 `matchProviderForSpfInclude()` + v3.3.15 `matchProviderForNsHost()` helpers consume `DETECTION_RULES` directly, so each entry lights up both attribution AND multi-record dedup paths. (#271)
  - **Google Cloud DNS** — NS pattern `*.googledomains.com` (e.g. `ns-cloud-a{1-4}.googledomains.com`). Was: raw `googledomains.com`.
  - **HubSpot** — SPF pattern `*.hubspotemail.net` (e.g. `21894833.spf06.hubspotemail.net`). Was: raw include hostname.
  - **Mailchimp Transactional** — SPF pattern `*.mcsv.net` (Mailchimp's transactional / Mandrill infrastructure; distinct from marketing on `mailchimp.com`). Was: raw `servers.mcsv.net`.
  - **Salesforce** — SPF pattern `(^|.)salesforce.com$`, anchored to avoid colliding with Pardot endpoints (`et._spf.pardot.com`). Was: raw `_spf.salesforce.com`. Regression test pins that Pardot rows surface separately when both Salesforce and Pardot includes are present.

## [3.3.15] - 2026-05-28

### Added

- **`map_supply_chain`: NS1 (IBM) and Dyn (Oracle) DNS providers now collapse across their sibling TLDs.** Same drift class as the v3.3.13 UltraDNS multi-TLD fix. NS1 uses both `*.ns1.com` and `*.nsone.net`; Dyn uses both `*.dyn.com` and `*.dynect.net`. Both now surface as one row per provider rather than two. (#269)
- **`map_supply_chain`: Oracle Cloud Email DETECTION_RULES entry.** SPF includes matching `(_c|_s\d+)\.oraclecloud\.com` now resolve to friendly `Oracle Cloud Email` instead of the raw include hostname. Same single-source pattern as the v3.3.8 M365 / v3.3.13 Trellix entries — the v3.3.13 `matchProviderForSpfInclude()` helper picks it up automatically. (#269)
- **`scan_domain`: NS-based Cloudflare CDN attribution as a heuristic fallback.** v3.3.12 dropped header-based Cloudflare detection because CF Workers' outbound `fetch()` rewrites the response `server` header on every response (making header-based detection unreliable from within a CF Worker). v3.3.15 adds a fallback heuristic that runs ONLY when header detection returned null: when BOTH (a) the domain's NS records all match `*.ns.cloudflare.com` AND (b) at least one A record falls within Cloudflare's 15 published edge IPv4 ranges (`cloudflare.com/ips/`), attribute the CDN as Cloudflare with `confidence: 'heuristic'` in finding metadata. Implementation lives in new pure-TS helper `src/lib/cdn-fallback-detection.ts` (no external deps); invoked from scan post-processing AFTER `check_http_security` runs. The header detector (`detectCdnProvider`) stays header-only by design. Real Cloudflare customers like ietf.org and ird.govt.nz, which previously surfaced as `cdnProvider: null`, now correctly show `'Cloudflare'`. (#269)

### Changed

- **Internal: NS-host dedup refactored to use `matchProviderForNsHost` helper.** Previously the dedup loop used a `host.includes(signalDomain)` substring heuristic derived from each rule's `signal` string — happened to work for UltraDNS (`.com`/`.net` both contain `ultradns`) but silently broke for NS1 (no shared substring between `ns1.com` and `nsone.net`). New helper delegates to the actual `DETECTION_RULES` regexes — mirrors the existing `matchProviderForSpfInclude` SSOT path, so detection and dedup use the same regex source instead of diverging via signal-string parsing. UltraDNS regression test stays green; the helper makes future multi-TLD provider additions trivial. (#269)

## [3.3.14] - 2026-05-28

### Fixed

- **`scan_domain`: `notApplicableCategories` and `categoryScores` reconciled via a single source of truth.** Pre-fix, scans could report a category in BOTH fields with contradictory values (e.g. `spf: 100` in `categoryScores` AND `spf` in `notApplicableCategories` for an anti-spoof-only domain). A new `isCategoryNonApplicable()` helper in `format-report.ts` is now the only place applicability is decided; both output fields derive from it. Invariant: every category in `notApplicableCategories` has `categoryScores[cat] === null`. (#267)
- **`scan_domain`: `web_only` / `non_mail` profiles correctly suppress mail-only categories.** Domains without MX are no longer penalised in `categoryScores` for missing DKIM / MTA-STS / BIMI / MX — those are marked N/A and excluded from the overall score formula. The legacy 'all-info findings → N/A' heuristic now also recognises positive 'record found / configured' signals, so a domain that publishes `v=spf1 -all` for anti-spoof correctly stays at `spf: 100, applicable` rather than getting suppressed to N/A. (#267)
- **`scan_domain`: maturity classifier now respects `scoringProfile`.** `computeMaturityStage()` accepts an optional `profile` parameter and routes `web_only` / `non_mail` domains through a new web-only ladder (Basic → Hardened → Defensive → Comprehensive) keyed off SSL / HSTS / DNSSEC / CAA / anti-spoof SPF+DMARC. Mail categories are intentionally excluded. The mail-enabled stage 4 gate is also tightened: `hardeningCount >= 2` AND at least one of {DNSSEC, MTA-STS, DANE} (the transport/integrity signals) is now required. CAA + DKIM-discovered alone no longer qualifies for "Hardened" — those are valuable signals but neither is transport encryption or DNS-integrity. (#267)
- **`check_dmarc`: DMARCbis `np=reject` / `np=quarantine` correctly credited.** When the modern non-existent-subdomain policy tag is present and set to a strict value, the "Subdomain policy weaker than parent policy" finding (raised for `sp=none`) is downgraded from HIGH (-25 score impact) to LOW (-5), because `np=` explicitly covers the non-existent-subdomain attack surface that `sp=none` otherwise leaves open. Result: domains running modern DMARCbis policies with intentional `sp=none` (e.g. registrar-style delegation patterns) score significantly higher than they did pre-fix; cross-domain ordering now correctly puts DMARCbis + strict alignment ahead of basic-DMARC-plus-reporting. Single-mechanism penalty system preserved (no parallel credit system). (#267)

### Changed

- **`StructuredScanResult.categoryScores` widened from `Record<string, number>` to `Record<string, number | null>`.** `null` is used for any category marked N/A. All known downstream consumers (`compare-domains.ts`, `analyze-drift.ts`, `batch-scan.ts`) already null-tolerant via `?? 0` — no consumer changes needed. Internal `ScanScore.categoryScores` shape unchanged.

## [3.3.13] - 2026-05-28

### Fixed

- **`map_supply_chain`: self-owned SPF wrapper subdomains no longer show as critical third-parties.** Confirmed recurring on PayPal (`pp._spf.paypal.com` + 4 `3ph*` siblings) and Stripe (`spf1.stripe.com`, `greenhouse-outbound-mail.stripe.com`). When an SPF include's effective parent equals the scan domain, the rows collapse into a single `<domain> (self-hosted SPF)` entry. Genuine third-party includes preserved. (#265)
- **`map_supply_chain`: UltraDNS no longer double-counted across sibling TLDs.** `ultradns.com` + `ultradns.net` (Neustar's redundant TLDs) now collapse to one `UltraDNS (Neustar)` row, matching the existing AWS Route 53 multi-TLD treatment. (#265)
- **`map_supply_chain`: `security_tooling_exposed` findings deduplicated when a service has multiple TXT records.** Same pre-aggregation pattern as the v3.3.9 `stale_integration` GSC fix — xero.com's 2 OneTrust TXT records → 1 finding with count embedded. Closes #261. (#265)
- **`check_dkim`: probe list expanded from 13 → 25 selectors.** New `dkim-selectors.ts` catalog adds Proton (`protonmail`/`protonmail2`/`protonmail3` — fixes proton.me false-negative), Mandrill, MailerSend, SparkPost, Postmark variants, and others. Custom selectors still pass via the `--selector` arg. (#265)
- **`check_dkim`: score floor at 50 when probe finds no records.** Eliminates the contradictory `score: 75 + HIGH "No DKIM found"` output. (#265)
- **`check_dkim`: CNAME-to-SaaS attribution + finding re-framing.** New `dkim-saas-attribution.ts` recognises SendGrid / Mailgun / Postmark / Mailchimp / Amazon SES / HubSpot / Klaviyo / Zoho / Proton CNAME endpoints. When a selector CNAME-delegates to a known SaaS provider (e.g. stripe `s1` → `*.sendgrid.net`), findings are attributed via `delegatedTo` metadata and the "missing v=DKIM1" finding downgrades to `info` (RFC 6376 §3.6.1 default is widely tolerated; upstream provider responsibility). Substantive findings (e.g. 1024-bit RSA key) preserved at `medium` severity with reframed copy crediting the SaaS provider. (#265)
- **`check_mta_sts`: missing-records finding now branches on MX presence.** Domains with MX (PayPal, Stripe — Google Workspace MX) get medium severity + "accepts inbound email but has no MTA-STS / TLS-RPT configured" copy; non-mail domains (gov.uk) keep low severity + the existing "normal for domains that do not accept inbound email" copy. (#265)
- **`check_lookalikes`: severity calibration matrix per issue #264.** Pure `calibrateLookalikeSeverity()` function replaces the "has MX → HIGH" shortcut. New severity matrix: `mail-infra alone → MEDIUM` (was HIGH); HIGH reserved for `mail-infra + corroborating signal` (recent registration <90d, disposable MX provider, no web content). Enrichment phase adds per-candidate RDAP-age probe + disposable-MX-host list + lightweight HEAD probe (all fail-soft). Eliminates 12 false-HIGH findings on generic-word lookalikes like `cero.com`, `dero.com`, `ero.com` against xero.com. Closes #264. (#265)

## [3.3.12] - 2026-05-28

### Fixed

- **CDN detection: drop the Cloudflare header rule entirely.** v3.3.11's diagnostic instrumentation confirmed empirically what three prior tightening passes missed (cf-ray → cf-cache-status → server:cloudflare): **Cloudflare Workers' outbound `fetch()` rewrites the response `server` header to `cloudflare` on every outbound response**, not just for CF-fronted origins. Diagnostic data captured `server: cloudflare` (with `cf-ray ...-AKL` + `cf-cache-status: DYNAMIC`) on responses from google.com (origin: `server: gws`) and github.com (origin: `server: github.com`). Header-based CF detection is therefore fundamentally impossible from inside a Cloudflare Worker — there is no header CF cannot impersonate in transit. **Resolution**: drop the CF detection rule entirely. The vendor-specific rules above it (Imperva, Sucuri, Vercel, CloudFront, Akamai, Fastly) still work because they use origin-set headers CF cannot impersonate. True Cloudflare customers (cloudflare.com, sites behind CF CDN/WAF) now go undetected — false-negative is strictly better than the 100% false-positive rate the original code had. Future work documented inline: add CF detection via DNS A-record IP-range matching against Cloudflare's published edge ranges (see cloudflare.com/ips/) — that's a separate code path, not header inspection. Also removes the v3.3.11 `cdnDiagnostics` finding-metadata field, its purpose fulfilled. (#259)

## [3.3.11] - 2026-05-28

### Added

- **Diagnostic-only release.** `check_http_security` findings with `cdnProvider` metadata now also carry a `cdnDiagnostics` field exposing the raw `server` / `cf-ray` / `cf-cache-status` / `cf-mitigated` / `x-cdn` / `x-iinfo` / `via` / `x-amz-cf-id` header values the Worker observed. v3.3.10's gate-tightening did not move the live behavior — google.com / github.com / microsoft.com still attribute as Cloudflare despite direct curls showing `server: gws` / `server: github.com` / no `server` header. Need empirical evidence of what the Worker actually receives on outbound `fetch()` before iterating further. The field will be removed in the next release once the root cause is understood. (#257)

## [3.3.10] - 2026-05-28

### Fixed

- **CDN detection: drop `cf-cache-status` and `cf-mitigated` from the Cloudflare gate — `server: cloudflare` alone now.** Follow-up to v3.3.9: live verification of v3.3.9 against `google.com` STILL returned `cdnProvider: "Cloudflare"` despite the v3.3.9 tightening, because Cloudflare's Worker `fetch()` infrastructure stamps **`cf-cache-status`** (typically `DYNAMIC` or `BYPASS` for non-cached fetches) on outbound responses too — not just `cf-ray`. Direct curls of `google.com` / `www.google.com` confirm `server: gws` with no CF-prefix headers, so the live mis-attribution came from CF Worker egress, not from the origin. `server: cloudflare` is the only header the origin's CF zone reliably sets that doesn't get attached to transit responses (CF customers can't override it via Transform Rules); any domain truly fronted by CF will carry it, so dropping the two secondary signals loses no true positives. The drift class (each previous tightening missed a CF-injected header the regression tests didn't cover) is captured in 2 new tests: `cf-cache-status` alone → null; `cf-mitigated` alone → null. (#255)

## [3.3.9] - 2026-05-28

### Fixed

- **`scan_domain` no longer reports `cdnProvider: "Cloudflare"` for every scanned domain.** Root cause was much broader than the symptom that surfaced it: the CDN detector in `src/tools/check-http-security.ts` treated the presence of a `cf-ray` response header as proof of Cloudflare, but the scanner runs inside a Cloudflare Worker and **Cloudflare's edge stamps `cf-ray` onto every outbound `fetch()` response for tracing — including ones from origins behind Imperva, Akamai, AWS, Google Frontend, etc.** Confirmed by re-scanning anz.co.nz (Imperva), amazon.com (Akamai), and google.com (Google Frontend) — pre-fix, all three returned `"Cloudflare"`. Cloudflare detection now requires `server: cloudflare` OR `cf-cache-status` OR `cf-mitigated` (which CF only sets when CF is actually fronting the origin, not when the Worker fetches through it). Added Imperva (`x-cdn: Imperva` / `x-iinfo`) and Sucuri detection; reordered vendor-specific rules ahead of the (tightened) Cloudflare rule; no-match still returns `null` (no fallback default). 9 new regression tests including the `cf-ray`-alone-is-not-Cloudflare assertion. (#253)
- **`map_supply_chain` no longer lists ccTLD second-level registry suffixes (`co.nz`, `co.uk`, `com.au`, …) as DNS hosting providers.** Root cause: `parts.slice(-2).join('.')` parent-domain derivation in `src/tools/map-supply-chain.ts` works for `.com/.net/.io` and silently degrades across the public-suffix long tail — for `ns1.anz.co.nz` it returned `co.nz`, the registry suffix, which then surfaced as a "DNS hosting provider" row. Same bug-class family as v3.3.8's M365 dedup (#251) — string heuristics that don't handle the long tail. Added `PUBLIC_SUFFIX_SECOND_LEVEL` (~50 ccTLD-2LDs covering uk/nz/au/za/jp/in/kr/br/mx/sg) + exported `getEffectiveParentDomain(host)` helper; NS rows that resolve to the scan domain are now treated as self-hosted and dropped from the third-party dependency list. Doc-comment notes the long-term fix is the Public Suffix List but the runtime cost isn't justified here. (#253)
- **`map_supply_chain` now resolves `_spf.fireeyecloud.com` to `Trellix Email Security`** (formerly FireEye Email Security) via a new `DETECTION_RULES` entry in `src/tools/provider-guides.ts`. Same drift-class fix as the v3.3.8 M365 work — once a known SaaS surface gets added to `DETECTION_RULES`, the v3.3.8 `matchProviderForSpfInclude()` helper picks it up automatically (single source of truth, no parallel list). (#253)
- **`map_supply_chain` no longer emits N identical `stale_integration` findings when a single SaaS provider has multiple TXT verification records.** ANZ has 3 `google-site-verification=…` TXT records (one per web property); the signals array surfaced 3 identical findings before, one now with the count embedded in `detail` ("3 TXT verification records but no corresponding SPF include"). (#253)

## [3.3.8] - 2026-05-28

### Fixed

- **`map_supply_chain` no longer double-counts the same provider when discovered via both an SPF include and a TXT verification record.** Live evidence on `spark.co.nz`: `Microsoft 365` appeared once via `MS=…` TXT verification AND once as a raw `spf.protection.outlook.com` row. Root cause: the M365 rule in `DETECTION_RULES` declared a single static `signal: 'mx:mail.protection.outlook.com'`, but matched via its `spf` pattern when `mxHosts` was empty — the dedup loop's signal-substring check (`'spf.protection.outlook.com'.includes('mail.protection.outlook.com')`) was then false, so the include slipped through to the unrecognized-SPF path and surfaced as a second row. (Google Workspace avoided the bug by coincidence — `_spf.google.com` substring-contains `google.com`.) New helper `matchProviderForSpfInclude()` reuses `DETECTION_RULES`' `spf` patterns directly (single source of truth — no parallel list); SPF dedup now resolves each include via that helper and skips it when the resolved provider name is already represented. Regression test exercises the spark.co.nz pattern (SPF M365 include + `MS=…` TXT) and asserts a single Microsoft 365 dependency with both `spf` + `txt-verification` sources at `critical` trust level. (#251)

## [3.3.7] - 2026-05-28

### Changed

- **Dev-tooling-only:** removed an inert pre-commit regex layer that scanned for `.dev/blocked-patterns` (a file that never existed in the repo, so the gate was always a no-op). Real PII / secrets protection remains carried by Gitleaks, `scan-sensitive-surface.mjs`, and the `File hygiene check` CI gate. No worker / tool / schema change; deployed bundle is byte-identical to v3.3.6. (#234)

## [3.3.6] - 2026-05-27

### Fixed

- **Three more tool handlers no longer hit the 28s `TOOL_CALL_TIMEOUT_MS` guillotine.** Same bug class as the v3.3.5 `discover_brand_domains` fix: a tool handler called its orchestrator without threading `signal`/`deadlineMs`, so a slow sub-operation could run past the server-wide tool cap and `Promise.race` would reject the whole call — discarding every completed sub-result. Discovered by a defense-in-depth audit immediately after #236 landed. All three fixes follow the `brand_audit_single` pattern (`AbortSignal.timeout(24_000)` + `deadlineMs: Date.now() + 24_000`) and add a per-stage deadline guard in the orchestrator so partial results are preserved rather than thrown away. Regression tests use the established hang-on-abort stub.
  - `compare_domains` (HIGH severity — easiest to trigger publicly): sequential `scanDomain` loop over 2–5 domains, each capped at 15s internally — 2 uncached domains routinely chained past 28s and lost every completed scan. The orchestrator now checks the deadline before each scan iteration, marks the result `partial: true`, and surfaces un-scanned domains in `errors` with `'budget_exceeded'`. `scanFn` injection seam added (mirrors `batch_scan`'s pattern) for testability.
  - `rdap_lookup` (MEDIUM): server-controlled `Retry-After` headers (up to 15s) plus a 2-attempt loop plus a WHOIS fallback could chain past 28s on slow/rate-limited TLD RDAP servers. `parseRetryAfterMs` now clamps the sleep against remaining budget and returns 0 when budget is exhausted; the retry short-circuits without sleeping just to time out. The orchestrator already accepted `signal` — the handler just wasn't passing one. Also threads `deadlineMs` through `fetchRdapResponse` and `fetchWhoisRegistrar`.
  - `discover_subdomains` (LOW-MED): cold-cache fallback chained 3 × 10-second timeouts (certstream `enumerate` → certstream `sans` → crt.sh) for ~30s, losing any data the earlier stages already gathered. The orchestrator now checks the deadline before each stage; if a prior stage returned data, the result is returned with `partial: true` rather than continuing past the cap.

## [3.3.5] - 2026-05-27

### Fixed

- **`discover_brand_domains` no longer 28-second-times-out when the SAN/CT signal hangs.** The tool handler called `discoverBrandDomains()` without threading `signal`/`deadlineMs`, so `correlateSans`'s retry loop (~46s) was uncancelable and the recursive-SAN headroom guard never armed; a hung crt.sh lookup blew the 28s tool cap, which rejected the whole call and discarded the 6 fast signals' completed results. The handler now threads a 24-second sync budget as `deadlineMs` and `signal: AbortSignal.timeout(24000)` into the orchestrator, matching the `brand_audit_single` pattern. A hung SAN signal degrades to `partial`/`timeout`/`failed` and the pipeline returns the other signals' results before the 28s race fires. Regression test exercises a hanging-SAN stub + fast NS signal with a verified negative control (#236).

### Added

- **`identity_secops` MCP tool group — 4 M365/Identity SecOps read tools** (tier `protective`, NON_CHECK_RESULT). `query_signins`, `query_ual`, `get_ca_policies`, `assess_coverage`. Tool count 73 → 77. The tools are **thin proxies** to bv-web's internal M365 surface via a new `m365Proxy` service binding — bv-mcp holds no M365 credentials. **Fail-soft**: returns `{ unprovisioned: true }` when the binding is absent (mirrors the `reconBinding` operator-tool pattern); never throws. Write tools (`block_ip`/`revoke_sessions`/`deploy_alert_policy`) ship later with SP4's approval gate (#237).
- **`m365Proxy` service-binding wiring + auth.** Threads `BV_WEB` service binding + `BV_WEB_INTERNAL_KEY` through `ToolRuntimeOptions` → `proxy.ts` → bv-web internal endpoints. M365 tools now reach bv-web with `Bearer` auth + `keyHash` in body; paired with the bv-web tenantId-resolution work (#238).

## [3.3.4] - 2026-05-26

### Changed

- **`discover_brand_domains` is now a paid-tier tool — free/unauthenticated daily limit lowered from 1/day to 0/day.** The full brand-discovery surface (`discover_brand_domains` + the async `brand_audit_*` family) now requires an authenticated paid tier. `brand_audit_*` were already 0/day for free; this closes the last free-tier entry point into brand discovery. An audit test (`brand-audit-quota.audit.test.ts`) locks the whole family at 0/day so the gate can't silently re-open. No tool-count or input-schema change.

## [3.3.3] - 2026-05-26

### Changed

- Negotiate MCP `protocolVersion` in the `initialize` handler (supports `2025-06-18` + `2025-03-26`; defaults to `2025-06-18`, matching structuredContent/outputSchema). The server now echoes the client's requested version when supported, and otherwise (omitted, malformed, or unsupported) returns its latest, `2025-06-18`. Previously it unconditionally returned `2025-03-26`, which was behind the structuredContent/outputSchema features bv-mcp already ships (introduced in spec `2025-06-18`). No tool-count or input-schema change.

## [3.3.2] - 2026-05-26

### Changed

- Scan-included `check_*` tool descriptions reference `scan_domain` for selection steering. The emitted `tools/list` description of each of the 16 scan-included checks now ends with the factual suffix "Part of the scan_domain audit.", letting an LLM pick `scan_domain` for a full audit and an individual `check_*` for a single control. Descriptive, not prescriptive — the suffix trips no phrase in the directory-review prescriptive-language audit. Applied at the `TOOLS` build (not per-tool), so it auto-covers any future scan-included tool. No tool-count or input-schema change.

## [3.3.1] - 2026-05-26

### Added

- **MCP `outputSchema` on CheckResult-returning tools.** Follow-up to 3.3.0 (which deferred this): the registry-driven `check_*`/recon tools — every tool whose `tools/call` `structuredContent` is a `CheckResult` (51 tools) — now declare a lenient `outputSchema` in `tools/list`, letting strict MCP clients validate the `structuredContent` added in 3.3.0. The schema pins only the always-present keys (`category`, `score`, `passed`, `findings`) and permits any extra properties (`checkStatus`, `partial`, `metadata`, finding metadata), so any real CheckResult validates. Special-case tools that return custom shapes (`scan_domain`, `batch_scan`, `compare_domains`, `compare_baseline`, `generate_*`, etc.) intentionally declare no `outputSchema`. Additive — no tool-count or input-schema change.

## [3.3.0] - 2026-05-26

### Added

- **MCP `structuredContent` on tool-call results.** Every tool that returns structured data now sets the MCP-standard `structuredContent` object on its `tools/call` result, giving all LLM/clients a reliable machine-readable channel. Arrays are wrapped as `{ results: [...] }` and scalars as `{ value: ... }` (MCP requires an object); `null`/`undefined` omits the field. Set independently of `format` — the legacy `<!-- STRUCTURED_RESULT … -->` comment in `content` is preserved for backward compatibility. Per-tool `outputSchema` declarations are intentionally out of scope (clients treat unschematized `structuredContent` as opaque JSON).

## [3.2.1] - 2026-05-26

### Removed

- **`check_package_trust`** tool entirely (74 → 73 tools). Removed `PackageTrustArgsSchema`, `callReconPackageCheck`, `PackageTrustResponseSchema`, and `PackageTrustResult` from all SSOT surfaces.

## [3.2.0] - 2026-05-26

### Added

- **bv-recon integration (operator-only).** 12 new MCP tools backed by a new fail-soft `BV_RECON` service binding (absent by default → tools return `unprovisioned`; public/free surface unchanged). Tool count 62 → 74.
  - Sync: `check_package_trust` (npm/PyPI supply-chain verdict), `check_realtime_threat_feed` (intel-gateway feed).
  - Dedup-by-enrichment (additive, fail-soft) of `cymru_asn`, `check_lookalikes`, `check_fast_flux` with bv-recon threat intel.
  - Async start/poll: `scan_buckets_start`/`_status`/`_findings`; `osint_investigate_domain_start`/`_infrastructure_start`/`_supply_chain_start` with shared `osint_investigation_status`/`_report`.
  - Tier-gated people-OSINT: `osint_investigate_username_start`/`_email_start` (owner/enterprise only, deny-by-default, governance audit).

### Fixed

- Corrected `brand_audit_get_report` indentation in `tool-definitions.ts` (resolved a tool-sync hook false positive).

## [3.1.1] - 2026-05-25

### Fixed

- **Scoring no longer fluctuates on transient check failures.** A check whose execution failed (`checkStatus` timeout/error — e.g. a cold-start HTTP fetch timeout) is now **excluded from the weighted score (renormalized) and surfaced as n/a** in `notApplicableCategories`, instead of being forced to `0` and dragging the overall score. Genuinely-missing controls (`missingControl`) still count. Eliminates the 0↔real score swing observed on cold-start scans (e.g. blackveilsecurity.com HTTP Security). (#213)

## [3.1.0] - 2026-05-25

### Changed

- **HTTP-security check attributes Cloudflare WAF interceptions served as HTTP 403.** Both JS challenges and access blocks (commonly served as 403) are now detected via `cf-ray`/`cf-mitigated` + body fingerprints and short-circuit with `checkStatus: 'error'` plus `wafEvent`/`wafKind` metadata, instead of falling into the generic "blocked by security appliance" path. Also fixes a `checkStatus` inconsistency between 200-served and 403-served challenges. No scoring change; wrapper-only (no `@blackveil/dns-checks` change). (#211)

## [3.0.0] - 2026-05-24

Major bump: removes the `brand_audit_watch` MCP tool (breaking tool-surface change). All deployed to production across PRs #197, #200, #201, #202, #203.

### Removed

- **BREAKING: `brand_audit_watch` MCP tool removed.** Replaced by three single-purpose tools — `list_brand_audit_watches` (read-only), `register_brand_audit_watch` (write), `delete_brand_audit_watch` (destructive) — so read and destructive operations live in separate tools per the Anthropic Directory review criteria. Clients calling `brand_audit_watch` must migrate. Behavior (owner-scoping, SSRF re-validation, 20-watch cap, per-tier quotas) is unchanged. Tool surface 60 → 62.

### Changed

- **Tool annotations carry a real `destructiveHint`** — `ToolDef` gained a `destructive?` flag; the previously hard-coded `destructiveHint: false` now reflects it. `delete_brand_audit_watch` advertises `destructiveHint: true`. New audit `test/audits/tool-annotations.audit.test.ts` locks the directory review criteria (title present, names ≤64, read/destructive split, no prescriptive/injection language in descriptions).
- **`scan_domain` description rewritten** to describe behavior factually instead of steering Claude ("Use this whenever…", "Start here…") — the latter is treated as prompt injection at directory review.
- **`tools/list` wire response is MCP-spec-shaped** — server-specific `group`/`tier`/`scanIncluded` fields moved under the spec-sanctioned `_meta` object instead of leaking as top-level tool fields.

### Fixed

- **`register_brand_audit_watch` validates the watched domain** at register time (`validateDomain`/`sanitizeDomain`), rejecting SSRF/blocklist-class domains before the DB write instead of storing a row that fails every cron cycle (#201, closes #198).
- **`check_dnssec_chain` no longer reports a false "broken chain at `.`"** — an empty root DNSKEY is a trust-anchor retrieval failure (the root is always signed), now surfaced as a non-high "Root trust anchor unverified" note (#200).
- **`check_dnssec_chain` no longer caches `unverified`-root results** (marked `partial`), so a transient empty self-heals on the next request instead of persisting as a stale false-negative (#202, #199).
- **DoH secondary-resolver confirmations are no longer edge-cached**, removing a vector for persisting a transient empty at the edge (#203, #199).
- **`discover_subdomains` distinguishes "CT source unavailable" from "no subdomains found"** — a crt.sh failure no longer reports a false-definitive empty (#200).

## [2.27.0] - 2026-05-23

### Added

- **Per-IP rate limit on `POST /oauth/register`** (#193) — DCR was publicly reachable (`ENABLE_OAUTH=true`) with no per-IP gate. 10 registrations/min, 30/hr per `cf-connecting-ip`; returns HTTP 429 + `retry-after` header (OAuth 2.1 convention — not MCP JSON-RPC `-32029`). KV fixed-window pattern mirrors `tokenRateExceeded` in `src/oauth/token.ts`. Legitimate first-time DCR usage is single-digit per IP per day, so 10/min absorbs retries without enabling enumeration. Resolves `TODO(phase-10): add per-IP rate limiting before public exposure`.

### Changed

- **Deleted 4 deprecated re-export shims** (#193) — `src/handlers/tool-schemas.ts`, `src/lib/context-profiles.ts`, `src/lib/scoring-engine.ts`, `src/lib/scoring-model.ts`. All callers now import directly from `@blackveil/dns-checks/scoring` or `src/schemas/tool-definitions`. `src/lib/scoring-config.ts` survives trimmed to only the project-local `parseScoringConfigCached` memoized wrapper. New audit `test/audits/deprecated-shim-absence.audit.test.ts` prevents reintroduction.
- **Drizzle-kit npm scripts wired to existing scoped tenant configs** (#193) — `drizzle:check`, `drizzle:generate`, and `:registry`/`:tenant` variants point at the existing `src/tenants/db/drizzle.{registry,tenant}.config.ts`. Resolves `TODO(tenant-d1-schemas)` comment. No root config added — would have collapsed two physically separate D1 databases.
- **Contributor docs updated to canonical package paths** (#193) — `CONTRIBUTING.md`, `CLAUDE.md`, `docs/scoring.md`, `.github/instructions/{tools,schemas}.instructions.md`, and `.github/copilot-instructions.md` all now point at `packages/dns-checks/src/scoring/{model,engine,config,profiles}.ts` post-shim deletion. Stops the next contributor being sent to files that don't exist.

### Internal

- `.playwright-mcp/` (ephemeral MCP tool capture dir) and `**/dist.bak/` (stale build snapshots) now gitignored to prevent recurrence.

## [2.26.0] - 2026-05-23

### Added

- **Paywall: `discovery_mode='tiered'` requires developer tier or higher** (#188). The brand-discovery surface (`discover_brand_domains`, `brand_audit_single`, `brand_audit_batch_start`) accepts `discovery_mode='tiered'`, which activates the private `BV_INFRA_GRAPH` / `BV_INTEL_GATEWAY` / `BV_ENTERPRISE` Tier 0/1/2 lookups. Pre-2.26 a free/agent caller could trigger that path at the per-tool quota limit. Now: `Error: Invalid discovery_mode: 'tiered' requires developer tier or higher`. No-op on BSL self-hosts where the bindings aren't provisioned.
- **Paywall: `depth='deep'` requires developer tier or higher** (#191). Same three tools. `depth='deep'` expands candidate seeding + enrichment fanout (~3× the per-call compute cost of `standard`). New error string: `Error: Invalid depth: 'deep' requires developer tier or higher`.
- **Audit test pinning `TIER_TOOL_DAILY_LIMITS` + `TIER_DAILY_LIMITS` + `TIER_CONCURRENT_LIMITS`** to the published pricing matrix (#190). Drift between pricing decisions and runtime config now fails CI rather than surfacing in customer tickets.
- **Audit test pinning deps-surface parity** between `brand_audit_single` (sync request path) and the queue consumer (#186, landed earlier). Catches "field declared on `BrandAuditPipelineDeps`, populated by env, but never threaded into the deps object actually passed to the pipeline" gaps — same class as the two real bugs fixed in this release.

### Fixed

- **`BV_CERTSTREAM` now threaded into the brand-audit queue consumer's pipeline deps** (#185). Pre-fix, queued audits silently fell back to direct `crt.sh` for the SAN signal while sync audits used the dedicated `BV_CERTSTREAM` service binding. Closed via `BrandAuditConsumerDeps.certstream` + `processBrandAuditMessage` forwarding into `singleDeps` + `src/index.ts` queue-consumer construction.
- **`BV_CERTSTREAM` → `brandAuditQueue` forwarding gap closed via the same pattern** (#186). The pipeline's CSC fast→full deep_scan enqueue at `brand-audit-pipeline.ts:1061` only fires when `deps.brandAuditQueue` is present. Neither call site forwarded it, so `view='csc_complement'` audits silently produced only `csc_complement_fast` and the deep_scan job never ran. Now wired in both `handlers/tools.ts` (sync path) and `queue/brand-audit-consumer.ts` (queue path).
- **Best-effort try/catch around `deps.brandAuditQueue.send()` in `runBrandAuditPipeline`** (#186). Previously dead code; activating it via #185+#186 meant a transient Cloudflare Queues `send()` blip would propagate out and flip the audit row to `failed` even though `csc_complement_fast` had already been persisted. Now mirrors the `pdfQueue.send()` best-effort pattern: log on failure, audit completes normally.
- **CSC deep_scan double-enqueue race on retry pass** (#186). The Phase 2b retry-enqueue (`!isRetry && deps.brandAuditQueue` at line 411) preserves the original message including `view='csc_complement'`. The retry pass re-entered the CSC branch with `force_refresh=true`, wrote `csc_complement_fast` again, and enqueued a second `deep_scan` message — producing a race where two `runDeepScanFromStepStore` workers contended on `csc_complement_full` (last-write-wins UPSERT, no MVCC). Closed by also gating the forwarding on `!isRetry` so retry passes inherit no `brandAuditQueue` and skip the inner CSC enqueue.

### Changed

- Stale 2-arg-call invariant comment in `src/queue/brand-audit-consumer.ts` updated to reflect that any single binding-backed dep (not just tier closures) activates the 3-arg call form (#187).
- CLAUDE.md corrected: static `BV_API_KEY` resolves to `owner` tier (downgraded to `partner` if `OWNER_ALLOW_IPS` mismatches), not `agent`. `agent` daily quota corrected to 200/day (not 500). The earlier "Paid OAuth tiers" paragraph had drifted from the actual code at `src/lib/tier-auth.ts:246-253` (#189).
- One-line JSDoc on `TIER_TOOL_DAILY_LIMITS` explaining the intentional `partner.brand_audit_single = 200` < `enterprise.brand_audit_single = 500` inversion — the daily cap mirrors the monthly `BRAND_AUDIT_QUOTAS` budget so a customer can't burn their monthly allowance in one day (#192).

## [2.25.0] - 2026-05-22

### Added

- `view='csc_complement'` mode on `brand_audit_single` and `brand_audit_batch_start`, gated to OAuth `enterprise`/`owner` tier. Emits a structured `cscComplement` payload (attached to summary finding metadata) with anchor identity, registrar portfolio, shadow-IT highlights, defensive-registration labels (via new per-candidate MX + HTTP enrichment), and a deferred per-apex deep-scan that fills posture + dangling-DNS findings.
- `brand_audit_status` exposes new `stage` values: `fast_ready`, `deep_ready` (via `findings[].metadata.stage`).
- `brand_audit_get_report` attaches `cscComplement` payload (full → fast fallback) to summary finding metadata.

### Internal

- `src/lib/registrar-portfolio.ts` — pure aggregator bucketing candidates by registrar family.
- `src/lib/brand-audit-csc-enrichment.ts` — per-candidate DoH MX + safeFetch HTTP enrichment feeding `evaluateDefensiveRegistration`.
- `src/lib/brand-audit-csc-builder.ts` — fast-stage cscComplement payload builder.
- `src/lib/brand-audit-csc-deepscan.ts` + `brand-audit-csc-deepscan-job.ts` — queue-backed per-apex `scan_domain` + `discover_subdomains` orchestration; phase='deep_scan' messages on BRAND_AUDIT_QUEUE.
- `src/schemas/brand-audit-csc.ts` — `BrandAuditCscSchema` (v1).
- `src/lib/registrar-identity.ts` — exported `classifyRegistrarFamily()` helper.
- `src/queue/brand-audit-consumer.ts` — deep_scan branch with error containment + ack-on-error.

## [2.24.0] - 2026-05-21

### Added

- **Daily SPF canary** (`src/lib/spf-canary.ts`, `src/scheduled.ts`) — probes a curated stable-SPF domain set during the daily cron and emits a webhook alert (with failing domains attached) when the null-rate breaches `ALERT_SPF_NULL_RATE_THRESHOLD` (default 15%). Outcome is always logged so silent runs are distinguishable from clean runs. A 189-domain pre-flight on the SPF lookup path found zero false-null SPFs — the canary exists as a tripwire for the next "elevated null SPF" dashboard observation.

### Changed

- **`scan_domain` free-tier daily limit raised 5 → 25** (`src/lib/config.ts`) — unauthenticated callers now get 25 scans per IP per day instead of 5. Quota headers (`x-quota-limit`) and `-32029` error messages updated accordingly.

### Fixed

- **Rate-limiter short-circuit on `Infinity` limits** (`src/lib/rate-limiter.ts`) — `checkToolDailyRateLimit` and `checkGlobalDailyLimit` now return early when `limit` is non-finite, before the `QuotaCoordinator` DO call. `JSON.stringify(Infinity)` yielded `"null"`, which hit the `validateQuotaPayload` finite-number guard and returned HTTP 400 on legitimate owner-tier requests. The `limit <= 0` carve-out (e.g. agent-tier brand-audit deny) is preserved.

### Tests

- `test/lib/spf-canary.spec.ts` — threshold breach, clean run, and DNS-error paths.
- `test/rate-limiter.spec.ts` — Infinity short-circuit, global-cap Infinity, `limit=0` security guard.
- `test/index.spec.ts`, `test/freemium-limits.spec.ts` — assertions realigned with the new `scan_domain` cap.

### Dependencies

- Patch bumps: `hono` 4.12.18 → 4.12.21, `marked` 18.0.3 → 18.0.4, `typescript-eslint` 8.59.3 → 8.59.4, Cloudflare devtools group (3 updates).

## [2.23.0] - 2026-05-21

### Added

- **CSC registrar family expansion** — `Corporation Service Company`, `CSC Corporate Domains`, `CSC Digital Brand Services`, `CSC Global`, and their regional subsidiaries (AU/CA/Malaysia) now collapse to a single `CSC` family in both `src/lib/registrar-identity.ts` (off-primary gate) and `src/lib/brand-classification.ts` (analyst reason string). Verified against regional-alpha.example.com, regional-beta.example.com, regional-gamma.example.com — previously false-positively flagged as shadowIt.
- **Defensive typosquat label** (`src/lib/brand-defensive-registration.ts`) — candidates within Damerau-Levenshtein 2 of the target with minimal operational infrastructure (no MX, parked-NS apex, or HTTP redirect to target) are annotated with `defensive: true` + `defensiveReason`. Surfaces in markdown and PDF rendering. Bucket assignment unchanged. Heuristic abstains in production until candidate MX + HTTP-redirect enrichment is wired through discovery (TODO marked).

### Fixed

- **Consumer-cap → reaper dead-zone** — audits whose worker hit the 5-min consumer cap previously sat in `running` until the 15-min cron reaper. Read-path piggyback on `brand_audit_status` and `brand_audit_get_report` now synthesises `failed` for running rows past a 7-min deadline (anchored on existing `created_at` column — no schema migration). Cron reaper threshold tightened from 15min → 10min as the safety net for non-polled audits.

### Tests

- `test/registrar-identity.test.ts` + `src/lib/brand-classification.test.ts` — CSC family normalisation and bucket-level integration assertions.
- `test/brand-defensive-registration.test.ts` — 22 unit cases (distance, parking NS detection, signal precedence).
- `test/brand-audit-{status,get-report}.integration.test.ts` — dead-zone closure (synthesised failed, persisted UPDATE, in-deadline negative, D1 write failure swallow).

## [2.22.0] - 2026-05-21

### Added

- **Brand-audit report sidecar v4** — `qaSchemaVersion: 4`, `relationshipSchemaVersion: 1`. Clean per-relationship buckets at the top level: `registrarSprawl` (Shadow IT), `vendorDependencies`, `ownedPortfolio`, `impersonationSurface`. Legacy `buckets` and `counts` preserved for backward compatibility.
- **Shadow IT semantics tightened** — Shadow IT now strictly means "owned brand domains on off-primary registrar infrastructure." Vendor dependencies route to `buckets.indeterminate` and never pollute `buckets.shadowIt`.
- `src/lib/sprawl-invariants.ts` — pure validator enforcing registrarSprawl item quality (≥2 signals, `combinedConfidence` ≥ 0.5, registrar + registrarSource + evidence required, `relationshipType: 'owned_off_primary_registrar'`). Wired into `runBrandAuditPipeline` to downgrade failing items to `indeterminate`.
- `.claude/hooks/block-force-push.sh` — replaces the bare-string PreToolUse hook that fired against any stdout containing the phrase "Force push blocked." The new script `jq`-extracts `tool_input.command` and matches anchored `git push --force*` patterns only.
- bv-whois: hardened lookup + resolver with additional registrar shape parsing; extended RDAP fallback TLD list.

### Tests

- `src/lib/sprawl-invariants.test.ts` — 36 cases per invariant + sweep over fixture sidecars.
- `test/audits/sidecar-bucket-separation.audit.test.ts` — vendorDependencies disjoint from `buckets.shadowIt`; `shadowIt` mirrors `registrarSprawl`.
- `test/audits/sidecar-registrar-labels.audit.test.ts` — no "Unknown registrar" strings; `lookup_failed` only as a numeric counter.
- `test/contracts/brand-report-sidecar-v3.contract.test.ts` → `…-v4.contract.test.ts` — renamed; asserts `qaSchemaVersion === 4`, `relationshipSchemaVersion === 1`, drift guard against ambiguous top-level `schemaVersion`.
- `test/audits/pretooluse-hook-scope.node.test.ts` — 13 cases pinning the hook to command-string matching only.
- `test/audits/private-config-injection.node.test.ts` — ensures `inject-private-config.cjs` preserves public service bindings not overridden by the private overlay.

## [2.21.5] - 2026-05-20

### Changed

- **Brand discovery (BlackVeil production only)**: BlackVeil's hosted runtime at `dns-mcp.blackveilsecurity.com` now defaults `discover_brand_domains` / `brand_audit_*` to `discovery_mode: 'tiered'` when the caller omits the argument. The flip is gated entirely on the env var `BRAND_AUDIT_DISCOVERY_MODE_DEFAULT="tiered"` set in BlackVeil's private deploy overlay (`.dev/wrangler.deploy.jsonc`); the public Zod schema default in `src/schemas/tool-args.ts` stays `'classic'` permanently. **BSL boundary**: anyone building this repo from `main` continues to get classic mode out of the box and does not need the proprietary cross-Worker bindings (`BV_INFRA_GRAPH`, `BV_INTEL_GATEWAY`, `BV_ENTERPRISE`) that tiered mode relies on. An explicit caller-supplied `discovery_mode` always wins over the env default.
- Added the explicit `authoritative_dns_infra` scoring profile, which weights authoritative DNS infrastructure, DNSSEC, NS, and zone-hygiene evidence while treating ordinary mail/web controls as non-scoring noise.
- Disabled the paid `MadaBurns/blackveil-dns-action` CI workflow by renaming it to `.github/workflows/dns-security.yml.disabled`; active CI/CD now rejects that paid action path by audit.

### Added

- `BrandAuditPipelineOptions.env` — narrow runtime-env shim read by `runBrandAuditPipeline` so the BlackVeil-production env var can flip the default without breaking the schema contract for self-hosters.
- `ToolRuntimeOptions.discoveryModeDefault` and `BrandAuditConsumerDeps.discoveryModeDefault` — runtime-only plumbing from the queue/HTTP dispatch sites in `src/index.ts` through `src/mcp/{execute,dispatch}.ts`, `src/handlers/tools.ts`, and `src/queue/brand-audit-consumer.ts` into the pipeline.
- README section "Brand-discovery modes" describing the `classic` (BSL self-host default) vs `tiered` (operator-deploy only) split and the deployment story.
- CLAUDE.md operator-deploy-only binding rows for `BV_INFRA_GRAPH`, `BV_INTEL_GATEWAY`, `BV_ENTERPRISE`, and the `BRAND_AUDIT_DISCOVERY_MODE_DEFAULT` env var.
- `check_authoritative_dns_infra` and `check_root_server_set`, bringing the MCP tool surface to 59 tools and adding authoritative DNS infrastructure as the 18th scoring category.
- `BV_INFRA_PROBE` service-binding support plus an infra-probe worker skeleton for raw authoritative DNS, root-server, BGP/RPKI, and vantage-point evidence.
- Root-hint baseline evidence for worker-only deployments, so root-server checks return structured partial evidence even without live infra probing.
- Remediation/explanation content and attack-path integration for authoritative DNS route hijack, recursion exposure, and zone-transfer risk signals.

### Tests

- 5 new vitest cases in `test/brand-audit-pipeline.test.ts` pinning the env-override semantics: (1) tiered when env says tiered + caller omits; (2) caller wins over env; (3) unset env → undefined (BSL default path); (4) any env value other than the literal `"tiered"` is ignored; (5) env-defaulted tiered runs stamp `discoveryMode: 'tiered'` on the summary finding identically to explicit-tiered runs.
- Added authoritative DNS infra coverage, registration, scoring, Wrangler-binding, and root-server-set tests.
- Added README/docs drift audits for the 59-tool authoritative DNS infrastructure surface.
- Added an active-workflow audit preventing paid DNS scan actions from running in CI/CD.

### Fixed

- Filtered benign `workerd/api/web-socket.c++:828: disconnected: WebSocket peer disconnected` teardown noise from Vitest output.

## [2.21.4] - 2026-05-17

### Security

- Removed tracked internal tenant and commercial planning documents from the public repository.
- Scrubbed customer-placeholder references from docs, comments, and chaos output.
- Tightened gitleaks coverage for customer-name placeholders while allowing timestamp-shaped SQL seed values.

### Changed

- Restricted the root npm package publish surface to `dist`, `LICENSE`, and `README.md` so npm releases do not include repo internals, tests, scripts, workflows, docs, or build caches.

### Tests

- Added an npm publish-surface audit that fails if the root package allowlist exposes internal repo paths.

## [2.21.3] - 2026-05-17

### Fixed

- Restored production customer OAuth consent routing by deploying `BV_WEB_OAUTH_CONSENT_URL` for `/oauth/authorize` while keeping legacy owner-key browser consent disabled.
- Added production redirect probing so `/oauth/authorize` must redirect to the bv-web customer consent URL with OAuth parameters preserved instead of returning `503 OAuth customer login is not configured`.

### Changed

- Deploy and release workflows now verify OAuth smoke health and customer-consent redirect behavior after Worker deployment.
- Production OAuth runbook now documents the customer redirect probe and required secrets.

### Tests

- Added an audit test for production OAuth Worker vars, bv-web service binding, secret hygiene, and deploy/release verification coverage.
- Added Python unit tests for `scripts/oauth/prod-probe.py --mode=redirect`.

## [2.21.2] - 2026-05-16

### Changed

- Release hardening only: no public API, runtime tool behavior, bindings, or schema changes.
- Bumped `@blackveil/dns-checks` workspace metadata to `1.1.3` so the tag-driven release workflow can publish both npm packages without colliding with the already-published `1.1.2` workspace package.

### Tests

- Added `test/chaos/varied-domain-all-tools.chaos.test.ts`, a deterministic offline chaos matrix that drives every registered MCP tool through `handleToolsCall` across varied domain fixtures and asserts `scan_domain` still covers every `scanIncluded` tool category.
- Tightened two existing test fixtures so release lint/typecheck stays clean under the current toolchain.

## [2.21.1] - 2026-05-15

### Completed — Phase 4 follow-up: watch diff + webhook delivery

v2.21.0 shipped the cron enqueue half of the watch loop and the webhook payload contract, but left the diff-and-deliver half as a follow-up. v2.21.1 closes that gap — when a watch-originated audit completes, the consumer now computes the classification fingerprint, compares it to the watch's `last_classification_hash`, and (when shifted + a `webhook_url` is configured) POSTs the diff payload via `safeFetch`.

### Added

- **`src/lib/brand-audit-classification-diff.ts`** — pure helpers: `computeClassificationHash(result) → string` (SHA-256 hex of sorted (domain, bucket) tuples; order-independent, summary-row-independent) and `computeDiff(previous, current) → { added, removed, modified }`. Both Worker-runtime-safe, no I/O.
- **`BrandAuditQueueMessageSchema`** gains optional `watchId` + `ownerId` fields — already produced by the v2.21.0 cron handler; v2.21.1 makes the consumer parse and consume them.
- **`BrandAuditConsumerDeps.deliverWebhook`** — injectable webhook deliverer (production default: `safeFetch`-wrapped POST returning `boolean`). Lets the consumer remain offline-testable.
- **Webhook delivery wiring in `processBrandAuditMessage`** — after a watch-originated target completes:
  1. Look up the watch row (defense in depth: confirm `message.ownerId === watch.owner_id`)
  2. Compute the new classification hash
  3. If hash matches `last_classification_hash`, no-op
  4. Otherwise persist the new hash **before** any delivery attempt (idempotency: redelivery of the same completed message can't re-fire)
  5. If `webhook_url` is set, fetch the prior CheckResult to compute the actual diff, then POST the `BrandAuditWatchWebhookPayloadSchema`-shaped payload
- **`src/schemas/brand-audit-watch-webhook.ts`** now exports the `BrandAuditBucket` type alongside the existing schema, so the diff module can reference it cleanly.

### Tests

- `test/brand-audit-classification-diff.test.ts` — 10 unit tests covering hash determinism (order-independence, summary-row ignoring) and diff branches (added/removed/modified, all-three-mix, empty-diff).
- `test/chaos/brand-audit-webhook-delivery.chaos.test.ts` — 6 chaos invariants:
  - Webhook 500 → audit completion is unaffected (target still completes)
  - Hash persisted **before** delivery → idempotent under redelivery
  - No `webhook_url` → drift detected, hash persisted, no fetch attempted
  - Cross-owner spoof (`message.ownerId != watch.owner_id`) → no hash update, no fetch
  - Same classification (no drift) → no fetch, no hash update
  - Delivery throws → audit still completes cleanly (fail-soft)

### Changed

- No new tools. No new bindings. No new schema migrations. Purely wiring + tests on top of v2.21.0.
- No tool-count cascade — tool surface stays at 57.

### Operator action required (deploy)

- None. Watches registered against v2.21.0 will start receiving webhooks on the next cron-driven drift after deploying v2.21.1.

### Known follow-ups (v2.21.3+)

- **Wrong-baseline diff under ad-hoc activity**: the prior-result lookup picks the most recent completed audit by this owner for this target — not the previous _watch tick's_ audit. If the same owner runs `brand_audit_single('apple.com')` ad-hoc between two watch ticks, that ad-hoc result becomes the "prior" baseline. Diff is then computed against the wrong audit and can mislead. Fix: add `last_audit_id` to `brand_audit_watches` + look up by exact audit_id.
- **No HMAC on webhook payloads**: receiver can't verify a delivery came from Blackveil. Standard practice is `X-Blackveil-Signature: hmac-sha256(secret, body)`. Same gap exists on the legacy `ALERT_WEBHOOK_URL`, so it's not a regression. Bundle both with the wrong-baseline fix.

## [2.21.0] - 2026-05-15

### Added — Brand audit Phase 4: scheduled monitoring + monthly quota enforcement

- **`brand_audit_watch` MCP tool** — register / list / delete recurring brand-audit watches. Single tool with an `action` discriminator. Owner-scoped (cross-owner deletes surface as `notFound`, never `accessDenied`). Per-principal cap of 20 active watches. Webhook URL re-validated via `validateOutboundUrl` at both register and delivery time (SSRF defense).
- **`brand_audit_watches` D1 table** (`src/lib/db/brand-audit-schema.ts`) — id, owner_id, domain, interval (daily/weekly/monthly), webhook_url, last_run_at, last_classification_hash, active, created_at. Indexed on `(owner_id, created_at)` and `(active, last_run_at)`.
- **`handleBrandAuditWatches`** (`src/scheduled.ts`) — cron handler that enumerates active watches whose `last_run_at` is older than their interval, enqueues a fresh `brand_audit_batch_start` per due watch, bumps `last_run_at`. Bounded per-tick by `MAX_WATCHES_PER_TICK = 100`. Fails soft on D1 errors (logged + skipped, doesn't crash the cron tick). Wired into the existing `*/15 * * * *` cron in `src/index.ts`.
- **`src/schemas/brand-audit-watch-webhook.ts`** — published Zod schema for the diff webhook payload (`{ schemaVersion, watchId, auditId, target, interval, detectedAt, previousHash, currentHash, changes: { added, removed, modified } }`). Locked here so downstream consumers (customer receivers, bv-web alert UI) have a wire-format contract that requires a `schemaVersion` bump to change.

### Changed — Monthly brand-audit quota enforcement (carryover from Phase 1)

- **`enforceBrandAuditQuota` is now actually called at runtime.** The helper + `BRAND_AUDIT_QUOTAS` constant shipped in v2.18.0 as a Phase-1 building block; v2.19.0 documented it as a deferred wiring task. v2.21.0 closes that gap: the dispatcher constructs a closure binding `principalId + authTier + rateLimitKv` and passes it as the `enforceQuota` dep into `brand_audit_single` and `brand_audit_batch_start`. The daily caps via `TIER_TOOL_DAILY_LIMITS` continue as a first-line check; the monthly UTC-window cap (`BRAND_AUDIT_QUOTAS`) now applies on top — free/agent=0, developer=50/mo, partner=200/mo, enterprise=500/mo, owner=unlimited.

### Tests

- `test/brand-audit-watch.integration.test.ts` — 7 unit tests (register happy path, SSRF webhook rejection, no-webhook register, watch-limit cap, list, delete, cross-owner notFound).
- `test/scheduled/brand-audit-cron.spec.ts` — 5 cron-handler tests (missing DB no-op, due watches enqueued, watch cap is bounded, missing queue fails soft, D1 enumeration failure fails soft).
- `test/contracts/brand-audit-watch-webhook.contract.test.ts` — 7 contract tests covering required fields, `schemaVersion` lock, hash format validation, bucket enum, required collections.
- `test/audits/brand-audit-watch-webhook.audit.test.ts` — 3 audit tests asserting the schema covers every documented field.
- Tool-count assertion cascade 56 → 57 across `test/{tool-metadata,tool-schemas,handlers-tools,index,schemas/tool-args,schemas/tool-definitions}.spec.ts`; `NON_SCAN_TOOL_NAMES` gets the new `brand_audit_watch` entry.

### Operator action required (deploy)

- **Schema apply**: `wrangler d1 execute brand-audit-v1 --remote --command "<paste brand_audit_watches CREATE TABLE>"` (full SQL inline in `docs/provisioning/brand-audit-bindings.md`).
- **No new bindings**: watches reuse `BRAND_AUDIT_DB` + `BRAND_AUDIT_QUEUE` from v2.19.0. The existing `*/15 * * * *` cron in `wrangler.jsonc` already covers the new handler.
- **Quota visibility**: the monthly enforcement now actually meters. Customers on `developer` who burned 50 audits in one day will be blocked for the remainder of the calendar month (UTC reset). Communicate the change before flipping.

## [2.20.0] - 2026-05-15

### Added — Brand audit Phase 3: PDF rendering via BV_BROWSER_RENDERER + R2

- **`src/lib/brand-audit-html-template.ts`** — pure, Worker-runtime-safe HTML template extracted from `scripts/brand-audit-brand-audit.spec.ts`. Single function `renderBrandAuditHtml(input) → string`. Same input always produces same output (no Date.now, no random IDs — date is an injected parameter so tests can lock it). XML-escapes every user-controlled interpolation (defense against unescaped script/CSS in registrar/domain strings). Dark Blackveil palette + Google Fonts, mirroring the existing report styling.
- **`src/lib/brand-audit-pdf.ts`** — `renderBrandAuditPdf(result, target, options)` wraps the template + posts to `BV_BROWSER_RENDERER` service binding (`POST /pdf`, JSON body `{ html }`, returns PDF bytes). Throws `browser_renderer_failed: <status>` on non-2xx so the consumer can map cleanly to a retry verdict.
- **`src/lib/r2-signed-url.ts`** — `generateR2SignedUrl(bucket, key, ttlSeconds=604800)` mints time-limited signed URLs via the R2 binding's `createSignedUrl`. 7-day default. Path-traversal guard rejects empty / oversize / `..`-containing / leading-`/` keys before signing.
- **`src/queue/brand-audit-pdf-consumer.ts`** — separate Cloudflare Queue consumer (`brand-audit-pdf-queue`, `max_batch_size=1` since Browser Rendering is single-request). For each `{ auditId, target, format }` message: idempotency check (skip if `pdf_r2_key` already set), reads `result_json` from D1, renders PDF, writes R2 at `audits/{auditId}/{target}.pdf`, updates `brand_audit_targets.pdf_r2_key`. Transient renderer/R2 failures → retry. Decoupled from the primary brand-audit-queue so audit `completed` doesn't wait for PDF render.
- **`brand-audit-consumer` fanout** — on per-target completion AND `format ∈ {markdown, both}` AND `BRAND_AUDIT_PDF_QUEUE` bound, sends a follow-up `{ auditId, target, format }` to the PDF queue. Best-effort: a send failure is swallowed (PDF is enrichment, not the durability boundary).
- **`brand_audit_get_report` PDF URL surface** — when `target.pdf_r2_key` is set AND `BRAND_REPORTS` R2 binding is wired, the response summary now carries `pdfUrl: string` (7-day signed). When the target is complete but PDF still pending, surfaces `pdfPending: true`. When `format=json` (no PDF requested), `pdfPending: true` indefinitely — clients shouldn't poll for a PDF that won't be rendered. CHANGELOG note: the per-target contract schema gained `pdfUrl: string | null` and `pdfPending: boolean`.
- **`src/index.ts` queue dispatch** — third route added for `batch.queue === 'brand-audit-pdf-queue'`. Routes to `handleBrandAuditPdfQueue` with `BRAND_AUDIT_DB`, `BRAND_REPORTS`, `BV_BROWSER_RENDERER` deps. Missing bindings → ack-all (no hot loop) until operator provisions per the runbook.
- **`docs/provisioning/brand-audit-bindings.md`** — extended with the new PDF queue + R2 + `BV_BROWSER_RENDERER` service binding declarations.

### Changed

- **`ToolRuntimeOptions`** extended with `brandReportsR2?: R2Bucket` and `browserRenderer?: Fetcher` for downstream wiring.
- **`brand_audit_get_report` per-target response contract** — added `pdfUrl: string | null` and `pdfPending: boolean` (locked in `test/contracts/brand-audit-status.contract.test.ts`).

### Operator action required (deploy)

- **New resources**: `wrangler queues create brand-audit-pdf-queue`. R2 bucket `bv-brand-reports` was declared in v2.19.0 ops doc but only Phase 3 actually writes to it — provision it now if you haven't.
- **`BV_BROWSER_RENDERER` service binding**: the `bv-browser-renderer` Worker must already be deployed in the account. Wire it in `.dev/wrangler.deploy.jsonc` per the updated provisioning doc.
- **Until provisioned**: PDF rendering is a no-op — the primary brand-audit flow still works, but `pdfUrl` will be `null` and `pdfPending` will read `true` after completion. No 500s, no hot loops.

## [2.19.0] - 2026-05-15

### Added — Brand audit Phase 2: async batch via queue + D1 state

- **`brand_audit_batch_start` MCP tool** — async producer for up to 50 targets per call. Validates + deduplicates the domain list, writes the parent `brand_audits` row to D1, enqueues one `{ auditId, target, format, min_confidence? }` message per target to `BRAND_AUDIT_QUEUE`. Returns `{ auditId, queuedAt, targetCount, etaSeconds, format, targets }` immediately so the caller can poll instead of holding a multi-minute connection open. **Quota model in v2.19.0 is daily** via `TIER_TOOL_DAILY_LIMITS` (developer=50/day, partner=200/day, enterprise=500/day; free/agent=0). The `BRAND_AUDIT_QUOTAS` constant + `enforceBrandAuditQuota` helper (shipped in v2.18.0 as a Phase-1 building block) describe a monthly window and remain a Phase 4 follow-up — the orchestrator accepts an injectable `enforceQuota` dep already, but the dispatcher wires only the daily gate today.
- **`brand_audit_status` MCP tool** — read-only D1 lookup that returns audit-level status, progress (`'N/M'`), and per-target statuses. Owner-scoped (someone else's auditId surfaces as `notFound`, never `accessDenied` — ID-enumeration defense). 10s cache to absorb tight polling loops without lying about progress.
- **`brand_audit_get_report` MCP tool** — fetches the result JSON for a completed audit. With `target` set, returns the per-target `CheckResult`; without, returns the audit-level aggregate. Returns `notReady` when polling against an in-flight audit. 60s cache. Phase 3 will add R2 signed-URL PDF retrieval; this v2.19.0 version returns inline JSON only.
- **`src/queue/brand-audit-consumer.ts`** — Cloudflare Queue consumer. For each `{ auditId, target }` message: idempotency check (SELECT status FROM brand_audit_targets — duplicate delivery of a completed/failed target acks without re-running brandAuditSingle, preserving budget under at-least-once delivery), status flip → `'running'`, run `brandAuditSingle`, persist result_json + final status, atomic counter tick. Marks audit `completed` when `completed_targets === total_targets`. Per-message timeout `BRAND_AUDIT_MESSAGE_TIMEOUT_MS = 300_000` (5 min, distinct from the scan-queue's 20s). Wire-format validated by Zod (`BrandAuditQueueMessageSchema`) as defense in depth.
- **D1 schema** (`src/lib/db/brand-audit-schema.ts`) — two tables: `brand_audits` (parent, status state-machine, total/completed counters, format, aggregate `results_json`) + `brand_audit_targets` (children, composite PK on `audit_id+target`, per-target `result_json` + `pdf_r2_key` for Phase 3). Index on `(owner_id, created_at)` for owner audit-list queries.
- **`docs/provisioning/brand-audit-bindings.md`** — operator runbook for one-time provisioning: `wrangler d1 create brand-audit-v1`, `wrangler queues create brand-audit-queue`, schema apply via `wrangler d1 execute --file=-`, plus the `.dev/wrangler.deploy.jsonc` snippet (private binding declarations).
- **Per-tier daily overrides** for the three new tools in `TIER_TOOL_DAILY_LIMITS` matching `BRAND_AUDIT_QUOTAS` (free/agent=0, developer=50 batch + 5000 polls, partner=200/10000, enterprise=500/25000). Free/agent blocked by `FREE_TOOL_DAILY_LIMITS.brand_audit_{*}=0`.
- **Chaos test** (`test/chaos/brand-audit-consumer.chaos.test.ts`) — locks the idempotency invariant: a duplicate delivery of a terminal-state target row must ack without re-running brandAuditSingle and without mutating D1.
- **Contract test** (`test/contracts/brand-audit-status.contract.test.ts`) — Zod-validated response shapes for batch-start, status, and get-report (target + aggregate modes).

### Changed

- **`brand_audit_single` candidate-fanout cap** (`src/tools/brand-audit-single.ts`) — applies the 5-line defensive cap flagged in the v2.18.0 security audit. Discovery output is sliced to `MAX_CANDIDATES_PER_AUDIT = 200`; the summary now carries `{ truncated: boolean, truncatedAt: number, discoveredTotal: number }` so callers can detect a capped audit. Bounds outbound RDAP fanout regardless of how wide discovery's SAN/NS coverage grows.
- **Queue dispatch** (`src/index.ts`) — the Worker's `queue:` handler now routes by `batch.queue` between `bv-scanner-queue` (tenant scans) and `brand-audit-queue` (Phase 2). Existing scanner-queue path unchanged. Switched the existing `console.log` to structured `logEvent` per project logging convention.
- **`ToolRuntimeOptions`** (`src/handlers/tools.ts`) — plumbing-only: added `brandAuditDb?: D1Database`, `brandAuditQueue?: BrandAuditQueueProducer`, `rateLimitKv?: KVNamespace`, `principalId?: string` for the three new tools.

### Operator action required (deploy)

- Provision `brand-audit-v1` D1, `brand-audit-queue` queue, and `bv-brand-reports` R2 bucket per `docs/provisioning/brand-audit-bindings.md`. Apply the schema (SQL inlined in the doc). Add the binding declarations to `.dev/wrangler.deploy.jsonc`. Then `npm run deploy:prod`. **Until these are provisioned, the three new tools return a `{ unprovisioned: true }` error finding rather than 500-ing**, so the surface is safe to ship before infrastructure is in place.

## [2.18.0] - 2026-05-15

### Added

- **`brand_audit_single` MCP tool** — synchronous one-target brand-portfolio audit. Composes `discoverBrandDomains` (all 8 signals) → parallel `checkRdapLookup` (concurrency=10) → `classifyCandidate` and emits a `CheckResult` with one finding per candidate plus a summary. Candidates land in one of four buckets (`consolidated` / `shadowIt` / `indeterminate` / `impersonation`) with severity mapped accordingly (info / medium / low / high). Cached 1h. Phase 1 of the brand-audit MCP suite — the sync sibling of the future async `brand_audit_batch_start` queue path. Findings emit under the existing `brand_discovery` CheckCategory (no scoring-union expansion) — the bucket lives in `metadata.bucket`, so production scan_domain scores are unchanged.
- **`src/lib/brand-audit-quota.ts`** — per-tier monthly target quotas (`BRAND_AUDIT_QUOTAS`) — Phase 1 building block. Free/agent=0, developer=50, partner=200, enterprise=500, owner=unlimited. Counter aligned to UTC calendar month, stored on `RATE_LIMIT` KV with `brand_audit:` prefix; fail-open on KV errors. Runtime enforcement is split: the existing per-tool daily quota system (`FREE_TOOL_DAILY_LIMITS.brand_audit_single = 0`, `TIER_TOOL_DAILY_LIMITS.agent.brand_audit_single = 0`) gates free + agent immediately; the full monthly enforcement helper (`enforceBrandAuditQuota`) wires into the dispatcher in Phase 2 alongside the async batch path.
- **`src/lib/brand-audit-markdown.ts`** — compact Markdown formatter for `brand_audit_single` results, mirroring the `format-report` pattern (sanitized output, bucket-grouped sections, quota / missingControl branches).

### Changed

- **`src/lib/brand-classification.ts`** — moved from `scripts/lib/brand-classification.ts` (and `.test.ts`) into production source so `brand_audit_single` can compose it. 32 existing classifier tests remained green throughout the move. The `scripts/brand-audit-brand-audit.spec.ts` import path updated to `../src/lib/brand-classification`.

## [2.17.0] - 2026-05-15

### Added

- **Four new brand-discovery signals** for `discover_brand_domains`: `http_redirect`, `mx_overlap`, `spf_include`, `cname_alignment`. Targets the defensive-portfolio gap that SAN/NS/DKIM/DMARC don't see for tier-1 brands — when amazon/microsoft/nike's alt-TLD assets don't share certs/NS/DKIM/DMARC with the seed, these signals catch them via operational DNS/HTTP behavior instead. `http_redirect` follows up to 3 HTTP redirects from `https://<candidate>/` and consolidates when the chain terminates at the seed's apex or a subdomain (default conf 0.95, near-deterministic). `mx_overlap` compares MX RRsets, with shared-SaaS multi-tenant downgrade and tenant-prefix matching (default conf 0.7, bumped to 0.9 on full candidate-side alignment under seed apex). `spf_include` walks the SPF include graph (RFC 7208 §4.6.4 10-lookup cap) and consolidates when any include is seed-rooted (default conf 0.85). `cname_alignment` walks CNAME chains up to 5 hops and consolidates when the chain terminates at the seed apex (conf 0.9) or a known CDN edge alias like `<seed>.akadns.net` / `<seed>.edgesuite.net` (conf 0.6). All four detectors are pure modules in `src/tenants/discovery/` with the `Detector(seed, { candidateDomains, ... }) → { coOwnedDomains, queryStatus }` shape. 33 new unit tests.
- **Brand-classification module** (`scripts/lib/brand-classification.ts`): pure classifier extracted from inline spec logic. 8 ordered rules — subdomain check first; registrant-organization match (new Rule 1.5); strong infra signal (`san`/`ns`/`dkim_key_reuse`); high-confidence `dmarc_rua`; matching registrar family + ≥2 corroborating signals; redacted/notfound source → indeterminate; high-confidence non-infra signal → shadowIt; medium-confidence → indeterminate; low-confidence → impersonation. 32 unit tests covering each rule + edge cases.
- **4th `indeterminate` bucket** in `brand-audit-brand-audit.spec.ts` output JSON + PDF template. Routes candidates whose registrar source is `redacted` (DENIC `.de`, etc.) or `notfound` separately from shadowIt/impersonation so genuine "can't determine" cases aren't mis-classified.
- **Expanded ccTLD coverage**: `brand-audit-brand-audit.spec.ts` `TLDS` list grew 15 → 40 entries (added `.jp`, `.kr`, `.cn`, `.tw`, `.in`, `.au`, `.nz`, `.za`, `.br`, `.mx`, `.cl`, `.ar`, `.es`, `.it`, `.nl`, `.be`, `.ch`, `.at`, `.pl`, `.cz`, `.se`, `.no`, `.dk`, `.fi`, `.ie`, `.ru`, `.tr`). Tier-1 brand defensive portfolios are global; the prior 15-TLD list silently dropped half their assets from caller-asserted candidate pools.

### Changed

- `brand-audit-brand-audit.spec.ts` now opts into all 8 discovery signals (4 existing + 4 new).
- Registrar lookup threads `registrant` organization from RDAP `entities[].vcardArray` through to the classifier; Rule 1.5 (registrant match) consolidates candidates whose registrant normalizes to the same string as the seed's, regardless of registrar family. Matters because MarkMonitor / BrandAudit / Com Laude manage many brands — registrar family is too coarse, but the registrant column distinguishes Apple Inc. from Google LLC.
- `brand-audit-brand-audit.spec.ts` `INFRASTRUCTURE_DOMAINS` inline Set deleted; spec now imports `isInfrastructureProvider` from `src/tenants/discovery/infrastructure-providers.ts` (50+ vendors vs the stale 28-entry inline list).
- Registrar lookups parallelized inside each target (concurrency=10) — the WHOIS fallback's per-candidate TCP/43 round-trips were turning every tier-1 target into a ~13 min run; concurrency brings each target back under 2 min.

### Fixed

- `lookupRegistrar` in `brand-audit-brand-audit.spec.ts` was reading `registrar` from one finding and `registrarSource` from a different finding (whichever came first). When RDAP returned empty registrar AND WHOIS subsequently filled in `redacted`, source would be picked from the RDAP finding (`unknown`) instead of the WHOIS finding (`redacted`) — silently breaking the indeterminate-bucket rule. Fixed to read both fields from the same finding (preferring the one with a populated registrar; falling back to the last source-carrying finding).
- Subdomain check now runs first in the classifier — was previously after the registrar-family check, so a subdomain of the target with a coincidental registrar-family match was bucketed as consolidated but lost the `'Organizational Subdomain'` forensic note.

## [2.16.0] - 2026-05-15

### Added

- **bv-certstream `/sans` integration for SAN-sibling discovery**: `discover_brand_domains`'s SAN signal (`correlateSans`) now prefers the `BV_CERTSTREAM` service binding when present, falling back to direct crt.sh on failure. Mirrors the existing `/enumerate` pattern used by `discoverSubdomains` but with a distinct `/sans?domain=X` endpoint — different crt.sh query shape (`?q=X` apex vs `?q=%.X` subdomain) and different consumer-side filter (siblings keep cross-brand names; subdomains strip them). Threaded `certstream` through `DiscoverBrandDomainsOptions` and the `discover_brand_domains` tool registry. Routes traffic through Cloudflare egress (less IP-throttled than direct user-side calls) with the worker's 30s timeout cap (vs bv-mcp's 15s). Companion worker change: `bv-web/cloudflare/certstream-worker` (`/sans` route + `queryCrtShSans` handler).

### Fixed

- **SAN-correlator silently dropped tier-1 brand candidates under crt.sh throttling**: `correlateSans` was single-shot — one fetch attempt, error/timeout/429 silently returned an empty SAN bucket. Surfaced by the BrandAudit brand audit where amazon.com, microsoft.com, brand-zeta.example.com returned **zero candidates** despite high-confidence brand asserts; investigation showed `signalStatus.san: 'error'` for all three while ns/dmarc_rua/dkim_key_reuse succeeded. crt.sh is heavily IP-throttled and intermittently 5xx's on tier-1 brand queries (verified: direct `curl --max-time 20` to crt.sh timed out for 4 of 5 sampled brands during the audit run). Added jittered exponential-backoff retry (default 2 retries, 500ms base × 2^attempt with ±50% jitter) inside `correlateSans` — only on transient `error`/`rate_limited`/`timeout` results; partial-success (stream cap hit) is `ok` and not retried. New `maxRetries`/`initialBackoffMs`/`sleepFn` options for test override.

## [2.15.0] - 2026-05-15

### Added

- **WHOIS fallback via bv-whois shim Worker (PR #116)**: Resolves the "17 of 44 candidates return Unknown registrar" gap exposed by the BrandAudit audit — ccTLDs `.me/.de/.co/.us/.sh/.io` don't have public RDAP servers. Self-hosted WHOIS-over-TCP/43 shim Worker with KV-backed referral cache (7-day TTL, 15 hardcoded fast-path TLDs, live IANA fallback) and Hono `POST /lookup` route. Service-binding wired into `check-rdap-lookup` via new `BV_WHOIS` binding (mirrors `BV_CERTSTREAM` pattern); fallback fires at all 3 RDAP failure paths and fails open if the binding throws. New `metadata.registrarSource: rdap | whois | redacted | notfound | unknown` field surfaces provenance per finding.
- **`@blackveil/dns-checks/whois` sub-export**: Pure parser primitives (`parseWhoisResponse`, `parseIanaReferral`, `MAX_RESPONSE_BYTES`) usable from both bv-mcp and bv-whois without code duplication. 26 parser unit tests against real captured registry fixtures.
- **`packages/bv-whois/` workspace**: 6 source files (transport / resolver / lookup / app / index + Hono router) with 34 tests covering TCP transport, SSRF host validation, IANA referral cache, response-size cap, body-length enforcement (defends against chunked-encoding bypass), and Zod-validated request/response shapes.

### Fixed

- **BrandAudit brand audit RDAP extraction (PR #114)**: Extraction matched on `f.title.includes('Registrar')` but the actual finding title is `'Registration details'` — every candidate came back with `registrar: 'Unknown'`. Fixed to extract from structured `f.metadata.registrar`. Also corrected the classification baseline: was hardcoded `BrandAudit`, now uses each target's own registrar family with MarkMonitor / Com Laude / SafeNames variant normalization. Classification shifted from `0 consolidated / 47 shadow-IT` (largely incorrect) to `23 consolidated / 17 sprawl / 4 impersonation`.
- **CLAUDE.md drift (PR #115)**: Version reference, tool count, missing source-layout entries (`src/tenants/`, `src/oauth/`, several `src/lib/` modules), missing CI/CD workflows, `deploy:private` → `deploy:prod` (the former doesn't exist in `package.json`), `npm run dev` → `npx wrangler dev`. Trimmed redundant sections.

### Security

- **Closed 3 self-review findings before merging WHOIS feature**:
  - Octal IPv4 bypass in `validateHost` (e.g. `0177.0.0.1` → 127.0.0.1 via legacy octal parsing): reject any hostname whose every label is purely numeric.
  - Body-size cap bypass in `POST /lookup`: read body as text and enforce `MAX_BODY_BYTES` on actual length (Content-Length-only checks bypassable via chunked encoding).
  - Unvalidated shim response shape: Zod-validate `WhoisFallbackPayload` from `bv-whois` instead of casting; malformed payload → `source: 'error'`.
- Residual risk acknowledged: DNS rebinding (validateHost runs before DNS resolution). Mitigated by trust model — WHOIS server hostnames come only from the hardcoded TLD→server map or IANA referrals, both trusted sources.

### Changed

- `.gitleaks.toml` allowlist paths for `real-ipv4-address` and `phone-number` rules include `/__tests__/` (Vitest/Jest-style colocated test dirs) — consistent with the `real-email-address` rule's existing allowlist. Captured IANA contact data in test fixtures no longer trips false positives.
- Default `vitest.config.mts` excludes `scripts/brand-audit-*.spec.ts` — calibration specs that use `fs.readFileSync` belong in the node-env `vitest.calibration.config.mts`.

## [2.14.2] - 2026-05-14

### Fixed

- **SCAN_CACHE put-then-delete anti-pattern (Cluster F5, bv-web 2026-05-14 analytics)**: `bv-dns-security-mcp-SCAN_CACHE` was showing 27M puts paired with 13M deletes over a 7-day window. Root cause: `runWithCacheTracked` cached every result, then partial results (e.g. lookalike-timeout fallbacks) were immediately `kv.delete()`'d at the callsite in `src/handlers/tools.ts`. Added optional `shouldCache?: (result: T) => boolean` predicate to `runWithCache` + `runWithCacheTracked`; callsite passes `(r) => !r.partial` so partial results skip the put entirely. Side benefit: closes a sub-ms consistency window where a partial result could leak to a concurrent reader between put and delete. (PR #113)

## [2.14.1] - 2026-05-14

### Changed

- **CI tooling only — no runtime changes**: `@cloudflare/vitest-pool-workers` bumped 0.15.2 → 0.16.4. Added `test.dangerouslyIgnoreUnhandledErrors: true` to `vitest.config.mts` to suppress miniflare's pool-teardown WebSocket-disconnect events that vitest was reporting as 2 file-level errors even when 3103/3103 test assertions passed — the events come from workerd's communication WebSocket on shutdown, not from any test code. Force-set `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` across all seven active workflows to silence the Node 20 deprecation warning while keeping action pins at v4 (avoids breaking-change risk from a major bump).
- **CHANGELOG backfilled for 2.14.0**: The 2.14.0 release commit was written before PR #111's discovery-precision fixes landed and only mentioned the Shadow Domain fix + esbuild override. The full 2.14.0 entry now reflects what actually shipped — corroboration gate, expanded infrastructure-providers allowlist, caller-asserted bypass, Slice 6 multi-tenant NS filter, streaming crt.sh SAN parser, Markov generator, shared infrastructure-providers module.

## [2.14.0] - 2026-05-13

### Added

- **Brand-discovery corroboration gate**: A candidate must be corroborated by ≥2 distinct signals OR be a single near-deterministic signal (`dkim_key_reuse`). Closes the LR-1..LR-3 leakage paths from the v2.14.0 "Zero False Positive" precision audit — single-signal `dmarc_rua@0.6` no longer surfaces unknown third-party aggregators (LR-1), single-signal NS no longer surfaces commodity-DNS / parking co-tenants (LR-2), and the `INFRASTRUCTURE_PROVIDERS` allowlist expanded 11 → 57 entries to cover known TLD-variant evasions like `cloudflare.io` / `salesforce.io` / `hubapi.com` and user-named gaps like `outlook.com` / `amazonses.com` / `mailgun.org` (LR-3).
- **Caller-asserted domain bypass**: Domains the operator passes in `candidate_domains` bypass the corroboration gate even at single-signal NS — the explicit listing IS the second corroboration. Restores discovery of real co-owned brand domains that share NS but lack DKIM key reuse (e.g. `blackveil.nz` / `blackveil.io` alongside `blackveil.com`).
- **Slice 6 — multi-tenant NS filter** (`src/tenants/discovery/shared-ns-hosts.ts`): Parking services and registrar-default NS providers (Sedo, ParkingCrew, GoDaddy `domaincontrol.com`, Namecheap `registrar-servers.com`) are filtered inside `ns-correlator.ts` before the confidence math. Hyperscale managed DNS (Cloudflare, Route 53, GCP) remains ownership-bearing because those providers assign unique NS hostnames per account.
- **Streaming crt.sh SAN parser**: Large-issuer brands return MB-scale crt.sh JSON; the SAN correlator now parses incrementally via `@streamparser/json-whatwg` and stops once the signal plateaus (100 redundant certs without a new sibling). Raises `maxCerts` cap to 200, timeout to 15s, byte ceiling to 25 MB.
- **Markov lookalike generator** (`src/tools/markov-generator.ts`): New trigram model seeds the active NS / DKIM signals with up to 20 generated candidates. Single-signal `markov_gen` is intentionally below the corroboration gate — it's a seed, not a verdict.
- **Shared infrastructure-providers module** (`src/tenants/discovery/infrastructure-providers.ts`): Single source of truth for the allowlist consumed by both the orchestrator filter and the dmarc-rua miner. Two-allowlist divergence is now structurally impossible; consistency enforced by `test/audits/dmarc-rua-processor-consistency.audit.test.ts`.

### Fixed

- **Shadow Domain Subdomain False Positive**: Updated the shadow domain discovery logic to correctly identify organizational subdomains (e.g., `dmarc.amazon.com`) as internal assets rather than "Shadow IT". Implemented a new `isSubdomainOf` utility and integrated it into `mineDmarcRua`, `discoverBrandDomains`, and the standard DMARC authorization check.
- **Dead constant drift**: `DEFAULT_SIGNAL_CONFIDENCE.dmarc_rua` aligned from `0.8` → `0.6` to match the miner's actual emission for `related` classification (LR-5).
- **Dependency Hardening**: Remediated four moderate severity vulnerabilities in `esbuild` (GHSA-67mh-4wv8-2f99) via a path-scoped `overrides` entry on `@esbuild-kit/core-utils` (drizzle-kit's transitive holding the vulnerable version). `npm audit`: 0 vulnerabilities.

### Tests

- New pinning tests for the corroboration gate (`test/discover-brand-domains-corroboration.test.ts`) and confidence math (`test/discover-brand-domains-math.test.ts`, locking the `san+markov < 0.5` invariant).
- New audit-layer regression nets: `test/audits/infrastructure-providers.audit.test.ts` (19 MUST_MATCH rows + negative controls), `test/audits/shared-ns-hosts.audit.test.ts` (12 MUST_MATCH parking + 6 MUST_NOT_MATCH hyperscale), `test/audits/discovery-signal-defaults.audit.test.ts` (default vs miner-emission consistency).

### Verified

- **Platform Tiers & Plan Limits**: Empirically verified all six platform tiers (Free, Agent, Developer, Enterprise, Partner, Owner). Confirmed that daily tool quotas, tool-specific overrides, and concurrency limits are strictly enforced at the MCP execution layer.
- **OWASP Top 10 Audit**: Completed a full codebase security audit. Confirmed robust protections against SQL injection, XSS, SSRF, and authentication failures.

## [2.12.0] - 2026-05-12

### Added

- **Multi-Tenant Brand Discovery (Phase 4)**: `POST /internal/tenants/discover` endpoint added. Supports multi-signal discovery (SAN, NS, RUA, DKIM) and auto-import of high-confidence candidates (≥ 0.85) to the tenant's portfolio.
- **Fingerprint Pre-flight Optimization (Phase 6)**: `POST /internal/tenants/scan` now performs a lightweight DNS fingerprint check before full execution. If the fingerprint matches the last known state and the scan is < 24h old, the cached result is reused, significantly reducing Worker CPU and D1 load. Use `force_refresh: true` to bypass.
- **Multi-Tenant Hammer Suite**: Added `scripts/chaos/tenant-chaos-v3.py` and Vitest integration tests to verify orchestrator efficiency, D1 contention handling, and audit-logging at scale.

### Changed

- **Tightened Free Tier Quotas**: Significantly reduced daily limits for unauthenticated users to protect platform resources and encourage API key registration (e.g., `scan_domain` reduced from 75/day to 5/day; `batch_scan` from 20/day to 1/day).
- **Protocol Compliance**: Aligned rate-limited responses with standard HTTP patterns by returning **HTTP 429 (Too Many Requests)** instead of HTTP 200. This includes global caps, per-IP minute/hour limits, and tiered daily quotas.

### Fixed

- **Production Config Injection**: Fixed `scripts/inject-private-config.cjs` to ensure `kv_namespaces`, `d1_databases`, and `analytics_engine_datasets` are correctly merged from private deployment configs into `wrangler.production.jsonc`.
- **CI Dependency Conflicts**: Resolved a peer dependency conflict between `wrangler` and `@cloudflare/workers-types` by pinning the latter to `4.20260511.1`.
- **Restored Build Scripts**: Restored missing `build:wasm` and `validate:internal-deps` scripts to `package.json` to fix CI Contract workflow failures.
- **Analytics Hook Regressions**: Resolved a test-suite crash caused by the missing `BV_WEB` service binding and restored integration coverage for queue consumer analytics.

## [2.10.19] - 2026-05-12

### Fixed

- **OAuth Re-Authorization Retry Logic**: Added logic to seamlessly retry OAuth re-authorizations after `403` failures to prevent token drift.

## [2.10.17] - 2026-05-10

## [2.10.16] - 2026-05-09

### Changed

- **Untracked 7 internal artifacts** (forward-only — not history-rewritten). Files kept locally and gitignored going forward; older tags ≤ v2.10.15 still contain them. All 7 were cleaned of secrets in the v2.10.8 history rewrite — no leak risk in older tags.
  - `phase8-monitoring.json` — phase rollout monitoring artifact
  - `scripts/phase7-validation.mjs`, `scripts/phase8-monitor.mjs`, `scripts/phase7-results.json` — internal phase rollout scripts/data
  - `reports/repo-audit-2026-04-06.html` — one-off internal audit
  - `docs/oauth-stripe-integration.md` — bv-web Stripe pairing details (kept private; self-hosters can ask)
  - `docs/MARKETING-BROCHURE.md` — commercial framing (better placed elsewhere than the OSS repo)

### Fixed

- **`npm audit` clears 4 moderate vulns** added when v2.10.15 introduced `drizzle-kit` as a devDep. drizzle-kit transitively pulled `@esbuild-kit/core-utils` which pinned `esbuild ~0.18.20` (GHSA-67mh-4wv8-2f99 — dev-server CVE). Added `overrides.esbuild: ^0.25.0` to force a non-vulnerable version. drizzle-kit only uses esbuild for build-time codegen so the dev-server CVE didn't apply to our usage, but the audit gate flagged it. `npm audit` now reports 0 vulnerabilities.

### Operational

- `.gitignore` patterns added: `/phase*-monitoring.json`, `/scripts/phase*-*.{mjs,json}`, `/docs/MARKETING-BROCHURE.md`, `/docs/oauth-stripe-integration.md`, `reports/repo-audit-*.html` so these can't accidentally re-stage.

## [2.10.15] - 2026-05-09

### Added

- **Drizzle migrations for Tenant D1 schemas** — closes the TODO from PR #105. Two migrations:
  - `src/tenants/db/migrations/registry/0000_minor_skaar.sql` — shared registry tables (`super_tenants`, `sub_tenants`, `tenant_keys`, `billing_events`) + `idx_billing_lookup` composite index.
  - `src/tenants/db/migrations/tenant/0000_clear_clea.sql` — per-sub-tenant tables (`domains`, `scans`, `findings`, `alerts`) + indexes including the `idx_alerts_active` partial index (`WHERE resolved_at IS NULL`).
- **`drizzle-kit ^0.31.10` devDep** + two drizzle configs (`src/tenants/db/drizzle.{registry,tenant}.config.ts`) targeting `d1-http` driver.
- **`npm run tenant:migrate`** (and per-DB variants) regenerates the SQL from the schema files.

### Changed

- Removed `TODO(tenant-d1-schemas)` comments from `src/tenants/db/schema/{registry,tenant}.ts` — now point at the generated migration paths.

### Operational

- 0 changes to existing source. Migrations are new artifacts; no production deploy semantics change.

## [2.10.14] - 2026-05-09

### Fixed

- **Default `SCAN_TIMEOUT_MS` raised 12s → 15s.** Production analytics over the last 7 days showed `scan_domain` p50 latency at 12,473 ms — fractionally above the prior 12s default — so roughly half of cold scans were racing the wall-clock timeout and returning partial results before the orchestrator finished its 16 leaf checks. 15s gives ~20% headroom over p50 and is comfortably under the bundled Workers CPU ceiling of 30s. Operator override up to 30s remains via the `SCAN_TIMEOUT_MS` env var.

### Added

- **`test/audits/tenant-capacity-readiness.audit.test.ts`** — 7 invariants codifying the Tenant-class capacity envelope: quota (`partner.scan_domain >= 2.5M`), quota-alias parity, scan timeout >= observed p50, per-check < scan timeout, and throughput projections that 2.5M-domain audits complete inside the 24h SLO. Tripped CI on the prior 12s timeout — the catch that motivated this PR.

### Changed

- **`test/config.spec.ts`** — `parseScanTimeout` assertions now reference the `SCAN_TIMEOUT_MS` constant instead of hardcoded literals so future bumps are a single-source-of-truth update.

### Operational

- `.gitignore`: added `reports/tenant-calibration-*.json` and `/scripts/tenant/` patterns for capacity-calibration tooling kept local-only.

## [2.10.13] - 2026-05-09

Enterprise tenant enablement — Phase 0 + start of Phase 1. No public-API behavior change for existing tools; adds quota headroom and the foundation for a multi-tenant orchestrator. Built TDD-first across 4 parallel agents in worktree isolation.

### Changed

- **`partner.scan_domain` daily quota raised 100K → 2.5M** (PR #102). The target enterprise scale includes 2.5M-domain portfolios; the prior cap blocked one-shot audits. Same change to the `scan` alias. Audit test `test/audits/tenant-scale-quota.audit.test.ts` locks the floor against future regression.

### Added

- **`src/tenants/adapters/`** — tenant-prefix-stamping adapters for D1/R2/KV (PR #103). Wrap each Cloudflare binding with a thin proxy that auto-stamps the tenant prefix on every read/write — call sites never need `WHERE tenant_id = ?` filtering. Adopted from the `webitte-hosting/emdash` pattern. Cross-tenant access via these adapters is impossible by construction. 17 unit tests covering prefix validation, key prefixing, list scoping, traversal rejection.
- **`src/tenants/discovery/san-correlator.ts`** — Subject Alternative Name (SAN) cert correlator (PR #104). Tier-1 signal in the brand-domain-discovery pipeline: query crt.sh for a seed domain, extract every SAN from the matched certs, filter to sibling domains (not seed, not subdomain), validate. Adopted from `bit4woo/teemo`. 10 unit tests including rate-limit/timeout/error paths and 5MB body cap with content-length pre-flight.
- **`src/tenants/db/schema/{registry,tenant}.ts`** — Drizzle schemas for the multi-tenant orchestrator (PR #105). Two databases: shared registry (super_tenants, sub_tenants, tenant_keys, billing_events) and per-sub-tenant (domains, scans, findings, alerts). Indexes for billing-lookup, scan-by-domain-time, scan-by-cycle, finding-by-domain-severity, and a partial alerts-active index. 46 unit tests using `getTableConfig` for structural assertions. **Migration generation deferred** — `drizzle-kit` is not yet a dependency; explicit `TODO(tenant-d1-schemas)` left in both files for the follow-up.

### Total

- **+76 unit tests** (17 + 10 + 46 + 3)
- **+17 source files** under `src/tenants/`
- **0 changes to existing source files** apart from the quota constant

## [2.10.12] - 2026-05-09

### Fixed

- **Analytics gap: `scan_domain` now emits `cacheStatus` blob.** Surfaced while building out the analytics drilldowns: the cache-effectiveness query reported `scan_domain` at **0 hits / 0 misses / 325,680 total** because the orchestrator's `tool_call` event left `blob8 = 'n/a'`. `tools/scan-domain.ts` returns `{ ...cached, cached: true }` on a top-level `cache:<domain>` hit but `handlers/tools.ts` wasn't threading that flag to `logToolSuccess`. Now passes `cacheStatus: result.cached ? 'hit' : 'miss'` from the dispatch case. `force_refresh: true` correctly reports `'miss'`. PR #101.

### Test

- New `test/scan-domain-cache-status.test.ts` (3 cases, RED→GREEN): cold call → `'miss'`, second call → `'hit'`, `force_refresh` → `'miss'`.

## [2.10.11] - 2026-05-09

Maintenance release — folds in the post-v2.10.10 work that wasn't yet shipped to production. No public API or behavior changes for normal callers; one prod-side change (removed temporary telemetry hook).

### Changed

- **Removed temporary `logExplainFindingRejection` telemetry hook** (`src/handlers/tool-args.ts`). 30-day analytics review showed `explain_finding` at 0 errors / 17 calls — the 27% rate that motivated the spike (2026-04-25) has fully resolved. Closed as Category C ("expected noise"). Closes [#77](https://github.com/MadaBurns/bv-mcp/issues/77).
- **Tightened `.gitleaks.toml`**: added path allowlists for `^test/`, `^packages/[^/]+/test/`, and `.github/CODEOWNERS`; added regex allowlist for `support@smithery.ai` (public business contact) and the `oldmail@retail.com` brochure narrative example. `customer-name` rule literal restored after the 2026-05-08 history rewrite mutated it. `phone-number` rule allowlists `^chaos-test-.*\.py$` for the pre-`scripts/chaos/` root location. `gitleaks detect` against full history now reports **0 findings** (was 103).
- **`docs/MARKETING-BROCHURE.md`**: replaced fictional `oldmail@retail.com` example with `oldmail@example.com` (clearly fictional, allowlisted).

### Fixed

- **CI rate-limit flake**: `test/index.spec.ts:1238` and `:1484` flaked on slow CI workers because `resetAllRateLimits()` only cleared the per-isolate `Map` while `rl:*` keys in the `RATE_LIMIT` KV namespace persisted with their 60s TTL across tests. New `resetAllRateLimitsKv(kv: KVNamespace)` helper paginates `kv.list({ prefix: 'rl:' })` and deletes every match (fail-soft). Wired into the existing `beforeEach`. Closes [#96](https://github.com/MadaBurns/bv-mcp/issues/96).

### Operational — history rewrite (no source-code impact)

On 2026-05-08 we ran `git filter-repo` twice across all 1,933+ commits and 82 tags:

1. **PII / dead-key scrub**: replaced prior customer-name and internal-hostname literals with generic placeholders, and 3 dead BV API keys (already revoked in prod) with `*_REDACTED_*`. Removed `.playwright-mcp/` browser-test snapshots and 2 internal docs (`docs/enterprise-architecture.md`, `docs/smithery-docs-nav.md`).
2. **OSS hygiene**: removed 6 internal-only docs from all history (`docs/architecture.md`, `docs/AS-BUILT.md`, `docs/phase8-golive.md`, `OAUTH_LOCAL_DEBUG.md`, `MCP.md`, `GEMINI.md`). Replaced one stale ref in `.github/instructions/scan-orchestration.instructions.md`. Added drift catchers to `.gitignore` (`/BENCHMARK_*.md`, `/CAPACITY_*.md`, `/Tenant-*.md`, `/*-Call-Prep.md`, `/AS-BUILT.md`, `/phase*-golive.md`, `/MCP.md`, `/GEMINI.md`).

Both rewrites force-pushed `main` and 82 tags. Anyone with a local clone needs:

```
git fetch origin --prune --prune-tags --tags --force && git reset --hard origin/main
```

GitHub-managed `refs/pull/*` retain pre-rewrite blobs (only visible via `git clone --mirror`); not reachable via normal `git clone`. See [#37](https://github.com/MadaBurns/bv-mcp/issues/37) for the announcement comment.

### Test infra

- **`.dev/analytics-30d.mjs`**: now auto-loads `CF_ANALYTICS_KEY` from `.dev.vars` (fallback chain: `CF_ANALYTICS_TOKEN` env → `CF_ANALYTICS_KEY` env → `.dev.vars` line). Added 3 query sections (session lifecycle by client type, error rate by client × tool, cache hit% by tool) and a `TOOL=` filter for per-tool drilldown. Internal-only (gitignored) — no public-surface change.

## [2.10.10] - 2026-05-08

### Security / Hardening — full-codebase audit, 10 findings closed (0 critical, 3 high, 4 medium, 3 low)

**HIGH**

- **SSRF: BIMI logo URL fetched without host validation (H2).** The `l=` and `a=` tag values come from a TXT record at `default._bimi.<domain>` and are entirely attacker-controlled. Pre-fix only `startsWith('https://')` + `endsWith('.svg')` were checked, leaving Cloudflare-internal hostnames and userinfo-spoofed URLs (`https://attacker@internal/...`) reachable despite the runtime `global_fetch_strictly_public` flag. Added `validateOutboundUrl()` in `src/lib/sanitize.ts` and `safeFetch` wrapper in `src/lib/safe-fetch.ts`; `src/tools/check-bimi.ts` now passes `safeFetch` instead of raw `fetch`. The package's `validateBimiSvg()` calls the wrapper transparently — blocked URLs surface as the existing "BIMI logo fetch failed" finding rather than an unhandled exception.
- **SSRF: HTTP redirect follower didn't validate redirect targets (H3).** Both `src/tools/check-http-security.ts` `fetchWithRedirects()` and the package-level `followRedirects()` only checked the redirect's scheme. An attacker controlling a domain's HTTPS response could redirect to any HTTPS URL, including CF-internal hostnames. Initial fetch (to `https://<validated-domain>`) keeps raw `fetch`; every redirect target now goes through `safeFetch`. Same fix in the package — embedders that pass raw `fetch` are documented as responsible for their own SSRF protection.
- **Internal `/tools/*` and `/analytics/*` lacked defense-in-depth bearer auth (H1).** Pre-fix the only gate was `isPublicInternetRequest()` (cf-connecting-ip absence). A misconfigured upstream that forwarded the header would expose the entire surface — `/tools/batch` accepts up to 8,000 DoH lookups per call without rate limiting, and `/analytics/*` leaked per-key telemetry. Added `internalLenientAuthGate` as an _opt-in_ check: enabled only when `REQUIRE_INTERNAL_AUTH=true` AND `BV_WEB_INTERNAL_KEY` is set. Default off so deploying 2.10.10 doesn't break the existing bv-web service binding (verified against bv-web's `bv-mcp-client.ts`, which doesn't currently send `Authorization` on `/internal/tools/call`). Rollout: ship 2.10.10 → update bv-web's service client to attach `Bearer ${BV_WEB_INTERNAL_KEY}` → deploy bv-web → flip `REQUIRE_INTERNAL_AUTH=true` on bv-mcp.

**MEDIUM**

- **Owner-tier OAuth JWTs bypassed `OWNER_ALLOW_IPS` for the full 90-day TTL (M1).** The IP gate was only enforced once at `/oauth/authorize` consent. Anyone briefly on an allowlisted IP (compromised dev box, shared VPN, ephemeral cloud instance) could mint a token usable from any subsequent IP for 90 days, with no revocation route reachable from the public surface. The JWT branch in `src/lib/tier-auth.ts` now re-checks `OWNER_ALLOW_IPS` for `claims.tier === 'owner'`, downgrading to `partner` on mismatch — mirrors the existing `BV_API_KEY` path. Empty/unset allowlist preserves backward compatibility for self-hosted dev installs.
- **`get_provider_insights.provider` had no max length (M2).** `z.string().min(1)` only — capped only by the 10 KB body limit, inconsistent with the `.max(200)` on every other string field including the sibling `generate_dkim_config.provider`. Added `.max(200)`.
- **`/internal/tools/call` had no body-size limit (M3).** `c.req.json()` was called with no pre-parse guard; `/internal/tools/batch` (correctly) caps at 256 KB. A service-binding caller could force the Worker to materialize an arbitrarily large payload before Zod rejected it. Now reads via `c.req.text()` and rejects with HTTP 413 above `MAX_REQUEST_BODY_BYTES` (10 KB, mirrors public `/mcp`).
- **Fuzzing alert fan-out: no per-tick dedup or cap (M4).** `handleFuzzingScan` ran every 15 min and re-alerted every flagged principal each tick. A sustained fuzzer (or rotating-IP attacker) drove repeat alerts that would hit Slack incoming-webhook rate limits. Added `fuzz:alerted:<principalId>` KV marker (1 h TTL) and `MAX_ALERTS_PER_TICK = 10` ceiling — converts the failure mode from O(N principals × 4 ticks/h) to O(min(N, 10) × 1 alert/h).

**LOW**

- **JWT tier claim accepted full 6-tier enum (L1).** `TierSchema.safeParse(claims.tier)` accepted `free | agent | developer | enterprise | partner | owner`, but minting paths only produce `owner | developer | enterprise`. Tightened to `JwtIssuableTierSchema = z.enum(['owner', 'developer', 'enterprise'])` so a future regression in `putCode` that quietly stores `tier: 'partner'` becomes a schema failure rather than a silent privilege grant.
- **OAuth authorize echoed ZodError messages on 400 (L2).** `src/oauth/authorize.ts` returned `Invalid authorization request: ${err.message}` from both GET and POST handlers, leaking schema field names and constraint descriptions to unauthenticated callers before `redirect_uri` was validated. `register.ts` and `token.ts` both use a static string already (per their own JSDoc); `authorize.ts` was the missed sibling. Now returns `'Invalid authorization request'` verbatim.
- **`cf-connecting-ip` not redacted in unhandled-exception logs (L3).** `SENSITIVE_KEY_PATTERN` used `^ip$` (anchored) — only matched the bare key `"ip"`, not `"cf-connecting-ip"`. The global error handler at `src/index.ts:235` would log client IPs in cleartext on unhandled Worker exceptions. Pattern updated to `(^ip$|cf-connecting-ip|...)`.

### Added

- `src/lib/sanitize.ts` — `validateOutboundUrl(url)` boundary check (https-only, no userinfo, hostname → `validateDomain`).
- `src/lib/safe-fetch.ts` — fetch wrapper that runs validateOutboundUrl on the destination before delegating to `fetch`. Throws `TypeError` on a blocked target so callers' existing network-error handlers absorb it cleanly.
- `src/internal.ts` — `internalLenientAuthGate` middleware applied to `/tools/*` and `/analytics/*`.
- Tests (TDD red → green for every finding):
  - `test/validate-outbound-url.test.ts`, `test/safe-fetch.test.ts` (H2/H3 helpers)
  - `test/internal-tools-analytics-auth.test.ts` (H1 gate behavior)
  - `test/tier-auth-owner-jwt-ip.test.ts` (M1 IP-rebind regression)
  - `test/tier-auth-jwt-enum.test.ts` (L1 tightened enum, full owner/developer/enterprise allow + free/agent/partner/nonsense reject)
  - `test/internal-tools-call-body-limit.test.ts` (M3 413 + small-body regression guard)
  - `test/fuzzing-alert-dedup.test.ts` (M4 cooldown + cap)
  - `test/log-cf-ip-redaction.test.ts` (L3 redaction)
  - `test/oauth/authorize-zod-leak.test.ts` (L2 generic message)
  - `test/schemas/tool-args.spec.ts` — provider max-length cases (M2)

### Changed

- `src/lib/tier-auth.ts` JWT branch: tier validated against narrower `JwtIssuableTierSchema`; owner-tier IP re-check now applied. Removed unused `TierSchema` import.
- `src/oauth/authorize.ts` — both GET and POST 400 paths return static `'Invalid authorization request'`.
- `src/lib/log.ts` — `SENSITIVE_KEY_PATTERN` extended to redact `cf-connecting-ip`.
- `src/scheduled.ts` — `handleFuzzingScan` adds per-principal cooldown marker + per-tick cap.
- `src/internal.ts` — `/tools/call` reads body via `c.req.text()` and enforces `MAX_REQUEST_BODY_BYTES`; lenient auth gate registered before route handlers (Hono middleware-order requirement).
- `src/schemas/tool-args.ts` — `GetProviderInsightsArgs.provider` adds `.max(200)`.
- `src/tools/check-bimi.ts`, `src/tools/check-http-security.ts` — pass `safeFetch` to package-level checks.
- `packages/dns-checks/src/checks/check-http-security.ts` — `followRedirects` JSDoc documents the SSRF contract for embedders.

### Operational

- All 207 test files pass (2,662 tests). Typecheck + ESLint clean.

## [2.10.9] - 2026-05-08

### Security / Hardening

- **OAuth misconfig fails fast at first RTT, not after consent.** v2.10.8 was deployed to production without `OAUTH_SIGNING_SECRET`. Discovery, register, authorize, and the consent dance all succeeded; only `/oauth/token` failed (500 server*error) — claude.ai surfaced it as the opaque "Couldn't connect" \_after* the user had committed to the consent flow. Root-caused by chaos-walking the live flow.
- **`oauthAvailability` three-state gate** added at `src/index.ts`. Every OAuth route (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/oauth/register`, `/oauth/{authorize,token}`) now dispatches through `oauthGuarded`, which returns `503 service_unavailable` (with JSON body per RFC 6749 §5.2) when `ENABLE_OAUTH=true` but `OAUTH_SIGNING_SECRET` is missing or under 32 bytes. `404 Not Found` is reserved for `ENABLE_OAUTH != 'true'` ("feature off"), preserving the semantic distinction OAuth clients can render different UI for.
- **`OAUTH_SIGNING_SECRET` constant promoted to `src/lib/config.ts`** (`OAUTH_SIGNING_SECRET_MIN_BYTES = 32`) plus an `isValidOAuthSigningSecret(s)` helper, so the route layer and the inner token signer share the same gate. The token-handler 500 path remains as defense in depth — exercised by direct unit tests, no longer reachable from outside the route.

### Added

- **Chaos test `test/chaos/oauth-misconfiguration.chaos.test.ts`** — walks every OAuth route under three env states (`OAUTH_SIGNING_SECRET` undefined, < 32 bytes, `ENABLE_OAUTH=false`) and asserts the wire shape (503 vs 404, error code, no leaked token shape).
- **Audit test `test/audits/oauth-readiness-gate.audit.test.ts`** — locks the contract via static analysis of `src/index.ts`: forbids bare `isOAuthEnabled` / `env.ENABLE_OAUTH ===` checks at the route layer, requires every OAuth route to dispatch through `oauthGuarded`, requires the `OAuthAvailability` type union to remain exactly `"ready" | "disabled" | "misconfigured"`. Catches future regressions at lint time.

### Changed

- **`test/oauth/token.spec.ts`**: the two tests that asserted 500 on missing/short signing secret now assert 503 (the route gate intercepts first). Inner-handler 500 path is preserved as defense in depth.

### Operational

- **Production rotation**: `OAUTH_SIGNING_SECRET` (64-byte hex) generated and pushed via `wrangler secret put` on 2026-05-08; `BV_API_KEY` rotated again the same session as routine hygiene. Both validated against live production.

## [2.10.8] - 2026-05-07

### Security

- **Rotated `BV_API_KEY` and redacted four leaked owner-tier tokens from git history.** Two committed scripts (`scripts/phase7-validation.mjs:21`, `scripts/phase8-monitor.mjs:19`) carried real owner keys as `process.env.BV_API_KEY || '...'` fallback defaults. Three additional hex tokens surfaced in past commits to `.mcp.json`, `scripts/tranco-{scan,deep-scan}.mjs`, and `scripts/chaos/chaos-test-wasm.py`. All four are invalidated in production (old keys → 401, new key → 200). `git filter-repo --replace-text` rewrote main, all branches, and all 79 tags; `allow_force_pushes` was lifted for the rewrite then restored. Both committed scripts now hard-fail on missing env var rather than fall back to a literal.
- **`gitleaks` signal-to-noise**: per-rule `.gitleaks.toml` allowlists (PII rules scoped to docs/test/scan-artifact paths; env-var-default patterns whitelisted) drop the repo-wide leak count from 10,161 → ~108 without loosening any actual secret-detection rules.

### Added

- **Audit `test/audits/no-tracked-secrets.audit.test.ts`**: scans every tracked file (via Vite `import.meta.glob('?raw')`) for BV-key, AWS-key, and PEM-header patterns, with explicit exclusions for legitimate test fixtures. TDD: `git stash` round-trip confirmed RED → GREEN.
- **Audit `test/audits/tool-quota-coverage.audit.test.ts`**: requires every tool in `TOOL_DEFS` to be either in `FREE_TOOL_DAILY_LIMITS` or in a new `INTENTIONALLY_UNLIMITED_TOOLS` set — never both, never neither. Forces the limit-vs-unlimited decision into PR diff.
- **Contract `test/contracts/oauth-tier.contract.test.ts`**: locks `CustomerOAuthTierSchema` to `developer | enterprise` only; rejects `agent` per the documented "Paid OAuth Tiers" contract.

### Changed

- **`check_dane_https` and `check_svcb_https` now have explicit per-IP daily limits (200/day each)**, mirroring `check_dane`. Previously they were governed only by baseline per-IP rate limiting. Surfaced by the new tool-quota-coverage audit; remaining 49 tools were already covered.
- **`CustomerOAuthTierSchema` narrowed from `['agent','developer','enterprise']` to `['developer','enterprise']`.** The `agent` tier is reachable via static API key only, never via OAuth — `bv-web`'s `PLAN_TO_MCP_TIER` mapping never returns `agent`. The schema now matches the documented contract. No runtime impact for any existing OAuth caller.
- **`FUZZ_THRESHOLDS` audit upgraded from shape-only to exact-value `toEqual`**. Future drift in either direction now requires updating both `src/lib/config.ts` and `test/audits/fuzzing-config.audit.test.ts` in the same PR diff, surfacing the change in code review.
- **`@cloudflare/vitest-pool-workers` bumped `^0.13.3 → ^0.15.2`** so the bundled `workerd` (`1.20260430.1`) supports the pinned `compatibility_date: 2026-04-22`. Eliminates the "requested 2026-04-22 falls back to 2026-03-17" warning that appeared on every test run.

### Operational

- **Manual-deploy mode**: `auto-deploy-main.yml` renamed to `auto-deploy-main.yml.disabled` while `CLOUDFLARE_API_TOKEN` is intentionally absent from the GitHub `production` environment. The v2.10.6 fail-fast guards correctly turned every main push red — disabling the workflow stops the noise. Re-enable: upload the token, then `git mv` back. Active ship path is `npm run deploy:private` from local.
- **Branch protection tightened**: added `File hygiene check` to required status checks (now 4: `build-and-test`, `Secret & PII scan`, `Dependency audit`, `File hygiene check`). `allow_force_pushes` and `allow_deletions` both `false`.

## [2.10.7] - 2026-05-07

### Fixed

- **CI release pipeline silently skipped npm + Cloudflare for v2.10.2 through v2.10.6** — `.github/workflows/publish.yml` used a warn-and-skip pattern (`echo skip=true >> $GITHUB_ENV`) when `NPM_TOKEN` or `CLOUDFLARE_API_TOKEN` was missing, gating downstream steps with `if: env.skip != 'true'`. The job exited `success` while publishing nothing. The MCP Registry and GitHub Release jobs ran fine (different secrets), so the workflow looked green for five consecutive releases. Production was running pre-v2.10.2 code until a manual deploy on 2026-05-07. Mirrored the `auto-deploy-main.yml` fail-fast pattern across all three publish.yml gates so missing secrets become a red CI signal.

### Added

- **Audit test for the silent-skip anti-pattern** — `test/audits/workflow-secret-check.audit.test.ts` scans every `.github/workflows/*.yml` (via Vite `?raw` imports) and asserts (a) no workflow writes `skip=true` to `$GITHUB_ENV`, and (b) every `if [ -z "$*_TOKEN" ]` guard ends with `exit 1`. Catches the regression at lint time before another five releases vanish.

## [2.10.6] - 2026-05-07

### Added

- **Fuzzing detection** — the worker now records error events from suspicious traffic patterns (unknown tool enumeration, JSON-RPC method enumeration, Zod argument fuzzing, auth probing) into a KV-backed sliding-window counter, and the existing 15-min cron emits a `fuzzing_suspected` alert via `ALERT_WEBHOOK_URL` when any principal trips the threshold. Detection is fail-soft — KV unavailable, webhook 500, or any other infrastructure failure must not break the request path. Principals are identified by `keyHash` for authenticated traffic and `ipHash` (FNV-1a of cf-connecting-ip) for anonymous; raw IPs never appear in alert payloads. New module surface: `src/lib/fuzzing-detector.ts`, `src/lib/fuzzing-counter.ts`, `src/schemas/alerting.ts`, `handleFuzzingScan` in `src/scheduled.ts`. Threshold config: `FUZZ_THRESHOLDS` in `src/lib/config.ts` (single source of truth, audited). v1 thresholds are conservative (×3 the plan defaults) to stay silent for one week of baseline collection before lowering.
- **`RATE_LIMIT` KV in test bindings** — required for the new integration tests.

### Testing

- 28 new tests across all 6 layers of the testing pyramid (unit / integration / contract / audit / subcutaneous E2E / chaos), each written first and watched fail per TDD. Full suite: 2587 pass.

## [2.10.5] - 2026-05-07

### Security

- **hono 4.12.14 → 4.12.18** — pulls in fixes for [GHSA-9vqf-7f2p-gf9v](https://github.com/advisories/GHSA-9vqf-7f2p-gf9v) (`bodyLimit()` chunked-encoding bypass) and [GHSA-69xw-7hcm-h432](https://github.com/advisories/GHSA-69xw-7hcm-h432) (`hono/jsx` HTML injection). Neither was exploitable in our codebase — we don't use Hono's `bodyLimit()` middleware (our custom `readRequestBody` in `src/mcp/request.ts` already streams chunks and checks bytes incrementally per the advisory's recommendation), and we don't import `hono/jsx` anywhere. Update is for clean `npm audit` output and defense-in-depth on transitive code paths.

## [2.10.4] - 2026-05-07

### Added

- **`ipHash` analytics dimension** — Cloudflare Analytics Engine `mcp_request` events now record an `i_`-prefixed FNV-1a hash of `cf-connecting-ip` as `blob11`, and `tool_call` events record it as `blob10`. This enables per-IP traffic investigation via the existing analytics pipeline; without this dimension, `src/lib/analytics.ts` only stored country/clientType/sessionHash/keyHash and there was no way to attribute traffic to a specific IP. The hash is lossy by design — equal IPs hash equally and a defender investigating a known suspect can hash client-side and filter, while a leak of the analytics dataset doesn't directly expose addresses. Filter via `WHERE blob11 = '<ipHash>'` (mcp_request) or `blob10 = '<ipHash>'` (tool_call).
- **Per-IP analytics CLI** — `IP=<addr> CF_ANALYTICS_TOKEN=... node .dev/analytics-30d.mjs [days]` now emits per-IP daily volume + tool breakdown sections. The script computes the FNV-1a `i_<hex>` hash locally so no IP ever leaves the operator's machine.

## [2.10.3] - 2026-05-07

### Security

- **`/internal/*` Host-header bypass closed** — removed the `Host: localhost:*` branch in the internal-route guard so an attacker who can spoof the Host header on a public-internet request can no longer skip the `cf-connecting-ip` gate. Cloudflare always sets `cf-connecting-ip` on public requests, making it the authoritative signal; the guard is now driven by a pure `isPublicInternetRequest()` helper. Defense-in-depth — likely not exploitable in production today.
- **`/internal/trial-keys/*` now requires `BV_WEB_INTERNAL_KEY`** — these routes mint API credentials and previously relied solely on the network-level guard. Added a `trialKeysAuthGate` middleware mirroring the `/oauth/grants` pattern: 503 if `BV_WEB_INTERNAL_KEY` is unset (mis-deploy), 401 on missing/wrong bearer.
- **PKCE verification is now constant-time** — `verifyPkce` decodes the challenge to bytes and compares against `SHA-256(verifier)` via the shared `constantTimeEqual` helper instead of string `===`. Not realistically exploitable due to SHA-256 preimage resistance and the 60s single-use code TTL, but eliminates the timing side-channel inconsistency with the rest of the auth code.
- **JWT `alg=HS256` pinned in verify** — `verifyJwt` now parses the header and rejects anything other than `HS256` before HMAC checking (RFC 8725 §3.1). Defense-in-depth against algorithm-confusion / downgrade attacks.

### Testing

- 16 new tests added across `test/internal-guard.spec.ts`, `test/internal-trial-keys-auth.spec.ts`, `test/oauth/pkce.spec.ts`, and `test/oauth/jwt.spec.ts` — written first and watched fail per TDD. Full suite: 2553 pass.

## [2.10.2] - 2026-05-06

### Fixed

- **OAuth consent endpoint critical bug** — endpoint required authentication before rendering consent page, causing 100% registration failure (302 redirects to `/sign-in` instead of showing consent form). Fixed by switching from `requireUserWithTenants` (throwing) to optional `getAuthenticatedUser` (non-throwing), allowing public access with two-state UI rendering. Verified live: HTTP 200, all 9 MCP clients passing, chaos test 58/58 (100%). Expected registration success improvement: 0% → ~90%+.
- **Profile accumulator upsert efficiency** — parallelized per-category weight updates in `handleIngest` to reduce lock contention and improve throughput (commit 944641f).

### Added

- **Phase 7-8 testing infrastructure** — comprehensive validation test suite including pressure tests (10+ domains), chaos tests (rapid requests, malformed inputs, invalid tools), false positive audit (confirms no regressions), and edge case validation (11 scenarios). All tests passing: 7/7 baseline health checks, 58/58 chaos tests.
- **Phase 8 monitoring** — `scripts/phase8-monitor.mjs` provides 7-point health check (OAuth Discovery 2/2, OAuth Endpoints 3/3, MCP Core 1/1, Integration 1/1). `phase8-monitoring.json` captures baseline for production surveillance.
- **Pressure/chaos test suite** — `scripts/pressure-chaos-test.mjs` with 50+ domains across categories (healthy, minimal DNS, subdomains, complex email, edge cases, rate limiting, timeouts) for production resilience validation.

### Changed

- **OAuth enablement** — Phase 4 hidden probe and Phase 7-8 full enablement completed. OAuth 2.1 endpoints now fully operational with tier-based access control (Free, Developer, Enterprise). Stripe subscription integration active.
- **Documentation** — Added comprehensive as-built reference (`docs/AS-BUILT.md`, 22.6 KB) and marketing brochure (`docs/MARKETING-BROCHURE.md`, 17.0 KB). Updated OAuth-Stripe tier mapping and agent tier documentation. Phase 8 go-live package complete.
- **Dependencies** — wrangler 4.85 → 4.87 (latest features and security patches).

### Security

- **OAuth 2.0 compliance** — RFC 6749, 7636 (PKCE), 8414 (Authorization Server Metadata) fully compliant. All 18 security checks passed, 0 critical/high/medium vulnerabilities identified.
- **Rate limiting** — per-tier enforcement verified operational (Free 300/day, Developer 10k/day, Enterprise 50k+/day).
- **External dependency validation** — `sanitizeReturnTo()` verification confirms protection against open redirect attacks.

### Docs

- **AS-BUILT.md** — comprehensive technical reference including architecture diagrams, OAuth 2.1 details, JWT token format, session management (2-hr TTL, auto-refresh), Stripe integration flow, production deployment status, testing results, security controls, rollback plan (<5 min), monitoring procedures, API reference, file structure, build instructions.
- **MARKETING-BROCHURE.md** — customer-facing positioning document with problem statement (78% lack DMARC, $5.3B annual losses), 51 security checks, real-world attack paths, customer outcomes, ROI, pricing tiers, getting started guide, deployment options, industry recognition, case studies, 15+ FAQ entries, success metrics.
- **oauth-stripe-integration.md** — integration guide with 10-step OAuth flow, tier comparison tables, error handling, configuration reference, monitoring guide, FAQ (10 questions).
- **phase8-golive.md** — go-live checklist, customer communication templates, support runbooks (5 common issues), emergency rollback plan, monitoring metrics targets.

### Testing

- **Chaos testing** — all 9 MCP client types validated (claude_code, cursor, vscode, claude_desktop, windsurf, mcp_remote, blackveil_dns_action, bv_claude_dns_proxy, unknown). p50 485ms, p95 2245ms, 0 5xx errors, 100% success rate.
- **Security audit** — 18/18 checks passed covering authentication, authorization, input validation, CSRF/XSS, sensitive data, OAuth 2.0 compliance, error handling, logging, external dependencies.
- **Production verification** — OAuth endpoint: HTTP 200 (fixed), Discovery: RFC 8414 compliant, all bindings verified (8/8).

## [2.10.1] - 2026-04-25

### Fixed

- **CI: Security workflow** — replaced `gitleaks/gitleaks-action@v2` with a self-installed pinned binary (`gitleaks 8.30.1`). The repo's Actions allowlist (`patterns_allowed: ["MadaBurns/*"]`) had been silently rejecting the third-party action since 2026-04-22, causing every Security run to `startup_failure` with 0 jobs created. Replicates the action's incremental scan behavior — PRs scan `base..head`, pushes scan `before..sha` (fallback `HEAD~1..HEAD` for fresh branches).

### Security

- **postcss 8.5.8 → 8.5.10** (transitive dev dep via `tsup`/`vitest`/`vite`) — resolves [GHSA-qx2v-qp2m-jg93](https://github.com/advisories/GHSA-qx2v-qp2m-jg93) (XSS via unescaped `</style>` in CSS Stringify Output). Dev-only impact; no production runtime exposure.

## [2.10.0] - 2026-04-25

### Security

- **OAuth 2.1 enabled in production** — `OAUTH_SIGNING_SECRET` (HS256, 32-byte random hex) uploaded via `wrangler secret put`, and `OAUTH_ISSUER=https://dns-mcp.blackveilsecurity.com` pinned as a hardening var against Host-header spoofing of discovery metadata. Discovery endpoints at `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` are live and return the pinned issuer. Rotation runbook: `scripts/oauth/README.md`.

### Changed — Reliability (2026-04-25, analytics-informed)

- **`check_spf`** — top-level DNS failures (timeout, DoH HTTP error, invalid response) now return a structured `CheckResult` with a `missingControl: true` finding (`errorKind: 'timeout' | 'dns_error'`) instead of throwing. Previously these propagated to the MCP caller as generic errors (~17.9% of direct `check_spf` calls over 30 days).
- **`batch_scan`** — replaced the sequential `for` loop with a bounded worker pool (default `concurrency: 3`) and a total wall-clock budget (default `budgetMs: 25_000`, leaving 5s Worker headroom). Domains that don't finish within budget return `error: 'batch_budget_exceeded'`. New `BatchScanOptions`: `budgetMs`, `concurrency`, `scanFn` (test injection). Production `p95`/`p99` was previously pinned at 28s; the new cap bounds single-domain stalls without starving other items in the batch.
- **`check_http_security`** — wrapped in a `TOTAL_BUDGET_MS = 10_000` cap covering dual-fetch + WAF body + package-level fetch. On budget exhaustion the tool returns `checkStatus: 'timeout'`, `score: 0`, and a high-severity `missingControl` finding. Caps a rare bimodal outlier observed in production (one domain drove `p99`/`max` to 28s while `p50` stayed at 3ms).
- **Client detection** — added `bv_load_test` client type (matches `bv-{load,chaos,tranco}-{test,scan}` user-agents). `scripts/tranco-scan.mjs` and `scripts/tranco-deep-scan.mjs` now send `User-Agent: bv-tranco-scan/1.0` so internal load-test traffic is segmented away from real-client `unknown` in analytics.

### Added

- **`scripts/oauth/prod-probe.py`** — Two-mode production OAuth probe. `--mode=smoke` POSTs a full junk payload to `/oauth/token` and asserts `400 invalid_grant` (verifies routing past the Zod/rate-limit gates). `--mode=e2e` runs the full `register → authorize → token → /mcp` flow against a live owner `BV_API_KEY` and asserts ≥40 tools in `tools/list`.
- **`scripts/oauth/README.md`** — Rotation and rollback runbook for the OAuth signing secret.
- **`explain_finding` telemetry spike (time-boxed, 2026-04-25)** — `src/handlers/tool-args.ts::logExplainFindingRejection` emits a sanitized `result: 'explain_finding_rejected'` log event when Zod rejects the tool's arguments, recording the rejected field, a 64-char-truncated value, and the Zod issue code. Diagnosing a 27% error rate (10/37 calls). Scheduled for removal or conversion into a schema fix once 7 days of data is reviewed (see `docs/plans/2026-04-25-analytics-findings-tdd-plan.md` Workstream D).
- **`.dev/analytics-30d.mjs`** — local script for ad-hoc Cloudflare Analytics Engine queries (daily volume, tool popularity, error rates, latency percentiles, client types, geo, tier breakdown, rate-limit hits, and a `check_http_security` per-domain outlier probe). Requires a CF API token with `Account Analytics:Read`:
  ```bash
  CF_ANALYTICS_TOKEN=$(grep '^oauth_token' ~/.wrangler/config/default.toml | sed 's/.*= *"\(.*\)"/\1/') \
    node .dev/analytics-30d.mjs 7
  ```

### Docs

- **README + client-setup + architecture + CLAUDE.md**: tool count updated 41/44 → 51 (current `tools/list` output). `docs/client-setup.md` now documents OAuth 2.1 as a third auth path alongside Bearer / `?api_key=`, including discovery endpoints, the register → authorize → token flow, PKCE constraints, and a link to the probe + rotation runbook. CLAUDE.md `Bindings` table now includes `OAUTH_SIGNING_SECRET` and `OAUTH_ISSUER`.
- **README + CLAUDE.md + troubleshooting**: `bv_load_test` client type documented. New batch/SPF/HTTP-security resilience behaviors documented in CLAUDE.md "Conventions" and `docs/troubleshooting.md` "Common Errors".

## [2.9.2] - 2026-04-21

### Added

- **MCP Registry listing** — published as `com.blackveilsecurity/dns` v2.9.2 on the [MCP Registry](https://registry.modelcontextprotocol.io). `server.json` added for registry publishing; `mcpName` field added to `package.json`.
- **Tool count assertion test** — CI now validates the tool count matches the declared total, preventing stale counts in docs.
- **CI auto-publish to MCP Registry** — `publish.yml` now pushes `server.json` to the registry on version tags alongside the existing npm + Cloudflare deploy steps.
- **Privacy policy link** — added to README footer linking to `https://www.blackveilsecurity.com/privacy`.

### Fixed

- **npm publish resumed** — the publish gap from 2.6.4 → 2.9.2 was caused by a GitHub Actions billing pause. Versions 2.6.5–2.9.1 were deployed to Cloudflare Workers but not published to npm. All changes are now included in this release.
- **README tool count** — corrected ASCII art diagram from "44 MCP tools" to "51 MCP tools" to match the actual `tools/list` output.

## [2.9.1] - 2026-04-19

### Changed

- **Dev dependencies**: bumped `wrangler` to `^4.83.0`.
- **Repo tooling**: added `.intent/` workspace config and new harness scripts (`scripts/context-usage-test.py`, `scripts/conversation-sim.py`, `scripts/output-usage-test.py`) plus tranco scan-result snapshots under `scripts/`. Dev-only; no runtime or published-package impact.
- **`.gitignore`**: removed duplicate `.mcp.json` entry.

## [2.9.0] - 2026-04-19

### Added

- **OAuth 2.1 authorization server for Claude mobile custom connector** — six new routes wired into the Hono app:
  - `POST /oauth/register` — RFC 7591 Dynamic Client Registration with redirect-URI allowlist, one-time `client_secret_basic` (hashed at rest), registration rate-limit (10/min per IP, fixed window).
  - `GET /oauth/authorize` — consent page with restrictive CSP (`default-src 'self'; script-src 'none'; form-action 'self'`), `X-Frame-Options: DENY`, plain-text 400 for pre-redirect_uri-verification errors (no HTML, no open-redirect vector).
  - `POST /oauth/authorize` — consent form handler with per-IP fixed-window rate-limit (5/min — pinned `expiresAt` prevents indefinite lockout), re-validates original query via `_q` hidden field, constant-time `BV_API_KEY` check, enforces `OWNER_ALLOW_IPS` at consent (see Changed).
  - `POST /oauth/token` — `authorization_code` grant with PKCE S256 verification, one-time code consumption (atomic `consumeCode`), HS256 JWT issuance (90-day TTL), enforces ≥32-byte `OAUTH_SIGNING_SECRET` floor per RFC 7518 §3.2, per-IP rate-limit (30/min).
  - `GET /.well-known/oauth-authorization-server` — RFC 8414 metadata.
  - `GET /.well-known/oauth-protected-resource` — RFC 9728 metadata pointing at the resource at `<issuer>/mcp`.
- **HS256 JWT utility** (`src/oauth/jwt.ts`): `signJwt` / `verifyJwt` / `newJti` built on Web Crypto HMAC-SHA256. Signature verified BEFORE payload parse (defense against parser bugs). `clockSkewSeconds: 30` from `config.ts` tolerates reasonable clock drift between worker and client.
- **KV-backed OAuth storage** (`src/oauth/storage.ts`): clients, codes, and revocation denylist under `oauth:` prefix. `consumeCode` is atomic (get-then-delete), preventing code replay under concurrent token requests. Revoked JTIs stored with bounded TTL matching JWT lifetime.
- **OAuth JWT in Bearer auth path** (`src/lib/tier-auth.ts`): three-segment tokens route through `verifyJwt` → `isRevoked` → owner-claim check at the top of `resolveTier`. On any verify failure (bad signature, wrong issuer/audience, expired, revoked), falls through silently to existing static-key / service-binding cascade — no double-401, no information leak.
- **Shared `parseOwnerAllowIps` helper** (`src/lib/config.ts`): trims, filters empty entries, treats whitespace-only input as "no gate." Used by both consent gate and static-key path for consistent semantics.
- **OAuth Zod schemas** (`src/schemas/oauth.ts`): per-endpoint request validation with static error descriptions (no Zod `error.message` leakage to clients).

### Changed

- **`OWNER_ALLOW_IPS` gate moved to consent step** (`src/oauth/authorize.ts`): previously enforced only at `/mcp` in `tier-auth.ts:167-173`. Since the OAuth JWT carries `tier: 'owner'` for 90 days, the gate now runs at `POST /oauth/authorize` before `BV_API_KEY` verification. Net effect: stolen owner credential from a non-allowlisted IP still downgrades to partner (static-key path unchanged), AND cannot mint an owner JWT (new consent gate). JWTs already issued to allowlisted IPs work from anywhere for their TTL — use `revokeJti` to kill specific tokens.
- **Global CSP hardened with `form-action 'self'`** (`src/index.ts`): blocks cross-origin form submissions to `/oauth/authorize`, closing a CSRF vector that would otherwise be open.

### Security

- **PKCE S256 only** — `plain` rejected at schema layer.
- **Constant-time PKCE verification** — computed challenge compared to stored challenge via SHA-256 digest + byte-wise XOR.
- **`client_secret` never round-trips** — stored hashed (SHA-256) in KV; only the plaintext from the DCR response is usable by the client, and DCR is one-shot.
- **Static `'Request body failed validation'` on Zod failures** at `/oauth/token` — no parser-internal detail leaks into `error_description`.
- **Discovery metadata** includes only the grant types and PKCE methods this server actually accepts (no wildcards).

### Env bindings

- **New secret**: `OAUTH_SIGNING_SECRET` — HS256 signing key, ≥32 bytes, upload via `wrangler secret put`. Token endpoint returns 500 with static error until populated.
- **New optional var**: `OAUTH_ISSUER` — issuer override. When unset, `resolveIssuer()` derives from request URL origin (correct for typical deployments; set this only if behind a proxy that mangles Host).

## [2.8.1] - 2026-04-18

### Added

- **Issue tracker triage automation** (`.github/workflows/triage-issues.yml`): on `issues: [opened, edited]`, matches six promotional-pattern regexes against title + body; applies `possibly-promotional` label and posts a single automated comment on initial open. Labels only — never auto-closes — so genuine feature requests aren't silently dropped. Workflow reads untrusted event payload fields via `env:` (no expression-injection risk).
- **Issue template config** (`.github/ISSUE_TEMPLATE/config.yml`): disables blank issues, adds structured contact links for Discussions, Security Advisories, and vendor-outreach routing. Forces issue authors to pick a template.

### Changed

- **`production` environment protection**: now requires admin approval + `protected_branches: true` deployment branch policy (applied via API, not in-repo). Affects CI-driven `publish.yml` Cloudflare and npm publish steps once their secrets are configured.
- **GitHub Actions allowlist**: restricted from `all` to `selected` — only GitHub-owned actions, verified-marketplace actions, and `MadaBurns/*` reusable workflows are permitted. Current workflows verified compatible.

## [2.8.0] - 2026-04-18

### Added

- **`DohOutcome` discriminated type** (`src/lib/dns-types.ts`, `src/lib/dns-transport.ts`): DoH transport now returns a discriminated `{ kind: 'ok'; response } | { kind: 'error'; reason: 'timeout' | 'network' | 'parse' | 'http' }` outcome. Callers can distinguish transport failures from "no records" results. Legacy `DohResponse | null` shape still available via `toNullable()`.
- **Unconfirmed secondary-resolver sentinel** (`src/lib/dns-transport.ts`): `confirmWithSecondaryResolvers` returns `{ kind: 'unconfirmed' }` when both bv-dns and Google DoH fail. `queryDoh` falls back to the primary result instead of treating "both resolvers down" as "confirmed absent," eliminating false-negative downgrades.
- **Session analytics on KV failure** (`src/lib/session.ts`): `createSession` accepts optional `AnalyticsClient`; emits `{ degradationType: 'kv_fallback', component: 'session' }` when the KV write fails. Wired via `src/mcp/dispatch.ts` and `src/index.ts`.
- **Per-IP KV advisory lock** (`src/lib/rate-limiter.ts`, `src/lib/config.ts`): `withIpKvAdvisoryLock` + `checkScopedRateLimitKVWithAdvisory` — bounded (≤500ms TTL, single 200ms retry) cross-isolate advisory lock activated only under in-memory contention on the same IP. Zero added latency on uncontended paths.
- **Adaptive-weight cross-isolate convergence** (`src/lib/profile-accumulator.ts`, `src/tools/scan-domain.ts`): `publishAdaptiveWeightSummary` + `getAdaptiveWeights` — isolates converge on identical `(profile, provider)` weight vectors within a 60-second KV TTL window while telemetry is flowing. Static-weight fallback on cache miss or accumulator outage.
- **WAF/CDN challenge classification** (`src/tools/check-http-security.ts`): Cloudflare and Akamai challenge pages are fingerprinted (`server` header + body "Just a moment..." match). Short-circuits to `checkStatus: 'error'` with `metadata: { wafChallenge: <name> }` and a single info finding instead of emitting misleading header-missing findings against a challenge page. Score zeroed on the direct-call path to match the scan-domain reconciliation.
- **Provider-detection degradation flag** (`src/tools/check-mx.ts`, `src/tools/scan/post-processing.ts`): `CheckResult.metadata.providerDetectionFailed = true` when the provider-signature fetch fails. Post-processing respects the flag and skips provider-informed DKIM severity adjustments instead of silently degrading.
- **DNSSEC transport-error classification** (`src/tools/check-dnssec.ts`): DNS transport failures surface as `checkStatus: 'error'` (via the inner-check "DNSSEC check failed" finding sentinel) instead of "not configured." Narrow `DnsQueryError` catch preserved so non-DnsQueryError exceptions still propagate.
- **Degradation event dedup + FNV collision probe** (`src/lib/analytics.ts`): `emitDegradationEvent` accepts optional `scanId` and dedups `(scanId, degradationType, component)` triples within a 60-second rolling window. `doubles[0]` carries `hashCollisionSuspected` (0/1) from an opportunistic in-memory FNV-1a collision cache (10k-entry LRU, production-path zero cost). `scanId` generated once per scan in `scanDomain`.
- **`CheckResult.metadata` field** (`packages/dns-checks/src/types.ts`): additive optional `metadata?: Record<string, unknown>` for carrying diagnostic signals (`providerDetectionFailed`, `wafChallenge`, `dnsError`, etc.). Non-breaking; Zod schema uses plain `z.object` so the field is stripped on validation boundaries rather than rejected.
- **Chaos regression harness** (`test/chaos/invariants.spec.ts`): 11 deterministic regression tests, one per invariant across P1–P8. Reverting any single production fix causes exactly one test to fail. Synchronous fault injection only — no `setTimeout`-based races.

### Changed

- **Error-path log truncation** (`src/lib/log.ts`): verified `MAX_ERROR_STRING_LENGTH = 1024` bound is preserved (error severity keeps four times the context of info/warn severities). Regression test pins the behavior.
- **Runtime `SENTINEL_TTL_SECONDS = 10`** (`src/lib/cache.ts`): tests now pin the bounded sentinel TTL plus the `.then`/`.catch` cleanup ordering so a racing poller always observes the cached result before the sentinel is cleared.

### Fixed

- **Dependency audit** (`package-lock.json`): bumped `hono` transitively to ≥4.12.14 to resolve moderate advisory `GHSA-458j-xx4x-4375` (hono/jsx SSR — unused by this project, but flagged by `npm audit --audit-level=moderate`).

## [2.7.1] - 2026-04-14

### Fixed

- **`check_svcb_https` wire-format parsing** (`packages/dns-checks/src/checks/check-svcb-https.ts`): Cloudflare DoH JSON returns HTTPS (type 65) records in RFC 3597 wire format (`\# <length> <hex>`) rather than the human-readable presentation form. The previous regex-based parsers (`parseAlpn`, `hasEch`, `parsePriority`) only recognised presentation format, so every domain whose HTTPS record was resolved via Cloudflare DoH was incorrectly flagged with `HTTPS record missing ALPN parameter` and `HTTPS record does not advertise HTTP/2`. Added `parseHttpsRecordWire()` that detects the `\# ` prefix, walks the DNS-name labels of TargetName, and decodes SvcParams to extract priority, ALPN protocol list, and ECH presence. Presentation-format parsers retained for the Google DoH fallback path which already returns presentation form. Tests in `test/check-svcb-https.spec.ts` were previously mocking presentation strings (which Cloudflare never returns), masking the bug — added two new tests using real Cloudflare wire-format hex and a synthesised multi-label TargetName fixture.

## [2.7.0] - 2026-04-14

### Added

- **7 new intelligence tools** for Cloudflare Workers:
  - `check_rbl` — Check MX server IP reputation against 8 DNS-based Real-time Blocklists (Spamhaus ZEN, SpamCop, UCEProtect L1/L2, Mailspike, Barracuda, PSBL, SORBS)
  - `check_dbl` — Check domain reputation against Spamhaus DBL, URIBL, and SURBL with bitmask return code decoding
  - `cymru_asn` — Map domain IPs to Autonomous System Numbers via Team Cymru DNS service with high-risk ASN flagging
  - `rdap_lookup` — Fetch domain registration data via RDAP (modern WHOIS) with IANA bootstrap, domain age calculation, and newly-registered domain detection
  - `check_fast_flux` — Detect fast-flux DNS behavior via multi-round DoH queries comparing IP rotation and TTLs
  - `check_dnssec_chain` — Walk the DNSSEC chain of trust from root to target domain, reporting DS/DNSKEY linkage and algorithm strength at each zone level
  - `check_nsec_walkability` — Assess zone walkability risk by analyzing NSEC3PARAM configuration (iterations, salt, opt-out)
- **Shared IP utilities** (`src/lib/ip-utils.ts`) — IPv4/IPv6 reversal and private IP detection for RBL/ASN lookups
- **NSEC3PARAM record type** (type 51) added to DoH query layer
- **Explanation templates** for all 7 new tool categories in `explain_finding`

### Fixed

- **CI `contract` job** — replaced hardcoded `/Users/adam/.cargo/bin/wasm-pack` path with PATH-resolved `wasm-pack` in `build:wasm` script, fixing CI failures across all PRs

## [2.6.7] - 2026-04-10

### Added

- **Score Stability layers** — three targeted mitigations for transient upstream variance that was causing repeat scans of the same domain to occasionally return different scores:
  - **DNSSEC AD flag confirmation probe** (`src/tools/check-dnssec.ts`): when the primary Cloudflare resolver reports "DNSSEC validation failing" (AD=false with DNSKEY+DS records present), a confirmation query is fired to Google DoH. If Google confirms AD=true, the check re-runs with the corrected flag. Resolves the observed edge-node flapping between score 100 (passing) and 75 (failing) on the same domain.
  - **HTTP security dual-fetch with header union** (`src/tools/check-http-security.ts`): two parallel HEAD requests are fired per domain and the 8 browser security headers are merged using union semantics before analysis. Eliminates score variance from CDN edge nodes returning different header sets within a single request.
  - **Transient zero retry in `scanDomain()`** (`src/tools/scan-domain.ts`): any check that returns `checkStatus='error'` with `score=0` (a thrown DNS or HTTPS exception caught by `safeCheck()`) is retried once with a fresh DNS query cache. Max 3 retries per scan, capped at 3 seconds of the 12-second scan budget, 2.5s per-retry timeout. Eliminates the worst-case multi-check zero-out swings (observed Δ52 on keenetic.io, Δ30 on vkuserphoto.ru, Δ20 on reddit.com pre-fix).
- **`scripts/chaos/score-stability-test.py`** — parameterized chaos test for measuring cross-request score stability. Scans N domains across R rounds with `force_refresh` and compares scores category-by-category. Supports loading domains from Tranco JSON files via `--from`. Measured stability: 0% drift at 20 domains, ~5% at 100 domains, ~6.5% at 200 domains (all at concurrency=3).
- **Score Stability section in `docs/scoring.md`** — documents per-request determinism, cross-request variance sources, the three mitigation layers, observed drift rates, and remaining variance sources for users who need consistent scoring.

### Fixed

- **`degradedStatuses` cleanup on successful retry**: when a retry recovers a previously-errored check, its category is now removed from the `degradedStatuses` map so post-processing does not re-apply the zero score to the recovered result.

## [2.1.20] - 2026-04-01

### Added

- **Authentication Hardening** — added `REQUIRE_AUTH` toggle to strictly enforce API key usage. When enabled, the server rejects all unauthenticated requests with 401 Unauthorized, providing a "private mode" for sensitive deployments.
- **Freemium Quota Visibility** — anonymous users now receive `x-quota-tier: free` and other quota-tracking headers in tool responses, aligning the developer experience for free and paid tiers.
- **Enhanced Permission Mapping** — refactored the Wasm policy engine to use an explicit tool-to-mode mapping for all 27+ tools, replacing pattern-based matching with strict architectural enforcement.

### Fixed

- **Git Secret Hygiene** — added `UNLIMITED_KEY_DO_NOT_COMMIT.txt` and `.mcp.json` to `.gitignore` to prevent accidental leakage of sensitive local configuration and master keys.

## [2.1.19] - 2026-04-01

### Added

- **Generic Scoring Engine** — decoupled from concrete DNS checks, using string-keyed categories and a three-tier pure functional formula.
- **WASM Policy Engine** — integrated `bv-wasm-core` for high-performance, tamper-resistant permission checks and token estimation.
- **Modernized Documentation** — completely rewritten README.md, CLAUDE.md, and scoring docs to reflect the new architecture and client-aware formatting.

### Fixed

- **Session revival race condition** — hardened tombstone logic in both memory and KV stores to prevent terminated sessions from being incorrectly revived after a DELETE request.

## [2.1.18] - 2026-04-01

### Added

- **`scripts/chaos/chaos-test-clients.py`** — comprehensive chaos test covering all 9 detected MCP client types
  (`claude_code`, `cursor`, `vscode`, `claude_desktop`, `windsurf`, `mcp_remote`, `blackveil_dns_action`, `bv_claude_dns_proxy`, `unknown`). 56 assertions across 10 sections: session lifecycle per client, format auto-detection (interactive → compact / non-interactive → full), explicit format override, `api_key` query param auth, Bearer vs `api_key` precedence, 9-client concurrent burst, legacy SSE per UA, session edge cases (missing, revival, tombstone, malformed), protocol guards (Content-Type, body size, GET without Accept), and batch JSON-RPC.

## [2.1.17] - 2026-04-01

### Changed

- CLAUDE.md: documented `?api_key=` query param auth, SPF `~all` soft-fail downgrade rule, and Smithery listing/configSchema integration.

## [2.1.16] - 2026-04-01

### Changed

- Documentation: updated Claude Code API key setup to use `?api_key=` query parameter as primary method; added Smithery connection instructions; updated test count.

## [2.1.15] - 2026-04-01

### Added

- **`api_key` query parameter auth** — bearer token can now be passed as `?api_key=` in the URL, enabling auth for clients that only support URL configuration (Smithery, URL-only MCP configs). Header takes precedence when both are present.
- **MCP tool annotations** — every tool definition now includes `group` (`email_auth` | `infrastructure` | `brand_threats` | `dns_hygiene` | `intelligence` | `remediation` | `meta`), `tier` (`core` | `protective` | `hardening`), and `scanIncluded` flag. Fields are included in `tools/list` responses and backward-compatible.
- **npm package exports** — `McpTool`, `TOOLS`, and `TOOL_SCHEMA_MAP` now exported from `blackveil-dns` for consumers who need the tool definitions at build time.
- **Smithery configSchema** — `smithery.yaml` now declares the `apiKey` parameter with `x-to: {query: api_key}` for seamless Smithery Connect integration.

### Fixed

- **SPF `~all` soft-fail downgraded when DMARC enforces** — SPF soft-fail (`~all`) findings are now lowered to `info` severity when the domain has an enforcing DMARC policy (`p=quarantine` or `p=reject`). The RFC-recommended `~all` posture was being incorrectly flagged as a risk in deployments where DMARC already prevents spoofing.
- **DMARC `pct` parameter parsed correctly** — `pct=<100` is now parsed from DMARC records when checking SPF enforcement context. Previously the `pct` check was missed on records that include the percentage tag.

### Changed

- **CI publishes `@blackveil/dns-checks` sub-package** — the `publish.yml` release workflow now publishes `packages/dns-checks` to npm alongside the root package on every version tag.

## [2.1.0] - 2026-03-30

### Added

- **`map_supply_chain`** — Map third-party service dependencies from DNS records. Correlates SPF includes, NS delegates, TXT verifications (39 SaaS patterns), SRV services, and CAA issuers into a unified dependency graph with trust level classification and risk signals (stale integrations, shadow services, insecure protocols, security tooling exposure)
- **`analyze_drift`** — Compare current security posture against a previous baseline; classifies drift as improving/stable/regressing/mixed with per-category deltas
- **`validate_fix`** — Re-check a specific control after applying a fix; returns fixed/partial/not_fixed verdict with propagation hints
- **`generate_rollout_plan`** — Generate phased DMARC enforcement timeline with exact DNS records per phase (aggressive/standard/conservative timelines)
- **`resolve_spf_chain`** — Recursively resolve the full SPF include chain with tree visualization, DNS lookup counting against RFC 7208 10-lookup limit, and detection of circular includes, void lookups, and redundant paths
- **`discover_subdomains`** — Discover subdomains via Certificate Transparency logs. Uses `bv-certstream-worker` service binding for cached data with crt.sh fallback. Detects shadow IT, expired services, wildcard exposure, and multi-CA sprawl
- **`map_compliance`** — Map scan findings to compliance frameworks: NIST 800-177, PCI DSS 4.0, SOC 2 Trust Services Criteria, CIS Controls v8. Shows pass/fail/partial status per control with related findings
- **`simulate_attack_paths`** — Analyze current DNS posture and enumerate 9 specific attack paths (email spoofing, subdomain takeover, DNS hijack, TLS stripping, XSS, clickjacking, cert misissuance, DKIM key compromise) with severity, feasibility, steps, and mitigations
- **Provider-aware fix plans** — `generate_fix_plan` now detects Google Workspace, Microsoft 365, Cloudflare, AWS, and 9 other providers to emit exact step-by-step console instructions with dependency-aware ordering
- Provider knowledge base (`provider-guides.ts`) — extensible static map of 13 provider detection signals and fix guides
- TXT hygiene analysis module (`txt-hygiene-analysis.ts`) — shared constants for 39 SaaS verification patterns and SPF cross-reference data

### Fixed

- Domain validation errors for IP addresses and label length now surface descriptive messages instead of generic "An unexpected error occurred"
- crt.sh queries now use `&exclude=expired` to prevent HTTP 503 on popular domains with large certificate histories

### Changed

- Tool count: 33 → 41 (8 new tools)

## [2.0.11] - 2026-03-28

### Fixed

- **HTTP security headers false negatives on redirecting domains.** `checkHTTPSecurity` used `redirect: 'manual'` without following redirects, causing it to analyze headers on 301/302 responses instead of the final destination. Domains like `nist.gov` (which 301s to `www.nist.gov`) were incorrectly reported as missing CSP, X-Frame-Options, and other headers that the final destination actually serves. Added `followRedirects()` to traverse up to 3 hops, including Cloudflare Workers opaque redirect responses (status 0).
- **2048-bit RSA DKIM keys incorrectly flagged as "below recommended."** `analyzeKeyStrength` in `dkim-analysis.ts` classified all keys with < 550 base64 chars as `strength: 'medium'`, which mapped to a "Below recommended RSA key" finding. A standard 2048-bit RSA key is ~392 chars and falls in this range. Split the threshold so keys below ~380 chars (sub-2048-bit) remain `'medium'`, while actual 2048-bit keys (380-549 chars) are classified as `'info'` — meeting the current minimum standard.

## [2.0.10] - 2026-03-27

### Security

- Hardened release baseline with incremental security safeguards and validation cleanups.

### Documentation

- Refined release documentation and metadata notes for clearer operator guidance.

## [2.0.9] - 2026-03-27

### Added

- MCP tool metadata: every tool definition in `tool-schemas.ts` now includes `group` (`email_auth` | `infrastructure` | `brand_threats` | `dns_hygiene` | `intelligence` | `remediation` | `meta`), `tier` (`core` | `protective` | `hardening`, omitted for non-scoring tools), and `scanIncluded` (boolean indicating participation in `scan_domain` parallel orchestration). Fields are included in `tools/list` responses and are backward-compatible — older clients ignore them.
- New exported types `ToolGroup` and `ToolTier` in `tool-schemas.ts`.
- `test/tool-schemas.spec.ts`: 10-test suite validating metadata completeness, type validity, and scan-inclusion consistency for all 33 tools.

## [2.0.8] - 2026-03-27

### Security

- `BV_API_KEY` static fallback comparison in `tier-auth.ts` changed from `===` (timing-unsafe) to SHA-256 hash comparison (constant-time). Primary auth paths (KV cache, service binding) were already safe.

### Fixed

- README license badge updated from MIT to BUSL-1.1 to match actual license.
- README test count updated from 800+ to 1090+, coverage from ~95% to ~90%.
- README tools table updated from 15 to 22 tools, coverage table from 13 to 20 categories.
- Broken documentation links removed (`docs/coverage.md`, `docs/security-and-observability.md`).
- MCP resource content (`resources.ts`) updated from 50 checks / 10 categories to 57+ checks / 20 categories.
- CONTRIBUTING.md test count updated.
- SUPPORT.md broken link to non-existent `docs/coverage.md` removed.

## [2.0.3] - 2026-03-25

### Fixed

- **Scoring: missing controls no longer pass security checks.** `buildCheckResult` now sets `passed = false` when findings indicate a missing security control — via `scoreIndicatesMissingControl()` (critical/high severity + deterministic/verified confidence) or explicit `missingControl: true` metadata. Previously, a domain with no SPF record (critical, -40) still scored 60/100 and passed.
- **Scoring: hardening tier uses `result.passed` instead of raw score.** The hardening tier bonus calculation now respects the `passed` flag from `buildCheckResult` rather than checking `score >= 50` directly. This prevents checks with absent controls (BIMI, DANE, TLS-RPT) from contributing hardening bonus points.
- **BIMI: validates DMARC enforcement when record exists.** BIMI check now queries DMARC policy regardless of whether a BIMI record is present. When DMARC is not enforcing (p=none), BIMI scores as failed with a medium-severity finding, since mail clients will not display the logo. Previously, a valid BIMI record with DMARC p=none scored 100/100.
- **BIMI/DANE/TLS-RPT: "not found" findings carry `missingControl: true` metadata.** Ensures these hardening-tier checks do not pass when their underlying control is absent, even though their severity (info/low/medium) is below the confidence-gate threshold in `scoreIndicatesMissingControl()`.
- `scoreIndicatesMissingControl()` moved from `scoring/engine.ts` to `scoring/model.ts` to allow `buildCheckResult` to use it without circular dependencies. Re-exported from engine for backward compatibility.

## [1.5.0] - 2026-03-18

### Added

- **MCP prompts support**: agent-led growth optimizations for MCP discoverability.
- **Tier-based rate limiting**: API key authentication resolves to tiers (free, agent, developer, enterprise) with per-tier daily quotas via Durable Objects.
- **Analytics observability**: MCP client detection from user-agent, country/client/tier context threading, session lifecycle events, SQL query builders for Analytics Engine, webhook alerting for Slack/Discord, cron-based alerting.
- **Performance**: scan-scoped DNS query cache to deduplicate redundant queries, batched sensitive subdomain probes (max concurrency 5), increased adaptive weight fetch timeout (50ms → 200ms).

### Fixed

- Service binding URL path corrected for tier-auth validation endpoint.
- Tier-auth debug logging removed; `Headers.entries()` TypeScript error fixed.
- Rate-limit test updated to expect tier-based quota headers for authenticated requests.

## [1.4.0] - 2026-03-17

### Added

- **5 new MCP tools** (17 → 22 total):
  - `check_http_security`: HTTP security header audit (CSP, X-Frame-Options, COOP, CORP, Permissions-Policy, Referrer-Policy, X-Content-Type-Options).
  - `check_dane`: DANE/TLSA record validation for MX and HTTPS certificate pinning.
  - `check_mx_reputation`: Mail server DNSBL lookup and PTR/FCrDNS validation.
  - `check_srv`: SRV record discovery for email, calendar, messaging, and other services.
  - `check_zone_hygiene`: SOA serial consistency and sensitive subdomain exposure detection.
- `scan_domain` now runs **14 checks** in parallel (was 12), adding HTTP Security and DANE.
- DNS library additions: PTR and SRV query helpers, TLSA record parser.

### Changed

- License changed from MIT to Business Source License 1.1 (BUSL-1.1).
- Test SPDX headers updated to BUSL-1.1.

### Security

- Error output sanitized and IPv4 validation added for new tools.
- Undici CVEs patched via npm override (7.18.2 → 7.24.4).

## [1.3.0] - 2026-03-15

### Added

- **2 new MCP tools** (15 → 17 total):
  - `check_shadow_domains`: Alternate-TLD variant discovery with email spoofing risk assessment.
  - `check_txt_hygiene`: TXT record audit for stale verifications, SaaS exposure, and cross-domain trust.
- Public-suffix library for brand name extraction.
- Shadow domains and TXT hygiene added to `CheckCategory` scoring system.
- Pre-commit hook to block committing sensitive directory paths.

### Changed

- Two-phase DNS probing for `check_lookalikes` and `check_shadow_domains`: Phase 1 NS existence filter reduces unnecessary queries.

### Fixed

- MCP session recovery after expiry for Claude Desktop.
- Lookalike variant generation dot mismatch and TXT hygiene DNS failure handling.

### Security

- Defense-in-depth hardening from DevSecOps review.

## [1.2.0] - 2026-03-13

### Added

- **Universal MCP transport support**: three first-party transports — Streamable HTTP, native stdio, and legacy HTTP+SSE — all driven by a single shared executor.
- **Shared MCP executor** (`src/mcp/execute.ts`): transport-neutral request processing layer (validation, rate limiting, session management, dispatch, analytics) consumed by all transports.
- **Native stdio transport** (`src/stdio.ts`): first-party `blackveil-dns-mcp` CLI binary for local-only MCP clients (Claude Desktop, etc.) via the `blackveil-dns` npm package.
- **Legacy HTTP+SSE compatibility**: `GET /mcp/sse` bootstrap stream and `POST /mcp/messages?sessionId=...` message endpoint for older MCP clients that have not migrated to Streamable HTTP.
- **JSON-RPC batch request support**: `POST /mcp` accepts JSON arrays of requests, returning a JSON array of responses (non-streaming) per the JSON-RPC 2.0 specification.
- Legacy SSE stream management module (`src/lib/legacy-sse.ts`) with heartbeat keepalive and graceful cleanup.
- `SERVER_VERSION` single source of truth (`src/lib/server-version.ts`) used by all transports.
- Comprehensive tests for batch requests (4 cases), stdio transport (5 cases), and legacy HTTP+SSE (2 cases).

### Changed

- `src/index.ts` refactored from monolithic transport handler into a thin HTTP adapter delegating to the shared executor.
- `src/mcp/dispatch.ts` now accepts `createSessionOnInitialize` and `existingSessionId` options for transport-specific session semantics.
- `src/mcp/request.ts` batch parsing: non-empty JSON arrays now succeed as `isBatch: true` instead of being rejected.
- `tsup.config.ts` emits a second `stdio` entry point alongside the existing `index` entry.
- `package.json` adds `bin` field (`blackveil-dns-mcp`), `exports.stdio` sub-path, and `mcp:stdio` script.
- `GET /mcp` now strictly requires `Mcp-Session-Id` header (returns 400 without it) — legacy SSE bootstrap moved to dedicated `/mcp/sse`.
- `DELETE /mcp` accepts session ID from both `Mcp-Session-Id` header and `?sessionId=` query parameter for cross-transport compatibility.

### Fixed

- Empty JSON-RPC batch arrays now correctly return a JSON-RPC error (-32600 Invalid Request) instead of being silently rejected.

## [1.1.0] - 2026-03-13

### Changed

- MX IP-target and DNS-query-failure findings downgraded from `high` to `medium` to match MX zero-importance scoring weight.
- `MX_HIGH` explanation entry severity updated to `medium` for consistency.
- `check_spf` now treats shared-platform SPF trust-surface findings as informational by default and only elevates them when weak DMARC enforcement and relaxed alignment corroborate the exposure.
- Free-tier daily quotas raised: `scan_domain` 25 → 75/day, `check_lookalikes` 10 → 20/day, `compare_baseline` 100 → 150/day per IP.

### Added

- Context-aware scoring profiles for `scan_domain`: five named profiles (`mail_enabled`, `enterprise_mail`, `non_mail`, `web_only`, `minimal`) that adapt importance weights based on detected domain purpose. Phase 1: auto-detection runs and is reported in the structured result (`scoringProfile`, `scoringSignals`), but only explicit `profile` parameter values activate different weights. New types `DomainProfile` and `DomainContext` exported from the public package API.
- `scan_domain` now returns a second content block containing machine-readable structured JSON (`score`, `grade`, `passed`, `maturityStage`, `maturityLabel`, `categoryScores`, `findingCounts`, `timestamp`, `cached`) wrapped in `<!-- STRUCTURED_RESULT -->` delimiters. CI/CD consumers can parse this reliably instead of regex-matching the text report.
- `buildStructuredScanResult()` and `StructuredScanResult` type exported from `src/tools/scan/format-report.ts` and the public package API.
- Publishable ESM npm package metadata, bundled public API entrypoint, and `prepack` build flow for consuming the scanner core as `blackveil-dns`.
- Public package exports for reusable scanner functions (`scanDomain`, `check*`, `explainFinding`, scoring helpers, validation helpers) without exposing Worker transport internals.
- Package API regression coverage in `test/package-api.spec.ts`.
- Private deployment override workflow via `wrangler.private.example.jsonc`, ignored `.dev/wrangler.deploy.jsonc`, and `npm run deploy:private` so real Cloudflare KV and Analytics bindings stay out of the public repo.
- Regression coverage for DMARC-aware SPF trust-surface severity in `test/check-spf.spec.ts`, `test/spf-trust-surface.spec.ts`, and `test/handlers-tools.spec.ts`.
- Dangling MX detection: MX hostnames that do not resolve to A or AAAA records are flagged as `medium` severity.

### Fixed

- Profile detection now correctly handles Null MX (RFC 7505) domains as `non_mail`/`web_only` instead of `mail_enabled`.
- Profile detection now defaults to `mail_enabled` when MX DNS query fails, instead of misclassifying as `non_mail`/`web_only`.
- `scan_domain` error path now preserves explicit profile override instead of silently dropping it.
- `scan_domain` tool schema description now lists all 12 checks including BIMI and TLS-RPT.
- MCP resource documentation corrected: "50+ checks in 13 categories" (was "50 checks in 10 categories").
- README check counts corrected for BIMI (2→1), TLS-RPT (2→1), Lookalikes (3→1).
- Scoring documentation (CLAUDE.md, docs/scoring.md, resources.ts) updated to reflect actual importance weights (Subdomain Takeover=3, NS=0, CAA=0) and added scoring profile documentation.
- Critical penalty documentation updated to reflect verified-confidence-only condition introduced in v1.0.3.
- Source file references in docs/scoring.md updated from barrel re-export to actual implementation files.
- Merged duplicate `### Added` section in CHANGELOG v1.0.3 entry.

## [1.0.3] - 2026-03-07

### Changed

- `check_subdomain_takeover` now reports unresolved third-party CNAME takeover signals as `high` (potential) instead of `critical`.
- Global scan critical penalty now applies only when at least one `critical` finding is confidence-qualified as `verified`.
- `check_dkim` now consolidates duplicate selector-probe key-strength findings across selectors to reduce repeated scoring penalties for identical key profiles.

### Added

- Regression coverage for takeover potential-severity behavior in `test/check-subdomain-takeover.spec.ts`.
- Regression coverage for verified-critical global penalty behavior in `test/scoring.spec.ts`.
- Regression coverage for DKIM duplicate key-strength consolidation in `test/check-dkim.spec.ts`.
- Cloudflare Analytics Engine dataset binding support (`MCP_ANALYTICS`) for request and tool usage telemetry.
- `/health` response now includes analytics runtime status (`analytics.enabled`) for operational verification.

### Fixed

- Analytics Engine payload schema now uses a single index per data point to match platform limits and prevent `writeDataPoint(): Maximum of 1 indexes supported` warnings.
- Reduced in-isolate KV rate limiter race amplification by serializing per-IP `get/check/put` updates.
- Added unauthenticated session-creation throttling (`30/min` per IP) for `initialize` and new SSE session bootstrap.
- Bounded in-memory session fallback with LRU eviction (`2000` max active sessions) to reduce memory-pressure abuse risk.
- Domain validation now rejects IPv4 literals across standard and alternate numeric forms (short-form, octal, hex, dword), including public-IP and dotted-numeric payloads (for example `192.0.2.53`, `0x8.0x8.0x8.0x8`, and `999.999.999.999`).

### Changed

- `check_subdomain_takeover` now runs known subdomain probe flow in parallel to reduce worst-case `scan_domain` latency.
- Provider signature loading now uses a short-lived in-isolate cache (5 minutes) when `PROVIDER_SIGNATURES_URL` is configured.
- `check_spf` now performs RFC-aware DNS lookup budget analysis with explicit near-limit signaling at 9/10 lookups.
- `check_dkim` now probes an expanded set of common provider selectors (`selector`, `s1024`, `s2048`, `amazonses`, `mandrill`, `mailjet`, `zoho`) for better detection depth.
- `check_dkim` now validates RSA key strength using base64 length heuristic (512/1024/2048/4096-bit detection) with critical/high/medium severity based on estimated bits.
- `check_dkim` now validates presence of `v=DKIM1` tag (medium severity if missing).
- `check_dmarc` now validates `sp` strictness against parent `p` policy, validates `fo` options, and validates `pct` range handling.
- `check_dmarc` now validates `rua=` and `ruf=` URI formats (must use `mailto:` scheme with valid email).
- `check_dmarc` now checks `adkim=` and `aspf=` alignment modes with low-severity warnings for relaxed alignment (default).
- `check_dmarc` "properly configured" info finding now displays even with low-severity alignment warnings.

### Added

- Provider signature cache behavior tests in `test/provider-signatures.spec.ts`.
- A dedicated `scan_domain` latency troubleshooting section in `docs/troubleshooting.md`.
- SPF regression test for lookup-budget near-limit warning behavior in `test/check-spf.spec.ts`.
- DMARC regression tests for `sp` downgrade detection, `fo` validation, and invalid `pct` handling in `test/check-dmarc.spec.ts`.
- DKIM RSA key strength validation tests covering all severity levels (critical, high, medium, info) in `test/check-dkim.spec.ts`.
- DKIM `v=` tag validation test in `test/check-dkim.spec.ts`.
- DMARC URI validation tests for `rua=` and `ruf=` tags in `test/check-dmarc.spec.ts`.
- DMARC third-party aggregator detection (dmarcian, valimail, agari, returnpath, postmarkapp, dmarcanalyzer, mimecast, proofpoint, 250ok, easydmarc).
- DMARC alignment mode validation tests for `adkim=` and `aspf=` tags in `test/check-dmarc.spec.ts`.
- 18 new DMARC test cases and 5 new DKIM test cases.
- Rate limiter regression test for concurrent KV requests (`test/rate-limiter.spec.ts`).
- Session creation limiter tests in `test/session.spec.ts`.
- Initialize throttling integration test in `test/index.spec.ts`.
- `tools/call` alias support for `scan` -> `scan_domain`.
- Alias coverage tests in `test/handlers-tools.spec.ts` and `test/index.spec.ts`.
- Domain-validation regressions for alternate IPv4 host literals in `test/sanitize.spec.ts`.
- `tools/call` integration coverage for short-form and octal loopback rejection in `test/index.spec.ts`.

## [1.0.2] - 2026-03-04

### Removed

- `upgrade_cta` from scan output — conversion hook belongs in README, not tool output

### Added

- HSTS header validation and HTTP→HTTPS redirect check in `check_ssl`
- Null MX (RFC 7505), IP address detection, redundancy check in `check_mx`
- SSL and MX explanation entries for `explain_finding`

### Changed

- `explain_finding` status enum expanded to include all severity levels (critical, high, medium, low, info)
- "No MX records found" severity from `high` to `medium`
- `CATEGORY_DEFAULTS` renamed to `CATEGORY_DISPLAY_WEIGHTS` for clarity

### Fixed

- CHANGELOG rate limit typo (50 → 100 req/hr)
- Static resources updated to reflect 10 checks (was "8 category checks")

## [1.0.0] - 2026-02-24

### Added

- 12 MCP tools: `scan_domain`, `check_spf`, `check_dmarc`, `check_dkim`, `check_mx`, `check_ssl`, `check_dnssec`, `check_mta_sts`, `check_ns`, `check_caa`, `check_subdomain_takeover`, `explain_finding`
- 3 static MCP resources: security checks guide, scoring methodology, DNS record types
- MCP Streamable HTTP transport (JSON-RPC 2.0) with SSE support
- Weighted scoring engine aligned with BLACKVEIL scanner (50 checks, 8 categories)
- Email authentication bonus (up to 8 points) when SPF + DKIM + DMARC all pass
- DNS-over-HTTPS via Cloudflare DoH — no direct DNS resolution
- KV-backed per-IP rate limiting (10 req/min, 100 req/hr) with in-memory fallback
- KV-backed scan result cache (5-min TTL) with in-memory fallback
- Per-check caching in `tools/call` handler
- Optional bearer token authentication (open mode when `BV_API_KEY` is empty)
- Constant-time token comparison for auth
- SSRF protection: blocks private IPs, reserved TLDs, DNS rebinding services
- Input validation per RFC 1035 (domain length, label rules)
- Error sanitization — only known validation errors surface to clients
- Request body size limit (10 KB)
- Session management with cryptographic session IDs
- Health endpoint at `/health`
- Landing page at `/`
- 245+ tests with ~95% line coverage
- CI/CD via GitHub Actions (test on PR, auto-deploy on push to main)
- Smithery marketplace manifest
- CLAUDE.md agent documentation

### Security

- IP sourcing uses only `cf-connecting-ip` — never `x-forwarded-for`
- Auth uses constant-time XOR comparison to prevent timing side-channel attacks
