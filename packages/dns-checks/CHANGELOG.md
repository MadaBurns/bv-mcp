# Changelog

All notable changes to `@blackveil/dns-checks` are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/), and this package adheres to [Semantic Versioning](https://semver.org/).

## [2.5.0]

### Changed (non-scoring; no score moves)

- `web_content` no longer reports a missing integrity hash as fixable when the provider cannot be pinned. Cross-origin resources from `static.cloudflareinsights.com` (Cloudflare Web Analytics), `challenges.cloudflare.com` (Cloudflare Turnstile), `googletagmanager.com` and `google-analytics.com`, or a subdomain of one of those hosts, now produce one `info` finding, "Cross-origin resource from a provider that does not support SRI", instead of the `low` "Cross-origin resource without Subresource Integrity". These providers change the file at the same URL, so a hash would break the page. The new finding names each provider and its reason in `metadata.providers`, and it states the remaining risk.
- Hosts match exactly or as a subdomain of a listed host, never by substring. A look-alike host, or another host of the same provider such as `cdnjs.cloudflare.com`, keeps the `low` finding.
- `web_content` has importance 0 in every profile and is excluded from scoring, so no overall score or grade moves. A consumer that matches on the old title will no longer see these hosts under it. No `*_PARITY_FIXTURES` expected score changed. `PARITY_CORPUS_VERSION` is `2.5.0`.

## [2.4.0]

### Added (no check changes; a consumer that starts calling it can move scores)

- `applySilentDomainDkimApplicability(results)` on the `@blackveil/dns-checks/scoring` subpath. For a domain with no inbound mail (no MX or an RFC 7505 null MX) and an SPF policy that authorizes no sender, it restates the DKIM findings "DKIM keys revoked", "Revoked DKIM key: …" and "DKIM key record has no public key: …" from `high` or `critical` to `info`, appends the reason to the detail, and retracts a declared `missingControl`. Revoking every key is the correct posture for a domain that neither sends nor receives mail. A usable key, even a weak one, keeps its rating. A result set that does not establish both conditions is returned unchanged, and a DKIM result that did not complete is returned as the same object.
- The rule was previously applied only by the hosted scanner's server layer (scoring model 1.42.0), so a consumer of the package alone reported the same domain with a high-severity DKIM finding. The hosted scanner now calls this function, so its output is unchanged.
- Call it on a scan's check results before `computeProfileAwareScanScore`. It rebuilds the `dkim` result from the adjusted findings, so that category's score and `passed` move with the severities. Under a profile that gives DKIM a nonzero weight (`non_mail` carries a small one) the overall score can rise; under `web_only` DKIM has zero weight and the overall score does not move.
- `mxDeclaresNoInboundMail(mxResult)` and `notApplicableMetadata(finding)` are exported from the same subpath. They are the predicate and the helper the rule uses, moved from the server layer so both sides share one implementation.
- No check function changed and no `*_PARITY_FIXTURES` expected score changed. `PARITY_CORPUS_VERSION` is `2.4.0`.

## [2.3.0]

### Changed (moves scores up; scoring model 2.3.0)

- The DMARC finding "No forensic reporting configured (ruf= absent)" is `info` instead of `low`. It is still reported when `rua=` is published and `ruf=` is not, with the same title, but it no longer deducts 5 points from the `dmarc` category. A forensic address is optional and a sender may decline it for privacy.
- The DMARC finding "Limited DMARC failure reporting coverage" (`fo=0`) is `info` when the record publishes no `ruf=` address, because the tag then has no effect. It stays `low` when a `ruf=` address is published. The title is unchanged.
- Six `DMARC_PARITY_FIXTURES` expected scores rise by 5. `PARITY_CORPUS_VERSION` is `2.3.0`.
- Unchanged: "No aggregate reporting" (`rua=` absent) stays `medium`, and so do the invalid `ruf=` address and invalid `fo=` findings.

## [2.2.0]

### Fixed (can move scores; scoring model 2.2.0)

- `checkDANEHTTPS` and `checkSVCBHTTPS` read a SERVFAIL or REFUSED answer for the TLSA / HTTPS lookup as "record absent" ("No DANE TLSA for HTTPS", "No HTTPS record found"), because a DoH resolver answers HTTP 200 for those and only the response code differs. They now use the rcode channel (`queryWithRcode`, `buildRcodeAbstentionResult`) and abstain: `checkStatus: 'error'`, an `inconclusive` finding with `errorKind: 'dns_error'`, never `missingControl`, so the scoring engine excludes the category. A NOERROR-empty or NXDOMAIN answer keeps its finding and score exactly. A thrown lookup already abstained and is unchanged.
- `checkBIMI` reads the `_dmarc` prerequisite lookup three-state. An unanswered lookup was treated as "DMARC not enforcing", which reported a published BIMI record as "BIMI record ineffective (DMARC not enforcing)" (`medium`, `missingControl`). It now reports an info finding "BIMI DMARC prerequisite not determined" with `inconclusive` and `errorKind: 'dns_error'` and leaves `controlPresent` undefined; an absent BIMI record no longer asserts DMARC state in that case. Answered `_dmarc` lookups behave as before.
- Checked and left unchanged: the DKIM CNAME-chain follow (`checkDKIM`) only attributes a selector to a SaaS provider after the TXT lookup has already found the key, so a failed CNAME hop cannot turn a present key into an absent one.
- `http_security` (dns-checks 2.1.1) now counts toward scoring model 2.2.0: an HTTP status 0 or 5xx answer is unmeasured and excluded, where it was scored before 2.1.1.
- The Worker-side PTR check (`src/tools/check-ptr.ts`, not part of this package) abstains for an unanswered MX lookup and for an unanswered A lookup of every mail host instead of reporting "no inbound mail" / "Mail server IPs unresolved". The corpus frequency of these cases is not measured.

## [2.1.1]

### Fixed (can move scores; scoring model unchanged at 2.1.0)

- `checkHTTPSecurity` treats an HTTP server error (status 0 or 5xx, on the first request or on the GET fallback) as unmeasured: the finding carries `inconclusive: true`, `errorKind: 'http_server_error'` and `httpStatus`, and the result is marked so the scoring engine excludes the category. Previously the answer was scored although no header evidence was available. The robots.txt skip remains a separate voluntary abstention.

## [2.1.0]

### Fixed (can move scores; scoring model 2.1.0)

- `checkSPF` resolves the DMARC context for its trust-surface findings with the same parent walk `checkDMARC` uses. A subdomain without its own `_dmarc` record inherits the parent's `sp=` (else `p=`), so an enforcing inherited policy no longer reads as "no DMARC record". A failed DMARC lookup (SERVFAIL, REFUSED or a thrown error) is unmeasured, not missing.
- SPF lookup counting ignores `redirect=` when the record has an `all` mechanism, and does not follow it.
- `checkTLSRPT` selects `v=TLSRPTv1` records individually instead of concatenating every TXT record at `_smtp._tls`. More than one TLS-RPT record yields only the multiple-records finding.
- RSA DKIM key-size estimation recognises 3072-bit keys; they were reported as 4096-bit.

## [2.0.0]

### Changed (breaking: score semantics)

- Scoring model 2.0.0. The default `tierSplit` is `{ core: 75, protective: 25, hardening: 0 }`. The hardening tier is empty; its binary pass-rate pool is removed.
- Former hardening categories (`dane`, `ptr`, `bimi`, `tlsrpt`, `txt_hygiene`, `mx_reputation`, `srv`, `zone_hygiene`, `brand_discovery`, `dnskey_strength`) are protective-tier categories with explicit per-profile importances in `PROFILE_WEIGHTS`. `tlsrpt` and `dane` weigh 2 in the mail profiles; the rest are 0 in the scan profiles, except `zone_hygiene` (10) and `dnskey_strength` (2) in `authoritative_dns_infra`.
- `lookalikes` and `shadow_domains` are importance 0 in every profile.
- `criticalOverallPenalty` defaults to `0` (was 15), and `emailBonusFull`/`emailBonusMid`/`emailBonusPartial` default to `0` (were 5/3/2). The config keys and code paths remain; an explicit `SCORING_CONFIG` override still applies.
- Unchanged: the critical-gap ceiling (64), the partial-enforcement ceiling (94), the evidence gate, null/UNGRADED abstention and profile detection.
- The `hardening` value remains in the published `CategoryTier` type and `tierSplit` key for compatibility, but no category uses it.

Scores produced under 2.0.0 are not comparable with earlier versions. See `docs/scoring.md` in the repository for the full methodology.
