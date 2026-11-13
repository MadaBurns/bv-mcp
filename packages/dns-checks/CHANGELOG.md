# Changelog

All notable changes to `@blackveil/dns-checks` are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/), and this package adheres to [Semantic Versioning](https://semver.org/).

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
