# Changelog

All notable changes to `@blackveil/dns-checks` are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/), and this package adheres to [Semantic Versioning](https://semver.org/).

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
