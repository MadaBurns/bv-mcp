// SPDX-License-Identifier: BUSL-1.1

/**
 * The scan_domain per-category dispatch table (and the sets derived from it).
 * Split out of scan-domain.ts (SQ-537) with no behaviour change; scan-domain.ts
 * re-exports every name that module exported before.
 */

import type { CheckCategory, CheckResult } from '../../lib/scoring';
import type { ZoneContext } from '@blackveil/dns-checks';
import type { QueryDnsOptions } from '../../lib/dns-types';
import type { RobotsFetchMemo } from '../../lib/robots-memo';
import { checkSpf } from '../check-spf';
import { checkDmarc } from '../check-dmarc';
import { checkDkim } from '../check-dkim';
import { checkDnssec } from '../check-dnssec';
import { checkSsl } from '../check-ssl';
import { checkMtaSts } from '../check-mta-sts';
import { checkNs } from '../check-ns';
import { checkCaa } from '../check-caa';
import { checkBimi } from '../check-bimi';
import { checkTlsrpt } from '../check-tlsrpt';
import { checkSubdomainTakeover } from '../check-subdomain-takeover';
import { checkMx } from '../check-mx';
import { checkPtr } from '../check-ptr';
import { checkHttpSecurity } from '../check-http-security';
import { checkDane } from '../check-dane';
import { checkDnskeyStrength } from '../check-dnskey-strength';
import { checkDaneHttps } from '../check-dane-https';
import { checkSvcbHttps } from '../check-svcb-https';
import { checkSubdomailing } from '../check-subdomailing';
import type { ScanRuntimeOptions } from './post-processing';

/**
 * TLS probe (Browser Rendering) is a paid-tier enrichment — skip it for
 * free/agent/anonymous scans, which are ~98% of volume and the cost driver.
 */
const PROBE_ELIGIBLE_TIERS = new Set(['developer', 'enterprise', 'partner', 'owner']);

/**
 * Resolve the TLS-probe binding for the `ssl` and `dane_https` checks, gated on tier
 * eligibility. Paid-tier only — free/agent/anonymous scans skip Browser Rendering.
 */
function resolveTlsProbeOptions(rt?: ScanRuntimeOptions): { tlsProbeBinding?: { fetch: typeof fetch }; tlsProbeAuthToken?: string } {
	return {
		tlsProbeBinding: PROBE_ELIGIBLE_TIERS.has(rt?.authTier ?? '') ? rt?.tlsProbeBinding : undefined,
		tlsProbeAuthToken: rt?.tlsProbeAuthToken,
	};
}

/** Shape the provider-signature options object shared by the mx and ptr checks. */
function resolveProviderSignatureOptions(rt?: ScanRuntimeOptions): {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
} {
	return {
		providerSignaturesUrl: rt?.providerSignaturesUrl,
		providerSignaturesAllowedHosts: rt?.providerSignaturesAllowedHosts,
		providerSignaturesSha256: rt?.providerSignaturesSha256,
	};
}

/**
 * A per-category check runner. Captures the bespoke argument shaping for each
 * scanned category in one place (the single source of dispatch truth used by
 * BOTH the initial-run fan-out and {@link runCheckRetry}). `ssl` and
 * `http_security` ignore the `dnsOptions` parameter by design — but DO take the
 * optional 4th `perCheckSignal` (R7).
 *
 * R7 signal routing — two DELIBERATELY distinct signals:
 *   • DoH checks read `dnsOptions.signal` (the SCAN-level signal). They share
 *     one `queryCache`, so a query started by check A and deduplicated to check
 *     B is driven by A's signal; a PER-CHECK abort there would cross-contaminate
 *     a sibling. The scan-level signal only fires when the whole scan times out,
 *     at which point abandoning every in-flight DoH query is correct.
 *   • THREE checks make INDEPENDENT, un-cached requests that no sibling can be
 *     deduplicated onto, so they safely receive the narrower `perCheckSignal`
 *     (composed: this check's per-check timeout OR the scan-level abort): the
 *     raw-`fetch` `ssl` and `http_security`, plus `dane_https`, whose TLS-probe
 *     service binding is likewise outside the shared `queryCache`. `dane_https`
 *     DOES still take `dnsOptions` for its TLSA lookup; the other two ignore it.
 *
 * The optional 6th `robotsMemo` (issue #641) is the ONE piece of per-scan state
 * those two raw-`fetch` checks DO share: a URL-keyed memo so the single
 * `https://<domain>/robots.txt` both of them must fetch is fetched once, not
 * twice. Omitted on the retry path and on every direct tool call, where each
 * check keeps its own private gate.
 */
type CheckRunner = (
	domain: string,
	dnsOptions: QueryDnsOptions,
	rt?: ScanRuntimeOptions,
	perCheckSignal?: AbortSignal,
	zone?: ZoneContext,
	robotsMemo?: RobotsFetchMemo,
	/**
	 * Wall-clock a check's own fetches may collectively spend (issue #641).
	 * Threaded like `robotsMemo`: optional 7th param, supplied at the single
	 * dispatch site, omitted by `runCheckRetry` and every direct tool call.
	 * Only checks that issue SEQUENTIAL fetches whose fixed timeouts can sum past
	 * the per-check budget need it — `ssl` (3+4+4 = 11s inside 8s), `http_security`,
	 * and (#674) `mta_sts` (robots 3s + policy 4s, after two DNS lookups) plus
	 * `subdomain_takeover` (robots 3s + fingerprint probe 4s, after two DNS lookups).
	 */
	fetchBudgetMs?: number,
) => Promise<CheckResult>;

/**
 * The single dispatch table for all NORMAL-PROFILE scanned categories.
 *
 * Key insertion order is load-bearing: it defines {@link SCAN_CATEGORIES} (and
 * thus the scan fan-out order). It MUST match the historical normal-profile
 * `ALL_CHECK_CATEGORIES` order. The `authoritative_dns_infra`/`root_server_set`
 * profile-only checks are deliberately NOT here — that profile takes its own
 * branch (Promise.all + mergeAuthoritativeDnsInfraResults).
 */
// Exported (only) so `test/audits/scan-domain-dns-pool-classification.audit.test.ts`
// can independently re-derive, via source-text reflection, which entries discard
// their `dns` parameter — see CHECKS_WITHOUT_DNS_POOL below. Not part of the
// public runtime contract; use CHECK_DISPATCH[cat](...) only, never re-key it.
export const CHECK_DISPATCH: Record<string, CheckRunner> = {
	spf: (d, dns) => checkSpf(d, dns),
	dmarc: (d, dns) => checkDmarc(d, dns),
	dkim: (d, dns) => checkDkim(d, undefined, dns),
	dnssec: (d, dns, _rt, _sig, zone) => checkDnssec(d, dns, zone),
	// R7: the raw-`fetch` checks take the narrower per-check signal (4th arg) so a
	// per-check / scan-level timeout aborts their in-flight HTTPS subrequests.
	// undefined outside scan context (direct calls / retry path) → unchanged.
	ssl: (d, _dns, rt, sig, _zone, robots, budget) =>
		checkSsl(d, { ...resolveTlsProbeOptions(rt), signal: sig, robotsMemo: robots, budgetMs: budget }),
	// #674: `mta_sts` and `subdomain_takeover` are the remaining raw-HTTP checks whose
	// fetches carry fixed timeouts the caller cannot lower (the package hardcodes the
	// policy-fetch and fingerprint-probe timeouts), so they take the budget for the same
	// reason `ssl` and `http_security` do.
	mta_sts: (d, dns, _rt, _sig, zone, _robots, budget) => checkMtaSts(d, dns, zone, { budgetMs: budget }),
	ns: (d, dns, rt, _sig, zone) => checkNs(d, dns, zone, { infraProbe: rt?.infraProbe }),
	caa: (d, dns, _rt, _sig, zone) => checkCaa(d, dns, zone),
	bimi: (d, dns) => checkBimi(d, dns),
	tlsrpt: (d, dns) => checkTlsrpt(d, dns),
	subdomain_takeover: (d, dns, _rt, _sig, _zone, _robots, budget) => checkSubdomainTakeover(d, dns, { budgetMs: budget }),
	http_security: (d, _dns, _rt, sig, _zone, robots, budget) => checkHttpSecurity(d, { signal: sig, robotsMemo: robots, budgetMs: budget }),
	dane: (d, dns) => checkDane(d, dns),
	mx: (d, dns, rt) => checkMx(d, resolveProviderSignatureOptions(rt), dns),
	// #841: TLSA pin verification captures the served certificate over the same
	// paid-tier-gated probe as `ssl`. The probe is a service binding the fetch budget
	// cannot wrap, so the budget is threaded for its `signal()`; the wrapper launches it
	// only when TLSA records exist, so a DANE-less domain (≈ all of them) pays nothing.
	dane_https: (d, dns, rt, sig, _zone, _robots, budget) =>
		checkDaneHttps(d, dns, { ...resolveTlsProbeOptions(rt), signal: sig, budgetMs: budget }),
	svcb_https: (d, dns) => checkSvcbHttps(d, dns),
	subdomailing: (d, dns) => checkSubdomailing(d, dns),
	dnskey_strength: (d, dns) => checkDnskeyStrength(d, dns),
	ptr: (d, dns, rt) => checkPtr(d, resolveProviderSignatureOptions(rt), dns),
};

/**
 * The runtime scan category set — the keys of {@link CHECK_DISPATCH}, in order.
 * Frozen export contract: `test/audits/scan-domain-wiring.audit.test.ts` pins
 * this against the `scanIncluded` SSOT in TOOL_DEFS.
 */
export const SCAN_CATEGORIES: CheckCategory[] = Object.keys(CHECK_DISPATCH) as CheckCategory[];

/**
 * Dispatch entries that ignore the `dnsOptions` (2nd) parameter entirely — see
 * the CheckRunner JSDoc above — and so never call `dnsSemaphore.run()`. These
 * are the ONLY two of the 19 {@link CHECK_DISPATCH} entries a raw-`fetch`
 * check can be: `dane_https` also takes the narrow per-check signal but DOES
 * still thread `dnsOptions` through for its TLSA lookup, so it is NOT here.
 *
 * #952/SQ-15 repair: `safeCheck`'s per-check timer extension (the `queueClock`
 * argument) must be withheld from these two. The original #952 fix wired the
 * shared `dnsSemaphore.saturatedMs()` unconditionally to every category, so a
 * raw-fetch check's declared timeout went silently unenforced whenever ANY
 * OTHER check in the same scan queued on the DNS pool — even though `ssl`/
 * `http_security` never wait on it themselves. Pinned against dispatch-table
 * drift by `test/audits/scan-domain-dns-pool-classification.audit.test.ts`,
 * which fails if a new entry discards its `dns` parameter without being added
 * here (or vice versa).
 */
export const CHECKS_WITHOUT_DNS_POOL: ReadonlySet<CheckCategory> = new Set<CheckCategory>(['ssl', 'http_security']);
