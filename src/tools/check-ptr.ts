// SPDX-License-Identifier: BUSL-1.1

/**
 * PTR / forward-confirmed reverse DNS (FCrDNS) check for a domain's mail servers.
 *
 * For each MX host, resolves its A records, performs a PTR lookup on each IP, then
 * forward-confirms: the PTR hostname's A records must contain the original IP (canonical
 * FCrDNS). Hardening-tier, bonus-only — absence never penalizes (`info`); a present but
 * unconfirmed PTR is `low`. Mirrors `check-mx`'s provider-options signature so managed
 * mail (Google/M365) is credited rather than flagged.
 *
 * The resolution phase is scheduled through a bounded pool — see `PTR_LOOKUP_CONCURRENCY`.
 */

import { buildCheckResult, createFinding, type CheckResult } from '../lib/scoring';
import { buildDnsErrorResult } from '../lib/dns-error-result';
import { queryDnsRecords, queryMxRecords, queryPtrRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { mapConcurrent } from '../lib/map-concurrent';
import { detectProviderMatches, loadProviderSignatures } from '../lib/provider-signatures';

export interface CheckPtrOptions {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
}

/**
 * Max DNS lookups this check keeps in flight during the mail-host / FCrDNS resolution phases.
 *
 * PTR is intrinsically serial *per IP* (PTR lookup, then a forward-confirming A lookup on the
 * PTR hostname), and the total query count is `1 (MX) + |mxHosts| (A) + 2 x |IPs|`. Resolving
 * that entirely serially made the check's latency scale with the size of the mail estate:
 * fastmail.com publishes 2 MX hosts resolving to 12 IPs = 27 serial round-trips, ~8.1s at a
 * ~300ms cold RTT, which exceeds the 8s per-check budget and surfaced as a `ptr` timeout in
 * `scan_domain` (#641). Scheduling those same queries through a bounded pool collapses them
 * into ~8 rounds (~2.4s cold) for that shape.
 *
 * **Why bounded rather than an unbounded `Promise.all` over the IP list.** Cloudflare caps
 * subrequests per invocation at 50 on the Free plan (10k+ on Paid, which BlackVeil production
 * runs), and a cold `scan_domain` already fans out ~20 subrequests across its 19 categories.
 * An unbounded burst over an arbitrary-length IP list would raise the PEAK in-flight subrequest
 * count without limit and tighten that Free-plan ceiling for BSL self-hosters. 4 is deliberately
 * conservative: it is a ~3.4x round-trip reduction on the fastmail shape while adding at most 3
 * to the instantaneous in-flight count. The TOTAL number of queries is identical either way —
 * only their scheduling changes, so the measurement (findings, severities, score) is unchanged.
 *
 * Inside `scan_domain` this composes with (and stays well under) the scan-wide
 * `Semaphore(SCAN_DNS_CONCURRENCY = 12)` that already caps outbound DoH fetches for the whole
 * fan-out, so the scan's peak subrequest pressure is unchanged. On a DIRECT `check_ptr` call
 * there is no such semaphore, which is why this bound lives here rather than being left to the
 * caller.
 */
const PTR_LOOKUP_CONCURRENCY = 4;

/** One mail-host IP awaiting PTR / forward-confirmation, carrying its originating MX host. */
interface MailHostIp {
	host: string;
	ip: string;
}

/** Per-IP FCrDNS outcome. `detail` is the human-readable fragment for this IP. */
interface PtrOutcome {
	status: 'confirmed' | 'mismatched' | 'missing';
	detail: string;
}

export async function checkPtr(domain: string, options?: CheckPtrOptions, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	try {
		const mx = await queryMxRecords(domain, dnsOptions);

		// An RFC 7505 null MX ("0 .") parses to an EMPTY exchange, so a null-MX domain
		// still yields `mx.length === 1` while carrying no mail host at all. Filter those
		// (and any empty/root exchange) out first and branch on the usable-host count, so
		// "no MX at all" and "null MX" both land in the same not-applicable fork. Branching
		// on `mx.length` alone let a null-MX domain fall through to the resolution loop and
		// emit the degenerate "could not resolve A records for 0 mail server host(s)".
		const mxHosts = mx.map((r) => r.exchange.replace(/\.$/, '').toLowerCase()).filter((h) => h.length > 0 && h !== '.');

		if (mxHosts.length === 0) {
			// Mirrors check_dane's no-inbound-mail fork: the domain does not accept email,
			// so PTR/FCrDNS is NOT APPLICABLE — not a measurement that failed.
			const nullMx = mx.length > 0;
			return buildCheckResult('ptr', [
				createFinding(
					'ptr',
					'PTR not applicable (no inbound mail)',
					'info',
					`${domain} publishes no usable MX records (${nullMx ? 'an RFC 7505 null MX' : 'none'}), so it does not accept inbound email. Reverse DNS (PTR / forward-confirmed reverse DNS) for mail servers is therefore not applicable.`,
					{ applicable: false, nullMx, mailHostCount: 0 },
				),
			]);
		}

		// Managed-provider credit: the provider controls PTR; treat the control as present.
		const signatures = await loadProviderSignatures({
			sourceUrl: options?.providerSignaturesUrl,
			allowedHosts: options?.providerSignaturesAllowedHosts,
			expectedSha256: options?.providerSignaturesSha256,
		});
		const providerMatches = detectProviderMatches(mxHosts, signatures.inbound);
		if (providerMatches.length > 0) {
			const names = providerMatches.map((m) => m.provider).join(', ');
			return buildCheckResult(
				'ptr',
				[
					createFinding(
						'ptr',
						'PTR managed by mail provider',
						'info',
						`Mail is handled by managed provider(s) (${names}); reverse DNS (PTR) is provider-controlled and not configurable by the domain owner.`,
						{ providers: providerMatches.map((m) => m.provider), signatureSource: signatures.source },
					),
				],
				true,
			);
		}

		// Resolution is issued through a BOUNDED pool (PTR_LOOKUP_CONCURRENCY) rather than
		// serially. The queries themselves are unchanged — same hosts, same IPs, same order of
		// results — so the findings/severities/score for a given DNS state are identical; only
		// the round-trip count drops. `mapConcurrent` writes results back by INDEX, so the
		// per-IP detail fragments stay in MX-record order regardless of which lookup finishes
		// first (the sole order-dependent output in this check).
		//
		// Error handling mirrors the old serial loop: the first failure aborts the check and
		// propagates to the top-level catch (transient-error result). The `firstError` latch
		// makes queued items no-op instead of rejecting, so in-flight siblings settle quietly
		// rather than surfacing as unhandled rejections, and no NEW work is dispatched after
		// a failure.
		let firstError: unknown;

		const ipsPerHost = await mapConcurrent(mxHosts, PTR_LOOKUP_CONCURRENCY, async (host) => {
			if (firstError !== undefined) return [] as string[];
			try {
				return await queryDnsRecords(host, 'A', dnsOptions);
			} catch (err) {
				firstError ??= err;
				return [] as string[];
			}
		});
		if (firstError !== undefined) throw firstError;

		const mailHostIps: MailHostIp[] = mxHosts.flatMap((host, index) => ipsPerHost[index].map((ip) => ({ host, ip })));

		const outcomes = await mapConcurrent(mailHostIps, PTR_LOOKUP_CONCURRENCY, async ({ host, ip }): Promise<PtrOutcome | null> => {
			if (firstError !== undefined) return null;
			try {
				const ptrHosts = await queryPtrRecords(ip, dnsOptions);
				if (ptrHosts.length === 0) {
					return { status: 'missing', detail: `${host} (${ip}): no PTR record` };
				}
				const ptrHost = ptrHosts[0].replace(/\.$/, '').toLowerCase();
				const forwardIps = await queryDnsRecords(ptrHost, 'A', dnsOptions);
				if (forwardIps.includes(ip)) {
					return { status: 'confirmed', detail: `${host} (${ip}): FCrDNS OK -> ${ptrHost}` };
				}
				return { status: 'mismatched', detail: `${host} (${ip}): PTR ${ptrHost} does not forward-resolve back to ${ip}` };
			} catch (err) {
				firstError ??= err;
				return null;
			}
		});
		if (firstError !== undefined) throw firstError;

		const totalIps = mailHostIps.length;
		let confirmed = 0;
		let mismatched = 0;
		let missing = 0;
		const detailParts: string[] = [];

		for (const outcome of outcomes) {
			/* c8 ignore next -- unreachable: a null outcome implies firstError, which threw above */
			if (!outcome) continue;
			if (outcome.status === 'confirmed') confirmed++;
			else if (outcome.status === 'mismatched') mismatched++;
			else missing++;
			detailParts.push(outcome.detail);
		}

		if (totalIps === 0) {
			// Genuine resolution failure: mail hosts EXIST (mxHosts is non-empty by the
			// guard above) but none of them resolved to an A record, so FCrDNS could not
			// be evaluated. Distinct from the not-applicable fork above.
			return buildCheckResult('ptr', [
				createFinding(
					'ptr',
					'Mail server IPs unresolved',
					'info',
					`Could not resolve A records for ${mxHosts.length} mail server host(s) (${mxHosts.join(', ')}); reverse DNS could not be evaluated.`,
					{ controlPresent: false, mailHostCount: mxHosts.length },
				),
			]);
		}

		const detail = detailParts.join('; ');

		if (confirmed === totalIps) {
			return buildCheckResult(
				'ptr',
				[
					createFinding(
						'ptr',
						'Forward-confirmed reverse DNS present',
						'info',
						`All ${totalIps} mail-server IP(s) have forward-confirmed reverse DNS (PTR). ${detail}`,
						{ confirmed, totalIps },
					),
				],
				true,
			);
		}

		const findings = [] as ReturnType<typeof createFinding>[];
		if (mismatched > 0) {
			findings.push(
				createFinding(
					'ptr',
					'Reverse DNS (PTR) misconfigured',
					'low',
					`${mismatched} of ${totalIps} mail-server IP(s) have a PTR record that fails forward-confirmation. ${detail}`,
					{ confirmed, mismatched, missing, totalIps },
				),
			);
		}
		if (confirmed === 0 && mismatched === 0) {
			// PTR absent entirely — bonus simply not earned, no penalty.
			findings.push(
				createFinding(
					'ptr',
					'No reverse DNS (PTR) for mail servers',
					'info',
					`None of the ${totalIps} mail-server IP(s) have a PTR record. ${detail}`,
					{ missing, totalIps, controlPresent: false },
				),
			);
		} else if (confirmed > 0 && mismatched === 0) {
			// Partial coverage: some IPs confirmed, others missing.
			findings.push(
				createFinding(
					'ptr',
					'Partial reverse DNS (PTR) coverage',
					'low',
					`${confirmed} of ${totalIps} mail-server IP(s) have forward-confirmed reverse DNS; the rest are missing. ${detail}`,
					{ confirmed, missing, totalIps },
				),
			);
		}

		return buildCheckResult('ptr', findings, confirmed > 0);
	} catch (err) {
		// Transient top-level DNS failure → structured transient-error result (see
		// buildDnsErrorResult). The `checkStatus: 'error'` shape lets scan_domain's
		// transient-zero retry fire; PTR is Hardening/bonus-only so this never penalizes.
		return buildDnsErrorResult('ptr', 'PTR', err);
	}
}
