// SPDX-License-Identifier: BUSL-1.1

/**
 * PTR / forward-confirmed reverse DNS (FCrDNS) check for a domain's mail servers.
 *
 * For each MX host, resolves its A records, performs a PTR lookup on each IP, then
 * forward-confirms: the PTR hostname's A records must contain the original IP (canonical
 * FCrDNS). Hardening-tier, bonus-only — absence never penalizes (`info`); a present but
 * unconfirmed PTR is `low`. Mirrors `check-mx`'s provider-options signature so managed
 * mail (Google/M365) is credited rather than flagged.
 */

import { buildCheckResult, createFinding, type CheckResult } from '../lib/scoring';
import { queryDnsRecords, queryMxRecords, queryPtrRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { detectProviderMatches, loadProviderSignatures } from '../lib/provider-signatures';

export interface CheckPtrOptions {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
}

export async function checkPtr(domain: string, options?: CheckPtrOptions, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	try {
		const mx = await queryMxRecords(domain, dnsOptions);
		if (mx.length === 0) {
			return buildCheckResult('ptr', [
				createFinding(
					'ptr',
					'PTR not applicable',
					'info',
					'No MX records found; reverse DNS (PTR) for mail servers is not applicable to this non-sending domain.',
					{ controlPresent: false },
				),
			]);
		}

		const mxHosts = mx.map((r) => r.exchange.replace(/\.$/, '').toLowerCase()).filter(Boolean);

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

		let totalIps = 0;
		let confirmed = 0;
		let mismatched = 0;
		let missing = 0;
		const detailParts: string[] = [];

		for (const host of mxHosts) {
			const ips = await queryDnsRecords(host, 'A', dnsOptions);
			for (const ip of ips) {
				totalIps++;
				const ptrHosts = await queryPtrRecords(ip, dnsOptions);
				if (ptrHosts.length === 0) {
					missing++;
					detailParts.push(`${host} (${ip}): no PTR record`);
					continue;
				}
				const ptrHost = ptrHosts[0].replace(/\.$/, '').toLowerCase();
				const forwardIps = await queryDnsRecords(ptrHost, 'A', dnsOptions);
				if (forwardIps.includes(ip)) {
					confirmed++;
					detailParts.push(`${host} (${ip}): FCrDNS OK -> ${ptrHost}`);
				} else {
					mismatched++;
					detailParts.push(`${host} (${ip}): PTR ${ptrHost} does not forward-resolve back to ${ip}`);
				}
			}
		}

		if (totalIps === 0) {
			return buildCheckResult('ptr', [
				createFinding(
					'ptr',
					'Mail server IPs unresolved',
					'info',
					`Could not resolve A records for ${mxHosts.length} mail server host(s); reverse DNS could not be evaluated.`,
					{ controlPresent: false },
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
		const message = err instanceof Error ? err.message : String(err);
		const isTimeout = /timed? out|timeout/i.test(message);
		return buildCheckResult('ptr', [
			createFinding(
				'ptr',
				isTimeout ? 'PTR check timed out' : 'PTR check could not complete',
				'high',
				isTimeout
					? `DNS lookup timed out before reverse DNS (PTR) could be resolved: ${message}`
					: `DNS lookup failed before reverse DNS (PTR) could be resolved: ${message}`,
				{ errorKind: isTimeout ? 'timeout' : 'dns_error', confidence: 'heuristic', missingControl: true },
			),
		]);
	}
}
