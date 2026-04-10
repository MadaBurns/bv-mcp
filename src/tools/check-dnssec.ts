// SPDX-License-Identifier: BUSL-1.1

/**
 * DNSSEC (DNS Security Extensions) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkDNSSEC } from '@blackveil/dns-checks';
import { DnsQueryError, queryDns, queryDnsRecords } from '../lib/dns';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult } from '../lib/scoring';

export { parseDnskeyAlgorithm, parseDsRecord } from '@blackveil/dns-checks';

const GOOGLE_DOH_ENDPOINT = 'https://dns.google/resolve';
const AD_CONFIRM_TIMEOUT_MS = 3000;

/**
 * Confirm the AD (Authenticated Data) flag via Google DoH.
 * Sends a single A-record query with CD=0 and returns whether AD is set.
 * Returns false on any error — callers should treat failure as "not confirmed".
 */
async function confirmAdWithGoogle(domain: string, timeoutMs = AD_CONFIRM_TIMEOUT_MS): Promise<boolean> {
	try {
		const url = `${GOOGLE_DOH_ENDPOINT}?name=${encodeURIComponent(domain)}&type=A&cd=0`;
		const resp = await fetch(url, {
			method: 'GET',
			redirect: 'manual',
			headers: { Accept: 'application/dns-json' },
			signal: AbortSignal.timeout(timeoutMs),
		});
		if (!resp.ok) return false;
		const data = (await resp.json()) as { AD?: boolean };
		return data.AD === true;
	} catch {
		return false;
	}
}

/**
 * Augment a DNSSEC check result with dnssecSource metadata.
 * Queries DNSKEY/DS records to determine whether DNSSEC is domain-configured or TLD-inherited.
 */
async function augmentWithSource(domain: string, baseResult: CheckResult, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const [dnskeyResult, dsResult] = await Promise.allSettled([
		queryDnsRecords(domain, 'DNSKEY', dnsOptions),
		queryDnsRecords(domain, 'DS', dnsOptions),
	]);

	const hasDnskey = dnskeyResult.status === 'fulfilled' && dnskeyResult.value.length > 0;
	const hasDs = dsResult.status === 'fulfilled' && dsResult.value.length > 0;
	const dnssecSource = hasDnskey && hasDs ? 'domain_configured' : 'tld_inherited';

	if (dnssecSource === 'tld_inherited') {
		const inheritedFinding = createFinding(
			'dnssec',
			'DNSSEC inherited from TLD',
			'info',
			`DNSSEC validation passes but ${domain} does not have its own DNSKEY or DS records. DNSSEC protection is inherited from the TLD registry, not configured by the domain owner.`,
			{ dnssecSource: 'tld_inherited' },
		);
		return buildCheckResult('dnssec', [...baseResult.findings, inheritedFinding]);
	}

	// domain_configured — tag the first non-info finding with the source, or add a carrier finding
	if (baseResult.findings.length > 0) {
		const [first, ...rest] = baseResult.findings;
		const tagged = { ...first, metadata: { ...(first.metadata ?? {}), dnssecSource: 'domain_configured' } };
		return buildCheckResult('dnssec', [tagged, ...rest]);
	}

	const configuredFinding = createFinding(
		'dnssec',
		'DNSSEC configured by domain owner',
		'info',
		`${domain} has DNSKEY and DS records — DNSSEC is explicitly configured by the domain owner.`,
		{ dnssecSource: 'domain_configured' },
	);
	return buildCheckResult('dnssec', [configuredFinding]);
}

/**
 * Check DNSSEC configuration for a domain.
 * Verifies the AD (Authenticated Data) flag, checks for DNSKEY/DS records,
 * and audits algorithm and digest type security.
 * Augments results with dnssecSource metadata: 'domain_configured' or 'tld_inherited'.
 *
 * When the primary resolver reports AD=false but DNSKEY+DS records exist ("validation failing"),
 * fires a confirmation probe to Google DoH. If Google says AD=true (edge flap), re-runs the
 * check with the corrected flag to avoid score instability.
 */
export async function checkDnssec(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	try {
	const baseResult = await checkDNSSEC(
		domain,
		makeQueryDNS(dnsOptions),
		{
			timeout: dnsOptions?.timeoutMs ?? 5000,
			rawQueryDNS: async (d, type, dnssecFlag) => {
				const resp = await queryDns(d, type as Parameters<typeof queryDns>[1], dnssecFlag ?? false, dnsOptions);
				return { AD: resp.AD, Answer: resp.Answer };
			},
		},
	) as CheckResult;

	// Skip augmentation when DNSSEC is definitively absent, failed, or misconfigured at the domain level.
	// 'DNSSEC chain of trust incomplete' means the domain has DNSKEY but no DS — it is domain-operator-configured
	// (just broken), not TLD-inherited.
	const dnssecAbsent =
		baseResult.findings.some((f) => f.title === 'DNSSEC not enabled') ||
		baseResult.findings.some((f) => f.title === 'DNSSEC check failed') ||
		baseResult.findings.some((f) => f.title === 'DNSSEC chain of trust incomplete');
	if (dnssecAbsent) {
		return baseResult;
	}

	// AD flag confirmation probe: when the primary resolver reports "DNSSEC validation failing"
	// (AD=false but DNSKEY+DS exist), confirm with Google DoH before trusting the verdict.
	// The AD flag flaps across Cloudflare edge nodes — Google provides a stable second opinion.
	const validationFailing = baseResult.findings.some((f) => f.title === 'DNSSEC validation failing');
	if (validationFailing) {
		const googleConfirmsAd = await confirmAdWithGoogle(domain, dnsOptions?.timeoutMs ?? AD_CONFIRM_TIMEOUT_MS);
		if (googleConfirmsAd) {
			// Google says AD=true — re-run with corrected flag to get the right findings
			const correctedResult = await checkDNSSEC(
				domain,
				makeQueryDNS(dnsOptions),
				{
					timeout: dnsOptions?.timeoutMs ?? 5000,
					rawQueryDNS: async (d, type, dnssecFlag) => {
						const resp = await queryDns(d, type as Parameters<typeof queryDns>[1], dnssecFlag ?? false, dnsOptions);
						return { AD: true, Answer: resp.Answer };
					},
				},
			) as CheckResult;
			return augmentWithSource(domain, correctedResult, dnsOptions);
		}
		// Google also says AD=false (or failed) — keep the original finding
		return baseResult;
	}

	return augmentWithSource(domain, baseResult, dnsOptions);
	} catch (err) {
		if (err instanceof DnsQueryError) {
			return buildCheckResult('dnssec', [
				createFinding(
					'dnssec',
					'DNSSEC check could not complete',
					'info',
					`Unable to verify DNSSEC for ${domain} — DNS query failed: ${err.message}`,
					{ checkStatus: 'error' },
				),
			]);
		}
		throw err;
	}
}
