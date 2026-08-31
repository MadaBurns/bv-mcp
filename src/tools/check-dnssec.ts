// SPDX-License-Identifier: BUSL-1.1

/**
 * DNSSEC (DNS Security Extensions) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkDNSSEC } from '@blackveil/dns-checks';
import type { ZoneContext } from '@blackveil/dns-checks';
import { queryDns, DnsQueryError } from '../lib/dns';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import { resolveZoneApex } from '../lib/zone-apex';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult } from '../lib/scoring';
import { readJsonResponseCapped } from '../lib/response-body';

export { parseDnskeyAlgorithm, parseDsRecord } from '@blackveil/dns-checks';

const GOOGLE_DOH_ENDPOINT = 'https://dns.google/resolve';
const AD_CONFIRM_TIMEOUT_MS = 3000;
const DOH_MAX_BODY_BYTES = 512 * 1024;

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
		if (!resp.ok) {
			void resp.body?.cancel().catch(() => undefined);
			return false;
		}
		const data = await readJsonResponseCapped<{ AD?: boolean }>(resp, DOH_MAX_BODY_BYTES);
		return data?.AD === true;
	} catch {
		return false;
	}
}

/**
 * Augment a validated DNSSEC result with source metadata.
 *
 * The shared check's structured presence flags are the source of truth: after #793,
 * `controlPresent: true` requires AD + DNSKEY + DS. Re-querying those records here
 * duplicated network work and could mislabel a transient/partial second observation as
 * TLD-inherited, so source attribution is derived from the completed check instead.
 */

function augmentWithSource(domain: string, baseResult: CheckResult): CheckResult {
	if (baseResult.controlPresent !== true || baseResult.recordPresent !== true) return baseResult;

	// Never tag the non-apex attribution note: that finding describes
	// the scanned label's inheritance relationship, while this metadata describes the
	// evaluated zone apex. Tag the first actual DNSSEC verdict/audit finding instead.
	const sourceCarrierIndex = baseResult.findings.findIndex((finding) => finding.title !== 'DNSSEC posture inherited from zone apex');
	if (sourceCarrierIndex >= 0) {
		const findings = baseResult.findings.map((finding, index) =>
			index === sourceCarrierIndex ? { ...finding, metadata: { ...(finding.metadata ?? {}), dnssecSource: 'domain_configured' } } : finding,
		);
		return buildCheckResult('dnssec', findings, baseResult.controlPresent, baseResult.recordPresent);
	}

	const configuredFinding = createFinding(
		'dnssec',
		'DNSSEC configured by domain owner',
		'info',
		`${domain} has DNSKEY and DS records — DNSSEC is explicitly configured by the domain owner.`,
		{ dnssecSource: 'domain_configured' },
	);
	return buildCheckResult('dnssec', [configuredFinding], baseResult.controlPresent, baseResult.recordPresent);
}

/**
 * Check DNSSEC configuration for a domain.
 * Verifies the AD (Authenticated Data) flag, checks for DNSKEY/DS records,
 * and audits algorithm and digest type security.
 * Augments validated results with `dnssecSource: 'domain_configured'` metadata.
 *
 * When the primary resolver reports AD=false but DNSKEY+DS records exist ("validation failing"),
 * fires a confirmation probe to Google DoH. If Google says AD=true (edge flap), re-runs the
 * check with the corrected flag to avoid score instability.
 */
export async function checkDnssec(domain: string, dnsOptions?: QueryDnsOptions, zone?: ZoneContext): Promise<CheckResult> {
	const resolvedZone = zone ?? (await resolveZoneApex(domain, dnsOptions));
	// A non-apex label with no zone of its own inherits DNSSEC posture from its
	// signed zone apex — thread the same target into the source-labelling
	// (augmentWithSource) and AD-confirmation (confirmAdWithGoogle) helpers so
	// they operate on the apex, not the empty subdomain. Apex targets (or an
	// unresolved zone) are unaffected: dnssecTarget === domain.
	const dnssecTarget =
		resolvedZone && !resolvedZone.isApex && resolvedZone.delegationStatus === 'inherited' ? resolvedZone.zoneApex : domain;
	try {
		const baseResult = (await checkDNSSEC(domain, makeQueryDNS(dnsOptions), {
			timeout: dnsOptions?.timeoutMs ?? 5000,
			zone: resolvedZone,
			rawQueryDNS: async (d, type, dnssecFlag) => {
				const resp = await queryDns(d, type as Parameters<typeof queryDns>[1], dnssecFlag ?? false, dnsOptions);
				return { AD: resp.AD, Answer: resp.Answer };
			},
		})) as CheckResult;

		// checkDNSSEC marks a transient transport failure as inconclusive (checkStatus:'error' + an
		// info "DNSSEC not assessed" finding) rather than throwing — propagate that so a transient DNS
		// failure is excluded from scoring, not misread as "no DNSSEC deployed".
		if (baseResult.checkStatus === 'error') {
			return baseResult;
		}

		// Skip augmentation when DNSSEC is definitively absent, failed, or misconfigured at the domain level.
		// 'DNSSEC island of trust' means the domain has DNSKEY but no parent DS — it is
		// domain-operator-configured but not anchored, rather than TLD-inherited.
		// (A transient transport failure already returned above via checkStatus:'error'.)
		const dnssecAbsent =
			baseResult.findings.some((f) => f.title === 'DNSSEC not enabled') ||
			baseResult.findings.some((f) => f.title === 'DNSSEC island of trust');
		if (dnssecAbsent) {
			return baseResult;
		}

		// AD flag confirmation probe: when the primary resolver reports "DNSSEC validation failing"
		// (AD=false but DNSKEY+DS exist), confirm with Google DoH before trusting the verdict.
		// The AD flag flaps across Cloudflare edge nodes — Google provides a stable second opinion.
		const validationFailing = baseResult.findings.some((f) => f.title === 'DNSSEC validation failing');
		if (validationFailing) {
			const googleConfirmsAd = await confirmAdWithGoogle(dnssecTarget, dnsOptions?.timeoutMs ?? AD_CONFIRM_TIMEOUT_MS);
			if (googleConfirmsAd) {
				// Google says AD=true — re-run with corrected flag to get the right findings
				const correctedResult = (await checkDNSSEC(domain, makeQueryDNS(dnsOptions), {
					timeout: dnsOptions?.timeoutMs ?? 5000,
					zone: resolvedZone,
					rawQueryDNS: async (d, type, dnssecFlag) => {
						const resp = await queryDns(d, type as Parameters<typeof queryDns>[1], dnssecFlag ?? false, dnsOptions);
						return { AD: true, Answer: resp.Answer };
					},
				})) as CheckResult;
				return augmentWithSource(dnssecTarget, correctedResult);
			}
			// Google also says AD=false (or failed) — keep the original finding
			return baseResult;
		}

		return augmentWithSource(dnssecTarget, baseResult);
	} catch (err) {
		if (err instanceof DnsQueryError) {
			const message = err.message;
			return {
				...buildCheckResult('dnssec', [
					createFinding('dnssec', 'DNSSEC check could not complete', 'info', `DNS query failed (${message}). DNSSEC posture unknown.`, {
						dnsError: message,
						checkStatus: 'error',
					}),
				]),
				checkStatus: 'error' as const,
			};
		}
		throw err;
	}
}
