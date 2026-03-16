// SPDX-License-Identifier: BUSL-1.1

import type { Finding } from '../lib/scoring';
import { createFinding } from '../lib/scoring';

const RESILIENT_NS_PROVIDERS: Record<string, string> = {
	'cloudflare.com':
		"Cloudflare's anycast network provides built-in geographic redundancy, so this is lower risk than single-provider setups on traditional DNS hosts.",
	'awsdns.com': "AWS Route 53's anycast network provides built-in geographic redundancy, so this is lower risk than single-provider setups on traditional DNS hosts.",
	'google.com':
		'Google Cloud DNS uses globally distributed authoritative infrastructure, so this is lower risk than single-provider setups on traditional DNS hosts.',
};

export type ParsedSoaValues = {
	refresh: number | null;
	retry: number | null;
	expire: number | null;
	minimum: number | null;
};

export function normalizeNsRecords(nsRecords: string[]): string[] {
	return nsRecords.map((record) => record.replace(/\.$/, '').toLowerCase());
}

export function getNsVisibilityFinding(domain: string, domainResolves: boolean): Finding {
	if (domainResolves) {
		return createFinding(
			'ns',
			'NS records not directly visible',
			'low',
			`No NS records returned for ${domain} directly, but the domain resolves. NS records may be managed at a parent zone.`,
		);
	}

	return createFinding(
		'ns',
		'No NS records found',
		'critical',
		`No nameserver records found for ${domain}. Without NS records, the domain cannot resolve.`,
	);
}

export function getSingleNsFinding(nsRecords: string[]): Finding | null {
	if (nsRecords.length !== 1) {
		return null;
	}

	return createFinding(
		'ns',
		'Single nameserver (violates RFC 1035 §2.2)',
		'high',
		`Only one nameserver found (${nsRecords[0]}). RFC 1035 §2.2 mandates at least two nameservers for every zone to ensure redundancy and availability.`,
	);
}

export function getNameserverDiversityFinding(nsRecords: string[]): Finding | null {
	const providerDomains = new Set(
		nsRecords.map((record) => {
			const parts = record.split('.');
			return parts.slice(-2).join('.');
		}),
	);

	if (providerDomains.size !== 1 || nsRecords.length <= 1) {
		return null;
	}

	const providerDomain = [...providerDomains][0];
	const providerContext =
		RESILIENT_NS_PROVIDERS[providerDomain] ?? 'Consider using nameservers from different providers for better resilience.';

	return createFinding(
		'ns',
		'Low nameserver diversity',
		'low',
		`All nameservers are under ${providerDomain}. ${providerContext} For maximum independence, a secondary DNS provider can be added.`,
	);
}

export function parseSoaValues(soaData: string): ParsedSoaValues | null {
	const soaParts = soaData.trim().split(/\s+/);
	if (soaParts.length < 7) {
		return null;
	}

	const refresh = parseInt(soaParts[3], 10);
	const retry = parseInt(soaParts[4], 10);
	const expire = parseInt(soaParts[5], 10);
	const minimum = parseInt(soaParts[6], 10);

	return {
		refresh: Number.isNaN(refresh) ? null : refresh,
		retry: Number.isNaN(retry) ? null : retry,
		expire: Number.isNaN(expire) ? null : expire,
		minimum: Number.isNaN(minimum) ? null : minimum,
	};
}

export function getSoaValidationFindings(soaValues: ParsedSoaValues): Finding[] {
	const findings: Finding[] = [];

	if (soaValues.refresh !== null) {
		if (soaValues.refresh < 300) {
			findings.push(
				createFinding(
					'ns',
					'SOA refresh interval too short',
					'low',
					`SOA refresh interval is ${soaValues.refresh}s (< 300s / 5 min). Very short refresh intervals increase DNS traffic and load on nameservers.`,
				),
			);
		} else if (soaValues.refresh > 86400) {
			findings.push(
				createFinding(
					'ns',
					'SOA refresh interval too long',
					'low',
					`SOA refresh interval is ${soaValues.refresh}s (> 86400s / 1 day). Long refresh intervals delay propagation of zone changes to secondary nameservers.`,
				),
			);
		}
	}

	if (soaValues.retry !== null && soaValues.refresh !== null && soaValues.retry > soaValues.refresh) {
		findings.push(
			createFinding(
				'ns',
				'SOA retry exceeds refresh interval',
				'low',
				`SOA retry interval (${soaValues.retry}s) exceeds refresh interval (${soaValues.refresh}s). Retry should be shorter than refresh to allow timely recovery after failed zone transfers.`,
			),
		);
	}

	if (soaValues.expire !== null && soaValues.expire < 604800) {
		findings.push(
			createFinding(
				'ns',
				'SOA expire too short',
				'medium',
				`SOA expire value is ${soaValues.expire}s (< 604800s / 1 week). If secondary nameservers cannot reach the primary for this duration, they will stop serving the zone.`,
			),
		);
	}

	if (soaValues.minimum !== null && soaValues.minimum > 86400) {
		findings.push(
			createFinding(
				'ns',
				'SOA negative cache TTL too long',
				'low',
				`SOA minimum (negative cache TTL) is ${soaValues.minimum}s (> 86400s / 1 day). This means NXDOMAIN responses will be cached for extended periods, delaying visibility of new records.`,
			),
		);
	}

	return findings;
}

export function getNsConfiguredFinding(nsRecords: string[]): Finding {
	return createFinding('ns', 'Nameservers properly configured', 'info', `${nsRecords.length} nameservers found: ${nsRecords.join(', ')}`);
}