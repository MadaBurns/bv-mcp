// SPDX-License-Identifier: MIT

import { queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { Finding } from '../lib/scoring';
import { createFinding } from '../lib/scoring';

/** Known risky SPF mechanisms that allow broad sending. */
export const RISKY_MECHANISMS = ['+all', '?all'];

/** Maximum recursion depth for SPF include expansion. */
export const MAX_RECURSION_DEPTH = 10;

/** Maximum total DNS queries during recursive expansion. */
export const MAX_RECURSIVE_QUERIES = 10;

export type SpfLookupAnalysis = {
	count: number;
	mechanisms: string[];
};

export type RecursiveState = {
	totalQueries: number;
	visited: Set<string>;
	cache: Map<string, SpfLookupAnalysis>;
	findings: Finding[];
	circularDetected: boolean;
};

/**
 * Count SPF mechanisms that consume DNS lookups in a single record (non-recursive).
 * RFC 7208 limits evaluation to 10 DNS-mechanism lookups.
 */
export function analyzeSpfLookupBudget(spfRecord: string): SpfLookupAnalysis {
	const mechanisms: string[] = [];
	for (const token of spfRecord.split(/\s+/)) {
		if (!token) continue;
		const normalized = token.replace(/^[+\-~?]/, '').toLowerCase();
		if (normalized.startsWith('include:')) mechanisms.push('include');
		else if (normalized === 'a' || normalized.startsWith('a:') || normalized.startsWith('a/')) mechanisms.push('a');
		else if (normalized === 'mx' || normalized.startsWith('mx:') || normalized.startsWith('mx/')) mechanisms.push('mx');
		else if (normalized === 'ptr' || normalized.startsWith('ptr:')) mechanisms.push('ptr');
		else if (normalized.startsWith('exists:')) mechanisms.push('exists');
		else if (normalized.startsWith('redirect=')) mechanisms.push('redirect');
	}

	return { count: mechanisms.length, mechanisms };
}

/**
 * Extract include domains and redirect domain from an SPF record.
 * Used by scan-domain provider inference — do not change the return shape.
 */
export function extractSpfSignalDomains(spfRecord: string): { includeDomains: string[]; redirectDomain?: string } {
	const includeDomains = Array.from(spfRecord.matchAll(/\binclude:([^\s]+)/gi))
		.map((match) => match[1].trim().toLowerCase())
		.filter((domain) => domain.length > 0);

	const redirectMatch = spfRecord.match(/\bredirect=([^\s]+)/i);
	const redirectDomain = redirectMatch?.[1]?.trim().toLowerCase();

	return {
		includeDomains,
		...(redirectDomain ? { redirectDomain } : {}),
	};
}

/** Extract domains referenced by include: and redirect= mechanisms. */
export function extractLookupDomains(spfRecord: string): { includes: string[]; redirect?: string } {
	const includes: string[] = [];
	let redirect: string | undefined;

	for (const token of spfRecord.split(/\s+/)) {
		if (!token) continue;
		const normalized = token.replace(/^[+\-~?]/, '').toLowerCase();
		if (normalized.startsWith('include:')) {
			const domain = normalized.slice('include:'.length);
			if (domain) includes.push(domain);
		} else if (normalized.startsWith('redirect=')) {
			const domain = normalized.slice('redirect='.length);
			if (domain) redirect = domain;
		}
	}

	return { includes, redirect };
}

/**
 * Recursively count all DNS-lookup-generating mechanisms across SPF include chains.
 * Tracks visited domains to detect circular includes.
 */
export async function countRecursiveLookups(
	spfRecord: string,
	depth: number,
	state: RecursiveState,
	dnsOptions?: QueryDnsOptions,
): Promise<number> {
	const local = analyzeSpfLookupBudget(spfRecord);
	let totalCount = local.count;

	if (depth >= MAX_RECURSION_DEPTH) {
		return totalCount;
	}

	const { includes, redirect } = extractLookupDomains(spfRecord);
	const domainsToResolve = [...includes];
	if (redirect) domainsToResolve.push(redirect);

	for (const targetDomain of domainsToResolve) {
		if (state.visited.has(targetDomain)) {
			if (!state.circularDetected) {
				state.circularDetected = true;
				state.findings.push(
					createFinding(
						'spf',
						'Circular SPF include detected',
						'high',
						`SPF include chain contains a circular reference involving ${targetDomain}. This will cause SPF evaluation to fail.`,
					),
				);
			}
			continue;
		}

		if (state.cache.has(targetDomain)) {
			totalCount += state.cache.get(targetDomain)!.count;
			continue;
		}

		if (state.totalQueries >= MAX_RECURSIVE_QUERIES) {
			break;
		}

		state.visited.add(targetDomain);
		state.totalQueries++;

		try {
			const txtRecords = await queryTxtRecords(targetDomain, dnsOptions);
			const nestedSpf = txtRecords.find((record) => record.toLowerCase().startsWith('v=spf1'));

			if (nestedSpf) {
				const nestedCount = await countRecursiveLookups(nestedSpf, depth + 1, state, dnsOptions);
				state.cache.set(targetDomain, { count: nestedCount, mechanisms: [] });
				totalCount += nestedCount;
			}
		} catch {
			// DNS query failed for nested domain — local mechanism count already includes the lookup.
		}

		state.visited.delete(targetDomain);
	}

	return totalCount;
}

/**
 * Check for overly broad IP ranges in SPF record.
 * Returns findings for ip4 prefixes <= /8 and ip6 prefixes <= /16.
 */
export function checkBroadIpRanges(spfRecord: string, metadata: Record<string, unknown>): Finding[] {
	const findings: Finding[] = [];

	for (const token of spfRecord.split(/\s+/)) {
		if (!token) continue;
		const normalized = token.replace(/^[+\-~?]/, '').toLowerCase();

		const ip4Match = normalized.match(/^ip4:([^/]+)(?:\/(\d+))?$/);
		if (ip4Match) {
			const prefix = ip4Match[2] ? parseInt(ip4Match[2], 10) : 32;
			if (prefix <= 8) {
				findings.push(
					createFinding(
						'spf',
						'Overly broad IP range',
						'high',
						`SPF record contains "${token}" which authorizes an extremely large IP range (/${prefix}). This undermines SPF protection by allowing too many servers to send mail.`,
						metadata,
					),
				);
			}
		}

		const ip6Match = normalized.match(/^ip6:([^/]+)(?:\/(\d+))?$/);
		if (ip6Match) {
			const prefix = ip6Match[2] ? parseInt(ip6Match[2], 10) : 128;
			if (prefix <= 16) {
				findings.push(
					createFinding(
						'spf',
						'Overly broad IPv6 range',
						'high',
						`SPF record contains "${token}" which authorizes an extremely large IPv6 range (/${prefix}). This undermines SPF protection by allowing too many servers to send mail.`,
						metadata,
					),
				);
			}
		}
	}

	return findings;
}