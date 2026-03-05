/**
 * SPF (Sender Policy Framework) check tool.
 * Queries TXT records for SPF and validates the policy.
 * Implements recursive include expansion per RFC 7208 §4.6.4.
 */

import { queryTxtRecords } from '../lib/dns';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';

/** Known risky SPF mechanisms that allow broad sending */
const RISKY_MECHANISMS = ['+all', '?all'];

/** Maximum recursion depth for SPF include expansion */
const MAX_RECURSION_DEPTH = 10;

/** Maximum total DNS queries during recursive expansion */
const MAX_RECURSIVE_QUERIES = 10;

type SpfLookupAnalysis = {
	count: number;
	mechanisms: string[];
};

/**
 * Count SPF mechanisms that consume DNS lookups in a single record (non-recursive).
 * RFC 7208 limits evaluation to 10 DNS-mechanism lookups.
 */
function analyzeSpfLookupBudget(spfRecord: string): SpfLookupAnalysis {
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
 * Used by scan-domain.ts for provider inference — do not change the return shape.
 */
function extractSpfSignalDomains(spfRecord: string): { includeDomains: string[]; redirectDomain?: string } {
	const includeDomains = Array.from(spfRecord.matchAll(/\binclude:([^\s]+)/gi))
		.map((m) => m[1].trim().toLowerCase())
		.filter((d) => d.length > 0);

	const redirectMatch = spfRecord.match(/\bredirect=([^\s]+)/i);
	const redirectDomain = redirectMatch?.[1]?.trim().toLowerCase();

	return {
		includeDomains,
		...(redirectDomain ? { redirectDomain } : {}),
	};
}

/** State tracking for recursive SPF expansion */
type RecursiveState = {
	totalQueries: number;
	visited: Set<string>;
	cache: Map<string, SpfLookupAnalysis>;
	findings: Finding[];
	circularDetected: boolean;
};

/**
 * Extract domains referenced by include: and redirect= mechanisms.
 */
function extractLookupDomains(spfRecord: string): { includes: string[]; redirect?: string } {
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
 * Respects query budget of MAX_RECURSIVE_QUERIES.
 */
async function countRecursiveLookups(
	spfRecord: string,
	currentDomain: string,
	depth: number,
	state: RecursiveState,
): Promise<number> {
	// Count local mechanisms that generate lookups
	const local = analyzeSpfLookupBudget(spfRecord);
	let totalCount = local.count;

	if (depth >= MAX_RECURSION_DEPTH) {
		return totalCount;
	}

	// Extract domains we need to recurse into
	const { includes, redirect } = extractLookupDomains(spfRecord);
	const domainsToResolve = [...includes];
	if (redirect) domainsToResolve.push(redirect);

	for (const targetDomain of domainsToResolve) {
		// Check circular
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

		// Check cached results
		if (state.cache.has(targetDomain)) {
			const cached = state.cache.get(targetDomain)!;
			totalCount += cached.count;
			continue;
		}

		// Check query budget
		if (state.totalQueries >= MAX_RECURSIVE_QUERIES) {
			break;
		}

		state.visited.add(targetDomain);
		state.totalQueries++;

		try {
			const txtRecords = await queryTxtRecords(targetDomain);
			const nestedSpf = txtRecords.find((r) => r.toLowerCase().startsWith('v=spf1'));

			if (nestedSpf) {
				const nestedCount = await countRecursiveLookups(nestedSpf, targetDomain, depth + 1, state);
				// Cache the nested count (subtract the local count of the nested record since
				// we want the total recursive count from this domain downward)
				state.cache.set(targetDomain, { count: nestedCount, mechanisms: [] });
				totalCount += nestedCount;
			}
		} catch {
			// DNS query failed for nested domain — note but don't crash
			// The local count already includes this mechanism, so no adjustment needed
		}

		state.visited.delete(targetDomain);
	}

	return totalCount;
}

/**
 * Check for overly broad IP ranges in SPF record.
 * Returns findings for ip4 prefixes <= /8 and ip6 prefixes <= /16.
 */
function checkBroadIpRanges(spfRecord: string, metadata: Record<string, unknown>): Finding[] {
	const findings: Finding[] = [];

	for (const token of spfRecord.split(/\s+/)) {
		if (!token) continue;
		const normalized = token.replace(/^[+\-~?]/, '').toLowerCase();

		// Check IPv4 ranges
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

		// Check IPv6 ranges
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

/**
 * Check SPF records for a domain.
 * Looks for v=spf1 TXT records and validates their configuration.
 * Recursively expands include chains to compute true DNS lookup count.
 */
export async function checkSpf(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];
	const txtRecords = await queryTxtRecords(domain);

	// Filter for SPF records
	const spfRecords = txtRecords.filter((r) => r.toLowerCase().startsWith('v=spf1'));

	if (spfRecords.length === 0) {
		findings.push(
			createFinding(
				'spf',
				'No SPF record found',
				'critical',
				`No SPF (v=spf1) TXT record found for ${domain}. Without SPF, any server can send email claiming to be from your domain.`,
			),
		);
		return buildCheckResult('spf', findings);
	}

	if (spfRecords.length > 1) {
		findings.push(
			createFinding(
				'spf',
				'Multiple SPF records',
				'high',
				`Found ${spfRecords.length} SPF records. RFC 7208 requires exactly one SPF record per domain. Multiple records cause unpredictable behavior.`,
			),
		);
	}

	const spf = spfRecords[0];
	const spfSignals = extractSpfSignalDomains(spf);
	const spfMetadata = {
		signalType: 'spf',
		includeDomains: spfSignals.includeDomains,
		...(spfSignals.redirectDomain ? { redirectDomain: spfSignals.redirectDomain } : {}),
	};

	// Check for redirect= — determines whether missing 'all' is an issue
	const hasRedirect = /\bredirect=/i.test(spf);

	// Check for overly permissive +all or ?all
	const allMechanism = spf.match(/[+?~-]all/i);
	if (allMechanism) {
		const qualifier = allMechanism[0];
		if (RISKY_MECHANISMS.includes(qualifier.toLowerCase())) {
			findings.push(
				createFinding(
					'spf',
					`Permissive SPF: ${qualifier}`,
					'critical',
					`SPF record uses "${qualifier}" which allows any server to send email as ${domain}. Use "-all" (hard fail) or "~all" (soft fail) instead.`,
					spfMetadata,
				),
			);
		} else if (qualifier.toLowerCase() === '~all') {
			findings.push(
				createFinding(
					'spf',
					'SPF soft fail (~all)',
					'low',
					`SPF record uses "~all" (soft fail). Consider upgrading to "-all" (hard fail) for stricter enforcement once you've verified all legitimate senders are included.`,
					spfMetadata,
				),
			);
		}
		// -all is the recommended setting, no finding needed
	} else if (!hasRedirect) {
		// RFC 7208 §6.1: redirect= replaces the entire record, making 'all' irrelevant
		findings.push(
			createFinding(
				'spf',
				"No 'all' mechanism",
				'medium',
				`SPF record does not end with an "all" mechanism. Without it, the default behavior is neutral, which provides weak protection.`,
				spfMetadata,
			),
		);
	}

	// Check for overly broad IP ranges
	findings.push(...checkBroadIpRanges(spf, spfMetadata));

	// Recursive DNS lookup budget (RFC 7208 §4.6.4)
	const state: RecursiveState = {
		totalQueries: 0,
		visited: new Set([domain]),
		cache: new Map(),
		findings: [],
		circularDetected: false,
	};
	const recursiveLookupCount = await countRecursiveLookups(spf, domain, 0, state);

	// Add any circular-include findings from recursive expansion
	findings.push(...state.findings);

	if (recursiveLookupCount > 10) {
		findings.push(
			createFinding(
				'spf',
				'Too many DNS lookups',
				'critical',
				`SPF record requires ${recursiveLookupCount} DNS lookups (limit: 10). Receivers may return PermError and reject legitimate mail.`,
				{ ...spfMetadata, lookupCount: recursiveLookupCount },
			),
		);
	} else if (recursiveLookupCount >= 9) {
		findings.push(
			createFinding(
				'spf',
				'SPF lookup budget near limit',
				'high',
				`SPF record requires ${recursiveLookupCount}/10 DNS lookups. Any future sender additions may push this domain into permanent SPF failures.`,
				{ ...spfMetadata, lookupCount: recursiveLookupCount },
			),
		);
	}

	// Check for deprecated ptr mechanism
	if (/\bptr\b/i.test(spf)) {
		findings.push(
			createFinding(
				'spf',
				'Deprecated ptr mechanism',
				'medium',
				`SPF record uses the "ptr" mechanism which is deprecated in RFC 7208 due to performance and reliability issues.`,
				spfMetadata,
			),
		);
	}

	// If no issues found, add an info finding
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'spf',
				'SPF record configured',
				'info',
				`SPF record found and properly configured: ${spf.substring(0, 100)}${spf.length > 100 ? '...' : ''}`,
				spfMetadata,
			),
		);
	}

	return buildCheckResult('spf', findings);
}
