// SPDX-License-Identifier: BUSL-1.1

/**
 * Lookalike domain detection tool.
 * Generates typosquat/lookalike domain permutations and checks for
 * active DNS registrations and mail infrastructure.
 * Standalone check — not included in scan_domain due to query volume.
 */

import { queryDnsRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { generateLookalikes } from './lookalike-analysis';

/** Default and minimum batch sizes for adaptive batching */
export const INITIAL_BATCH_SIZE = 10;
export const MIN_BATCH_SIZE = 3;
export const BACKOFF_DELAY_MS = 500;
export const FAILURE_THRESHOLD = 2;

/** Maximum wall-clock time for the entire lookalike check (ms). */
const LOOKALIKE_TIMEOUT_MS = 20_000;

/** Canary label used for wildcard detection on parent domains */
export const WILDCARD_CANARY_LABEL = '_bv-wc-probe';

/** Lean DNS options for Phase 1 existence checks — fast, no retries, no secondary confirmation. */
export const PHASE1_DNS_OPTS: QueryDnsOptions = {
	timeoutMs: 2000,
	retries: 0,
	skipSecondaryConfirmation: true,
};

interface LookalikeResult {
	domain: string;
	hasA: boolean;
	hasMX: boolean;
}

/** Minimum number of NS records that must overlap to consider domains as sharing nameservers. */
const SHARED_NS_THRESHOLD = 1;

/**
 * Check whether an MX record represents real mail infrastructure.
 * RFC 7505 null MX ("0 .") explicitly means "no mail accepted" and must be excluded.
 */
function isRealMxRecord(data: string): boolean {
	// Null MX: priority 0, exchange "." — RFC 7505
	const trimmed = data.trim();
	return trimmed !== '0 .' && trimmed !== '0\t.';
}

/**
 * Check a single lookalike domain for DNS and MX records.
 * Filters out null MX records (RFC 7505) to avoid false positives.
 */
async function probeLookalike(domain: string): Promise<LookalikeResult> {
	const [aRecords, mxRecords] = await Promise.allSettled([
		queryDnsRecords(domain, 'A'),
		queryDnsRecords(domain, 'MX'),
	]);

	const realMxRecords =
		mxRecords.status === 'fulfilled' ? mxRecords.value.filter(isRealMxRecord) : [];

	return {
		domain,
		hasA: aRecords.status === 'fulfilled' && aRecords.value.length > 0,
		hasMX: realMxRecords.length > 0,
	};
}

/**
 * Count the number of labels (dot-separated segments) in a domain.
 */
function labelCount(domain: string): number {
	return domain.split('.').length;
}

/**
 * Extract the parent domain from a dot-insertion permutation.
 * E.g., "blackve.ilsecurity.com" → "ilsecurity.com"
 */
function getParentDomain(domain: string): string {
	const parts = domain.split('.');
	return parts.slice(1).join('.');
}

/**
 * Detect wildcard DNS on a set of parent domains by probing a canary subdomain.
 * Returns a Set of parent domains that have wildcard A records.
 */
async function detectWildcardParents(parentDomains: string[]): Promise<Set<string>> {
	const wildcardParents = new Set<string>();
	const probes = parentDomains.map(async (parent) => {
		try {
			const canary = `${WILDCARD_CANARY_LABEL}.${parent}`;
			const records = await queryDnsRecords(canary, 'A');
			if (records.length > 0) {
				wildcardParents.add(parent);
			}
		} catch {
			// Query failed — not a wildcard
		}
	});
	await Promise.allSettled(probes);
	return wildcardParents;
}

/**
 * Phase 1: Fast NS existence check for all domains in parallel.
 * Returns only domains that have NS records (i.e., are registered),
 * along with their normalized NS record data for ownership comparison.
 */
async function filterByNsExistence(domains: string[]): Promise<{ registered: string[]; nsMap: Map<string, Set<string>> }> {
	const nsMap = new Map<string, Set<string>>();
	const results = await Promise.allSettled(
		domains.map(async (domain) => {
			const ns = await queryDnsRecords(domain, 'NS', PHASE1_DNS_OPTS);
			if (ns.length > 0) {
				nsMap.set(domain, normalizeNsSet(ns));
			}
			return { domain, hasNs: ns.length > 0 };
		}),
	);
	const registered = results
		.filter(
			(r): r is PromiseFulfilledResult<{ domain: string; hasNs: boolean }> =>
				r.status === 'fulfilled' && r.value.hasNs,
		)
		.map((r) => r.value.domain);
	return { registered, nsMap };
}

/**
 * Normalize a set of NS record values for comparison.
 * Strips trailing dots, lowercases, and returns a Set.
 */
function normalizeNsSet(nsRecords: string[]): Set<string> {
	return new Set(nsRecords.map((ns) => ns.replace(/\.$/, '').toLowerCase()));
}

/**
 * Check whether two NS sets share at least SHARED_NS_THRESHOLD nameservers.
 * Shared nameservers are a strong signal that both domains are controlled by the same entity.
 */
function sharesNameservers(primaryNs: Set<string>, lookalikeNs: Set<string>): boolean {
	let overlap = 0;
	for (const ns of lookalikeNs) {
		if (primaryNs.has(ns)) {
			overlap++;
			if (overlap >= SHARED_NS_THRESHOLD) return true;
		}
	}
	return false;
}

/**
 * Query NS records for the primary domain to use for ownership comparison.
 * Returns an empty set if the query fails.
 */
async function queryPrimaryNs(domain: string): Promise<Set<string>> {
	try {
		const ns = await queryDnsRecords(domain, 'NS', PHASE1_DNS_OPTS);
		return normalizeNsSet(ns);
	} catch {
		return new Set<string>();
	}
}

/**
 * Run permutation probes with adaptive batch sizing and backoff.
 * Starts at INITIAL_BATCH_SIZE, halves on repeated failures (floor at MIN_BATCH_SIZE),
 * recovers on clean batches.
 */
async function probeWithAdaptiveBatching(
	permutations: string[],
): Promise<PromiseSettledResult<LookalikeResult>[]> {
	const allResults: PromiseSettledResult<LookalikeResult>[] = [];
	let batchSize = INITIAL_BATCH_SIZE;
	let delayMs = 0;

	for (let i = 0; i < permutations.length; i += batchSize) {
		if (delayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, delayMs));
		}

		const batch = permutations.slice(i, i + batchSize);
		const batchResults = await Promise.allSettled(batch.map((d) => probeLookalike(d)));
		allResults.push(...batchResults);

		// Count failures in this batch
		const failures = batchResults.filter((r) => r.status === 'rejected').length;
		if (failures > FAILURE_THRESHOLD) {
			// Back off: halve batch size (floor to MIN_BATCH_SIZE) and add delay
			batchSize = Math.max(MIN_BATCH_SIZE, Math.floor(batchSize / 2));
			delayMs = BACKOFF_DELAY_MS;
		} else if (delayMs > 0 && failures === 0) {
			// Recover: if a clean batch after backoff, try increasing again
			batchSize = Math.min(INITIAL_BATCH_SIZE, batchSize + 2);
			delayMs = 0;
		}
	}

	return allResults;
}

/**
 * Detect registered lookalike/typosquat domains with DNS or mail infrastructure.
 * Generates domain permutations and checks for active registrations using adaptive batching.
 * Filters out false positives from wildcard DNS on parent domains and null MX records.
 */
export async function checkLookalikes(domain: string): Promise<CheckResult> {
	return Promise.race([
		checkLookalikesCore(domain),
		new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Lookalike check timed out')), LOOKALIKE_TIMEOUT_MS)),
	]).catch(() => {
		const result = buildCheckResult('lookalikes', [
			createFinding(
				'lookalikes',
				'Lookalike check incomplete',
				'info',
				'Lookalike check did not complete within the time limit. Results may be incomplete — try again shortly.',
			),
		]);
		// Mark as partial so callers can skip caching
		result.partial = true;
		return result;
	});
}

async function checkLookalikesCore(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];
	const permutations = generateLookalikes(domain);

	if (permutations.length === 0) {
		findings.push(
			createFinding(
				'lookalikes',
				'No active lookalike domains detected',
				'info',
				`No lookalike domain permutations could be generated for ${domain}.`,
			),
		);
		return buildCheckResult('lookalikes', findings);
	}

	// Identify dot-insertion permutations (they have more labels than the original domain)
	const originalLabelCount = labelCount(domain);
	const dotInsertionParents = new Map<string, string[]>(); // parent → [permutations]
	const nonDotInsertionPerms: string[] = [];

	for (const perm of permutations) {
		if (labelCount(perm) > originalLabelCount) {
			const parent = getParentDomain(perm);
			const existing = dotInsertionParents.get(parent);
			if (existing) {
				existing.push(perm);
			} else {
				dotInsertionParents.set(parent, [perm]);
			}
		} else {
			nonDotInsertionPerms.push(perm);
		}
	}

	// Detect wildcard DNS on parent domains of dot-insertion permutations
	const wildcardParents = dotInsertionParents.size > 0
		? await detectWildcardParents([...dotInsertionParents.keys()])
		: new Set<string>();

	// Filter out permutations whose parent has wildcard DNS
	const filteredDotInsertionPerms: string[] = [];
	for (const [parent, perms] of dotInsertionParents) {
		if (!wildcardParents.has(parent)) {
			filteredDotInsertionPerms.push(...perms);
		}
	}

	const permsToProbe = [...nonDotInsertionPerms, ...filteredDotInsertionPerms];

	// Phase 1: Fast NS existence check — filter out unregistered domains
	// Also query the primary domain's NS for ownership comparison
	const [nsResult, primaryNs] = await Promise.all([
		filterByNsExistence(permsToProbe),
		queryPrimaryNs(domain),
	]);
	const { registered: registeredPerms, nsMap: lookalikeNsMap } = nsResult;

	if (registeredPerms.length === 0) {
		findings.push(
			createFinding(
				'lookalikes',
				'No active lookalike domains detected',
				'info',
				`Checked ${permutations.length} domain permutations of ${domain}. No active registrations detected.`,
			),
		);
		return buildCheckResult('lookalikes', findings);
	}

	// Phase 2: Detail probe only registered domains
	const probeResults = await probeWithAdaptiveBatching(registeredPerms);
	const results: LookalikeResult[] = [];
	for (const result of probeResults) {
		if (result.status === 'fulfilled') {
			results.push(result.value);
		}
	}

	// Classify results — check for shared nameservers with primary domain to detect defensive registrations
	let highCount = 0;
	for (const result of results) {
		const lookalikeNs = lookalikeNsMap.get(result.domain);
		const sameOwner = primaryNs.size > 0 && lookalikeNs !== undefined && sharesNameservers(primaryNs, lookalikeNs);

		if (sameOwner) {
			// Shared nameservers — likely a defensive registration by the same entity
			findings.push(
				createFinding(
					'lookalikes',
					`Lookalike domain likely owned by same entity: ${result.domain}`,
					'info',
					`The domain ${result.domain} shares nameservers with ${domain}, indicating it is likely a defensive registration by the same owner.${result.hasMX ? ' Has active mail infrastructure.' : ''}${result.hasA ? ' Has web presence.' : ''}`,
					{ lookalikeDomain: result.domain, hasA: result.hasA, hasMX: result.hasMX, sharedNs: true },
				),
			);
		} else if (result.hasMX) {
			highCount++;
			findings.push(
				createFinding(
					'lookalikes',
					`Lookalike domain with mail infrastructure: ${result.domain}`,
					'high',
					`The domain ${result.domain} is registered with active mail servers (MX records), which could be used for phishing or email spoofing targeting ${domain}.`,
					{ lookalikeDomain: result.domain, hasA: result.hasA, hasMX: result.hasMX },
				),
			);
		} else if (result.hasA) {
			findings.push(
				createFinding(
					'lookalikes',
					`Lookalike domain registered: ${result.domain}`,
					'medium',
					`The domain ${result.domain} is registered (has web presence) but no mail infrastructure detected. It could still be used for phishing websites targeting ${domain}.`,
					{ lookalikeDomain: result.domain, hasA: result.hasA, hasMX: result.hasMX },
				),
			);
		}
	}

	// Summary finding for high-severity lookalikes
	if (highCount > 0) {
		findings.push(
			createFinding(
				'lookalikes',
				`${highCount} lookalike domain${highCount > 1 ? 's' : ''} with mail capability detected`,
				'high',
				`${highCount} lookalike domain${highCount > 1 ? 's' : ''} of ${domain} ${highCount > 1 ? 'have' : 'has'} active mail infrastructure, presenting a phishing risk. Consider monitoring these domains and implementing DMARC with p=reject to protect your brand.`,
				{ lookalikeDomainCount: highCount },
			),
		);
	}

	// If no active lookalikes found
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'lookalikes',
				'No active lookalike domains detected',
				'info',
				`Checked ${permutations.length} domain permutations of ${domain}. No active registrations with DNS or mail infrastructure detected.`,
			),
		);
	}

	return buildCheckResult('lookalikes', findings);
}
