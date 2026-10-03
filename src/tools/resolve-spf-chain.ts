// SPDX-License-Identifier: BUSL-1.1

/**
 * Recursively resolve the full SPF include chain.
 * Counts DNS lookups against the RFC 7208 10-lookup limit,
 * builds a tree, and flags issues.
 */

import type { OutputFormat } from '../handlers/tool-args';
import type { QueryDnsOptions } from '../lib/dns-types';
import { describeRcode } from '@blackveil/dns-checks';
import { queryTxtRecordsWithRcode } from '../lib/dns';
import { sanitizeOutputText } from '../lib/output-sanitize';

export interface SpfNode {
	domain: string;
	record: string | null;
	lookups: number;
	mechanisms: string[];
	children: SpfNode[];
	error?: string;
}

export interface SpfIssue {
	type:
		| 'over_limit'
		| 'at_limit'
		| 'approaching_limit'
		| 'circular_include'
		| 'void_lookup'
		| 'redundant_include'
		| 'lookup_limit_exceeded'
		| 'lookup_inconclusive'
		| 'redirect_ignored';
	severity: 'critical' | 'high' | 'medium' | 'low';
	detail: string;
	/** Set on `lookup_inconclusive`: the probe never concluded, so nothing is claimed about the record. */
	inconclusive?: boolean;
	errorKind?: 'dns_error' | 'transport_error';
}

export interface SpfChainResult {
	domain: string;
	totalLookups: number;
	maxDepth: number;
	limit: number;
	overLimit: boolean;
	tree: SpfNode;
	issues: SpfIssue[];
	/** True when at least one TXT lookup in the chain never concluded (SERVFAIL/REFUSED/transport error). */
	inconclusive?: boolean;
}

/**
 * Mechanisms that cost 1 DNS lookup per RFC 7208 §4.6.4. Mechanisms take an optional
 * qualifier (`+ - ~ ?`, RFC 7208 §4.6.1 / §5); `redirect=` is a modifier and takes none.
 */
const LOOKUP_MECHANISMS = /^([+\-~?]?(include:|a(?:$|[:\/])|mx(?:$|[:\/])|exists:|ptr(?:$|[:\/]))|redirect=)/i;

/** An `all` mechanism, with or without a qualifier. */
const ALL_MECHANISM = /^[+\-~?]?all$/i;

/** RFC 7208 §4.6.4: at most 10 DNS-querying terms; the 11th is a PermError. */
const LOOKUP_LIMIT = 10;

/** Extract the target domain from include:/redirect= directives. */
function extractTarget(mechanism: string): string | null {
	const includeMatch = mechanism.match(/^[+\-~?]?include:(.+)$/i);
	if (includeMatch) return includeMatch[1].trim().toLowerCase();
	const redirectMatch = mechanism.match(/^redirect=(.+)$/i);
	if (redirectMatch) return redirectMatch[1].trim().toLowerCase();
	return null;
}

/** Parse an SPF record into its mechanisms. */
function parseMechanisms(record: string): string[] {
	return record
		.replace(/^v=spf1\s*/i, '')
		.split(/\s+/)
		.filter((m) => m.length > 0);
}

/** Mutable state shared by one chain resolution. */
interface ChainState {
	/** DNS-querying terms evaluated so far across the whole chain (RFC 7208 §4.6.4 counts every evaluation). */
	counted: number;
	/** An include/redirect past the 10th lookup was not expanded. */
	truncated: boolean;
	/** At least one TXT lookup never concluded. */
	inconclusive: boolean;
}

/**
 * Recursively resolve an SPF include chain.
 *
 * `path` holds only the domains on the CURRENT recursion path (a true cycle); `allSeen`
 * counts every evaluation (a domain reached via two paths is redundant, not circular, and
 * RFC 7208 still charges each evaluation against the lookup limit).
 *
 * The node count is bounded by construction: a child is only expanded while
 * `state.counted <= LOOKUP_LIMIT`, so a chain holds at most LOOKUP_LIMIT + 1 nodes.
 */
async function resolveNode(
	domain: string,
	path: Set<string>,
	allSeen: Map<string, number>,
	depth: number,
	issues: SpfIssue[],
	state: ChainState,
	dnsOptions?: QueryDnsOptions,
): Promise<SpfNode> {
	const normalized = domain.toLowerCase();

	// Circular detection: only an ancestor on the current path is a cycle.
	if (path.has(normalized)) {
		issues.push({
			type: 'circular_include',
			severity: 'high',
			detail: `Circular include detected: ${normalized} already visited in this chain.`,
		});
		return { domain: normalized, record: null, lookups: 0, mechanisms: [], children: [], error: 'circular' };
	}

	// Redundant detection: reached before via a different path.
	const seenCount = allSeen.get(normalized) ?? 0;
	if (seenCount > 0) {
		issues.push({
			type: 'redundant_include',
			severity: 'low',
			detail: `${normalized} is included via multiple paths.`,
		});
	}
	allSeen.set(normalized, seenCount + 1);

	// Max depth guard
	if (depth > 10) {
		return { domain: normalized, record: null, lookups: 0, mechanisms: [], children: [], error: 'max depth exceeded' };
	}

	path.add(normalized);
	try {
		let txtRecords: string[];
		try {
			const outcome = await queryTxtRecordsWithRcode(normalized, dnsOptions);
			if (outcome.inconclusive) {
				state.inconclusive = true;
				const reason = `DNS lookup inconclusive (${describeRcode(outcome.rcode)})`;
				issues.push({
					type: 'lookup_inconclusive',
					severity: 'medium',
					detail: `${normalized}: ${reason}. The record was not measured, so no conclusion is drawn about it.`,
					inconclusive: true,
					errorKind: 'dns_error',
				});
				return { domain: normalized, record: null, lookups: 0, mechanisms: [], children: [], error: reason };
			}
			txtRecords = outcome.records;
		} catch {
			state.inconclusive = true;
			issues.push({
				type: 'lookup_inconclusive',
				severity: 'medium',
				detail: `${normalized}: DNS query failed. The record was not measured, so no conclusion is drawn about it.`,
				inconclusive: true,
				errorKind: 'transport_error',
			});
			return { domain: normalized, record: null, lookups: 0, mechanisms: [], children: [], error: 'DNS query failed' };
		}

		const spfRecord = txtRecords.find((r) => r.toLowerCase().startsWith('v=spf1'));
		if (!spfRecord) {
			issues.push({
				type: 'void_lookup',
				severity: 'medium',
				detail: `${normalized} has no SPF record. This include wastes a DNS lookup.`,
			});
			return { domain: normalized, record: null, lookups: 0, mechanisms: [], children: [] };
		}

		const mechanisms = parseMechanisms(spfRecord);
		// RFC 7208 §6.1: redirect is ignored when the record has an `all` mechanism.
		const hasAll = mechanisms.some((m) => ALL_MECHANISM.test(m));

		// Count in evaluation order and resolve include:/redirect= targets while within the limit.
		const children: SpfNode[] = [];
		let ownLookups = 0;
		for (const mech of mechanisms) {
			if (hasAll && /^redirect=/i.test(mech)) {
				issues.push({
					type: 'redirect_ignored',
					severity: 'low',
					detail: `${normalized}: ${mech} is ignored because the record has an "all" mechanism (RFC 7208 §6.1); it is neither followed nor counted.`,
				});
				continue;
			}
			if (!LOOKUP_MECHANISMS.test(mech)) continue;
			ownLookups++;
			state.counted++;
			const target = extractTarget(mech);
			if (!target) continue;
			if (state.counted > LOOKUP_LIMIT) {
				state.truncated = true;
				continue;
			}
			children.push(await resolveNode(target, path, allSeen, depth + 1, issues, state, dnsOptions));
		}

		const childLookups = children.reduce((sum, c) => sum + c.lookups, 0);

		return {
			domain: normalized,
			record: spfRecord,
			lookups: ownLookups + childLookups,
			mechanisms,
			children,
		};
	} finally {
		path.delete(normalized);
	}
}

/** Compute max depth of the tree. */
function computeMaxDepth(node: SpfNode, current: number = 0): number {
	if (node.children.length === 0) return current;
	return Math.max(...node.children.map((c) => computeMaxDepth(c, current + 1)));
}

/**
 * Recursively resolve the full SPF include chain for a domain.
 *
 * @param domain - Validated, sanitized domain
 * @param dnsOptions - DNS query options
 */
export async function resolveSpfChain(domain: string, dnsOptions?: QueryDnsOptions): Promise<SpfChainResult> {
	const issues: SpfIssue[] = [];
	const allSeen = new Map<string, number>();
	const state: ChainState = { counted: 0, truncated: false, inconclusive: false };
	const tree = await resolveNode(domain, new Set(), allSeen, 0, issues, state, dnsOptions);

	const totalLookups = tree.lookups;
	const maxDepth = computeMaxDepth(tree);
	const limit = LOOKUP_LIMIT;
	const overLimit = totalLookups > limit;

	// Add limit-related issues
	if (overLimit) {
		issues.unshift({
			type: 'over_limit',
			severity: 'critical',
			detail: `SPF lookup limit exceeded: ${totalLookups}/${limit}. Emails may fail SPF validation after the 10th lookup.`,
		});
	} else if (totalLookups === limit) {
		// AT the limit, not approaching it. 10/10 is still WITHIN RFC 7208 §4.6.4's allowance
		// (hence `overLimit === false`), but there is zero headroom left, so calling it
		// "approaching_limit" with "0 remaining" understated the state.
		// Severity is aligned with `check_spf`'s "SPF lookup budget near limit" finding,
		// which is `high` at >= 9 lookups (packages/dns-checks/src/checks/check-spf.ts) —
		// the same fact must not carry two different severities across two tools.
		issues.unshift({
			type: 'at_limit',
			severity: 'high',
			detail: `SPF is AT the ${limit}-lookup limit: ${totalLookups}/${limit}. The record still validates, but there is no headroom left — adding any further sender pushes it over the limit and receivers will return PermError.`,
		});
	} else if (totalLookups >= 8) {
		issues.unshift({
			type: 'approaching_limit',
			// Match check_spf's >= 9 → high threshold; 8 stays medium.
			severity: totalLookups >= 9 ? 'high' : 'medium',
			detail: `SPF using ${totalLookups}/${limit} lookups. Only ${limit - totalLookups} remaining before the limit.`,
		});
	}

	if (state.truncated) {
		issues.push({
			type: 'lookup_limit_exceeded',
			severity: 'high',
			detail: `Resolution stopped after the ${limit}th lookup: remaining include/redirect targets were not expanded, so the reported lookup count is a lower bound.`,
		});
	}

	return { domain, totalLookups, maxDepth, limit, overLimit, tree, issues, ...(state.inconclusive ? { inconclusive: true } : {}) };
}

/** Render a tree node as text lines with box-drawing characters. */
function renderTree(node: SpfNode, prefix: string, isLast: boolean, isRoot: boolean, lines: string[]): void {
	const connector = isRoot ? '' : isLast ? '└─ ' : '├─ ';
	const childPrefix = isRoot ? '' : isLast ? '   ' : '│  ';

	if (isRoot) {
		const record = node.record ? sanitizeOutputText(node.record, 200) : '(no SPF record)';
		lines.push(`${prefix}${record}`);
	} else {
		const safeDomain = sanitizeOutputText(node.domain, 100);
		const lookupLabel = node.lookups === 1 ? '1 lookup' : `${node.lookups} lookups`;
		if (node.error) {
			lines.push(`${prefix}${connector}${safeDomain} — ${node.error}`);
		} else if (node.record) {
			lines.push(`${prefix}${connector}${safeDomain} (${lookupLabel})`);
		} else {
			lines.push(`${prefix}${connector}${safeDomain} — no SPF record`);
		}
	}

	for (let i = 0; i < node.children.length; i++) {
		const child = node.children[i];
		const last = i === node.children.length - 1;
		renderTree(child, prefix + childPrefix, last, false, lines);
	}
}

/** Format an SPF chain result as human-readable text. */
export function formatSpfChain(result: SpfChainResult, format: OutputFormat = 'full'): string {
	const lines: string[] = [];
	const status = result.overLimit
		? 'OVER LIMIT'
		: result.totalLookups >= result.limit
			? 'AT LIMIT'
			: result.totalLookups >= 8
				? 'WARNING'
				: result.inconclusive
					? 'INCONCLUSIVE'
					: 'OK';

	if (format === 'compact') {
		lines.push(`SPF Chain: ${result.domain} — ${result.totalLookups}/${result.limit} lookups (${status})`);
		renderTree(result.tree, '', true, true, lines);
		if (result.issues.length > 0) {
			lines.push('');
			for (const issue of result.issues) {
				const icon = issue.severity === 'critical' ? '🚨' : issue.severity === 'high' ? '🔴' : '⚠';
				lines.push(`${icon} [${issue.severity.toUpperCase()}] ${sanitizeOutputText(issue.detail, 200)}`);
			}
		}
		return lines.join('\n');
	}

	lines.push(`# SPF Chain: ${result.domain}`);
	lines.push(`**Lookups:** ${result.totalLookups}/${result.limit} (${status})`);
	lines.push(`**Max depth:** ${result.maxDepth}`);
	lines.push('');
	lines.push('## Include Tree');
	renderTree(result.tree, '', true, true, lines);

	if (result.issues.length > 0) {
		lines.push('');
		lines.push('## Issues');
		for (const issue of result.issues) {
			lines.push(`- **[${issue.severity.toUpperCase()}]** ${issue.detail}`);
		}
	} else {
		lines.push('');
		lines.push('No issues detected.');
	}

	return lines.join('\n');
}
