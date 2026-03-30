// SPDX-License-Identifier: BUSL-1.1

/**
 * Recursively resolve the full SPF include chain.
 * Counts DNS lookups against the RFC 7208 10-lookup limit,
 * builds a tree, and flags issues.
 */

import type { OutputFormat } from '../handlers/tool-args';
import type { QueryDnsOptions } from '../lib/dns-types';
import { queryTxtRecords } from '../lib/dns';
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
	type: 'over_limit' | 'approaching_limit' | 'circular_include' | 'void_lookup' | 'redundant_include';
	severity: 'critical' | 'high' | 'medium' | 'low';
	detail: string;
}

export interface SpfChainResult {
	domain: string;
	totalLookups: number;
	maxDepth: number;
	limit: number;
	overLimit: boolean;
	tree: SpfNode;
	issues: SpfIssue[];
}

/** Mechanisms that cost 1 DNS lookup per RFC 7208 §4.6.4. */
const LOOKUP_MECHANISMS = /^(include:|redirect=|a(?:$|[:\/])|mx(?:$|[:\/])|exists:|ptr(?:$|[:\/]))/i;

/** Extract the target domain from include:/redirect= directives. */
function extractTarget(mechanism: string): string | null {
	const includeMatch = mechanism.match(/^include:(.+)$/i);
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

/** Count lookup-costing mechanisms (not counting recursive children). */
function countDirectLookups(mechanisms: string[]): number {
	return mechanisms.filter((m) => LOOKUP_MECHANISMS.test(m)).length;
}

/**
 * Recursively resolve an SPF include chain.
 */
async function resolveNode(
	domain: string,
	visited: Set<string>,
	allSeen: Map<string, number>,
	depth: number,
	issues: SpfIssue[],
	dnsOptions?: QueryDnsOptions,
): Promise<SpfNode> {
	const normalized = domain.toLowerCase();

	// Circular detection
	if (visited.has(normalized)) {
		issues.push({
			type: 'circular_include',
			severity: 'high',
			detail: `Circular include detected: ${normalized} already visited in this chain.`,
		});
		return { domain: normalized, record: null, lookups: 0, mechanisms: [], children: [], error: 'circular' };
	}

	// Redundant detection
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

	visited.add(normalized);

	let txtRecords: string[];
	try {
		txtRecords = await queryTxtRecords(normalized, dnsOptions);
	} catch {
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
	const directLookups = countDirectLookups(mechanisms);

	// Recursively resolve include:/redirect= targets
	const children: SpfNode[] = [];
	for (const mech of mechanisms) {
		const target = extractTarget(mech);
		if (target) {
			const child = await resolveNode(target, new Set(visited), allSeen, depth + 1, issues, dnsOptions);
			children.push(child);
		}
	}

	const childLookups = children.reduce((sum, c) => sum + c.lookups, 0);
	const totalLookups = directLookups + childLookups;

	visited.delete(normalized);

	return {
		domain: normalized,
		record: spfRecord,
		lookups: totalLookups,
		mechanisms,
		children,
	};
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
export async function resolveSpfChain(
	domain: string,
	dnsOptions?: QueryDnsOptions,
): Promise<SpfChainResult> {
	const issues: SpfIssue[] = [];
	const allSeen = new Map<string, number>();
	const tree = await resolveNode(domain, new Set(), allSeen, 0, issues, dnsOptions);

	const totalLookups = tree.lookups;
	const maxDepth = computeMaxDepth(tree);
	const limit = 10;
	const overLimit = totalLookups > limit;

	// Add limit-related issues
	if (overLimit) {
		issues.unshift({
			type: 'over_limit',
			severity: 'critical',
			detail: `SPF lookup limit exceeded: ${totalLookups}/${limit}. Emails may fail SPF validation after the 10th lookup.`,
		});
	} else if (totalLookups >= 8) {
		issues.unshift({
			type: 'approaching_limit',
			severity: 'medium',
			detail: `SPF using ${totalLookups}/${limit} lookups. Only ${limit - totalLookups} remaining before the limit.`,
		});
	}

	return { domain, totalLookups, maxDepth, limit, overLimit, tree, issues };
}

/** Render a tree node as text lines with box-drawing characters. */
function renderTree(node: SpfNode, prefix: string, isLast: boolean, isRoot: boolean, lines: string[]): void {
	const connector = isRoot ? '' : isLast ? '└─ ' : '├─ ';
	const childPrefix = isRoot ? '' : isLast ? '   ' : '│  ';

	if (isRoot) {
		const record = node.record ? sanitizeOutputText(node.record, 200) : '(no SPF record)';
		lines.push(`${prefix}${record}`);
	} else {
		const lookupLabel = node.lookups === 1 ? '1 lookup' : `${node.lookups} lookups`;
		if (node.error) {
			lines.push(`${prefix}${connector}${node.domain} — ${node.error}`);
		} else if (node.record) {
			lines.push(`${prefix}${connector}${node.domain} (${lookupLabel})`);
		} else {
			lines.push(`${prefix}${connector}${node.domain} — no SPF record`);
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
	const status = result.overLimit ? 'OVER LIMIT' : result.totalLookups >= 8 ? 'WARNING' : 'OK';

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
