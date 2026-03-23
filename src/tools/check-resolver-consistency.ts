// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS resolver consistency check tool.
 *
 * Queries 4 public DoH resolvers (Cloudflare, Google, Quad9, OpenDNS) in parallel
 * for multiple record types and compares answer sets to detect:
 * - GeoDNS / CDN steering (SPLIT_HORIZON)
 * - Propagation issues or blocking (INCOMPLETE)
 * - Potential DNS poisoning (SUSPICIOUS)
 * - Normal consistent resolution (CONSISTENT)
 */

import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';
import type { CheckResult } from '../lib/scoring-model';
import { buildCheckResult, createFinding } from '../lib/scoring-model';
import { checkMultiResolverConsistency, type ConsistencyResult } from '../lib/dns-multi-resolver';
import type { RecordTypeName } from '../lib/dns-types';

/** Default record types to check. */
const DEFAULT_TYPES: RecordTypeName[] = ['A', 'AAAA', 'MX', 'TXT', 'NS'];

/**
 * Check DNS resolver consistency for a domain.
 *
 * @param domain - Validated, sanitized domain
 * @param recordType - Optional specific record type to check. If omitted, checks A, AAAA, MX, TXT, NS.
 * @returns CheckResult with findings per record type
 */
export async function checkResolverConsistency(
	domain: string,
	recordType?: string,
): Promise<CheckResult> {
	const types: RecordTypeName[] = recordType
		? [recordType.toUpperCase() as RecordTypeName]
		: DEFAULT_TYPES;

	const results = await checkMultiResolverConsistency(domain, types);

	const findings = results.map((result: ConsistencyResult) => {
		switch (result.status) {
			case 'CONSISTENT':
				return createFinding(
					'zone_hygiene',
					`${result.recordType} records consistent`,
					'info',
					result.detail,
					{
						recordType: result.recordType,
						resolverCount: result.resolverAnswers.filter((r) => r.status === 'ok').length,
						status: result.status,
					},
				);

			case 'SPLIT_HORIZON':
				return createFinding(
					'zone_hygiene',
					`${result.recordType} records differ across resolvers`,
					'low',
					result.detail,
					{
						recordType: result.recordType,
						status: result.status,
						resolverAnswers: result.resolverAnswers.map((r) => ({
							resolver: r.resolver,
							status: r.status,
							answers: r.answers,
						})),
					},
				);

			case 'INCOMPLETE':
				return createFinding(
					'zone_hygiene',
					`${result.recordType} records incomplete across resolvers`,
					'low',
					result.detail,
					{
						recordType: result.recordType,
						status: result.status,
						resolverAnswers: result.resolverAnswers.map((r) => ({
							resolver: r.resolver,
							status: r.status,
							answers: r.answers,
						})),
					},
				);

			case 'SUSPICIOUS':
				return createFinding(
					'zone_hygiene',
					`${result.recordType} records show suspicious divergence`,
					'high',
					result.detail,
					{
						recordType: result.recordType,
						status: result.status,
						resolverAnswers: result.resolverAnswers.map((r) => ({
							resolver: r.resolver,
							status: r.status,
							answers: r.answers,
						})),
					},
				);
		}
	});

	return buildCheckResult('zone_hygiene', findings);
}

/** Format resolver consistency results as human-readable text. */
export function formatResolverConsistency(result: CheckResult, format: OutputFormat = 'full'): string {
	const suspicious = result.findings.filter((f) => f.severity === 'high').length;
	const splits = result.findings.filter((f) => f.severity === 'low').length;
	const consistent = result.findings.filter((f) => f.severity === 'info').length;

	if (format === 'compact') {
		const lines = [`Resolver Consistency: ${consistent} consistent, ${splits} split, ${suspicious} suspicious`];
		for (const finding of result.findings) {
			if (finding.severity === 'info') continue;
			lines.push(`- [${finding.severity.toUpperCase()}] ${finding.title} — ${sanitizeOutputText(finding.detail, 200)}`);
		}
		return lines.join('\n');
	}

	const lines: string[] = [];

	lines.push('# DNS Resolver Consistency Check');
	lines.push('');

	for (const finding of result.findings) {
		const status = finding.metadata?.status as string ?? 'unknown';
		const icon = status === 'CONSISTENT' ? '✓' : status === 'SUSPICIOUS' ? '✗' : '⚠';
		lines.push(`${icon} ${finding.title}`);
		lines.push(`  ${finding.detail}`);

		const resolverAnswers = finding.metadata?.resolverAnswers as Array<{ resolver: string; status: string; answers: string[] }> | undefined;
		if (resolverAnswers) {
			for (const ra of resolverAnswers) {
				const answerStr = ra.answers.length > 0 ? ra.answers.join(', ') : '(empty)';
				lines.push(`    ${ra.resolver}: [${ra.status}] ${answerStr}`);
			}
		}
		lines.push('');
	}

	lines.push(`Summary: ${consistent} consistent, ${splits} split/incomplete, ${suspicious} suspicious`);

	return lines.join('\n');
}
