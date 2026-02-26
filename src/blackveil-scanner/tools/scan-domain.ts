/**
 * Domain scan orchestrator for BLACKVEIL Scanner npm package.
 * Runs all DNS/email security checks in parallel and returns combined results and score.
 *
 * @param domain - Domain name to scan (e.g., example.com)
 * @returns Promise<{ results: Record<string, any>, score: number }>
 */
import { checkSPF } from './check-spf';
import { checkDMARC } from './check-dmarc';
import { checkDKIM } from './check-dkim';
import { checkDNSSEC } from './check-dnssec';
import { checkSSL } from './check-ssl';
import { checkMtaSts } from './check-mta-sts';
import { checkNS } from './check-ns';
import { checkCAA } from './check-caa';
import { checkMX } from './check-mx';
import type { CheckResult } from '../lib/scoring';
import { calculateScanScore } from '../lib/scoring';

export async function scanDomain(domain: string): Promise<{ results: Record<string, CheckResult>, score: number }> {
	const checks = [
		checkSPF,
		checkDMARC,
		checkDKIM,
		checkDNSSEC,
		checkSSL,
		checkMtaSts,
		checkNS,
		checkCAA,
		checkMX,
	];

	// Check if domain exists via NS query
	try {
		const nsResult = await checkNS(domain);
		if (
			nsResult.findings.some(
				(f) => f.title?.toLowerCase().includes('no nameserver records found') || f.detail?.toLowerCase().includes('nxdomain')
			)
		) {
			// NXDOMAIN detected
			return {
				results: {
					NXDOMAIN: {
						category: 'ns',
						passed: false,
						score: 0,
						findings: [
							{
								category: 'ns',
								title: 'Domain does not exist (NXDOMAIN)',
								severity: 'critical',
								detail: `The domain ${domain} does not exist in DNS (NXDOMAIN). No further checks performed.`,
							},
						],
					},
				},
				score: 0,
			};
		}
	} catch (e) {
		// If NS check throws, treat as NXDOMAIN
		return {
			results: {
				NXDOMAIN: {
					category: 'ns',
					passed: false,
					score: 0,
					findings: [
						{
							category: 'ns',
							title: 'Domain does not exist (NXDOMAIN)',
							severity: 'critical',
							detail: `The domain ${domain} does not exist in DNS (NXDOMAIN). No further checks performed.`,
						},
					],
				},
			},
			score: 0,
		};
	}

	const results: Record<string, CheckResult> = {};
	await Promise.all(
		checks.map(async (fn) => {
			const name = fn.name.replace(/^check/, '').toUpperCase();
			results[name] = await fn(domain);
		})
	);

	const score = calculateScanScore(results);
	return { results, score };
}
