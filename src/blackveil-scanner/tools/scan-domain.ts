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
