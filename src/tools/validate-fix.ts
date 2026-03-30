// SPDX-License-Identifier: BUSL-1.1

/**
 * Validate Fix tool.
 * Re-checks a specific DNS control after a user applies a fix.
 * Runs the single check function (always live, no cache), evaluates the result,
 * and returns a verdict: fixed, partial, or not_fixed.
 */

import type { OutputFormat } from '../handlers/tool-args';
import type { CheckResult, Finding, Severity } from '../lib/scoring-model';
import type { QueryDnsOptions } from '../lib/dns-types';
import { sanitizeOutputText } from '../lib/output-sanitize';
import { checkSpf } from './check-spf';
import { checkDmarc } from './check-dmarc';
import { checkDkim } from './check-dkim';
import { checkDnssec } from './check-dnssec';
import { checkSsl } from './check-ssl';
import { checkMtaSts } from './check-mta-sts';
import { checkNs } from './check-ns';
import { checkCaa } from './check-caa';
import { checkBimi } from './check-bimi';
import { checkTlsrpt } from './check-tlsrpt';
import { checkHttpSecurity } from './check-http-security';
import { checkDane } from './check-dane';

/** Map of check names to their check functions. */
const CHECK_FUNCTIONS: Record<string, (domain: string, dnsOptions?: QueryDnsOptions) => Promise<CheckResult>> = {
	spf: (d, o) => checkSpf(d, o),
	dmarc: (d, o) => checkDmarc(d, o),
	dkim: (d, o) => checkDkim(d, undefined, o),
	dnssec: (d, o) => checkDnssec(d, o),
	ssl: (d) => checkSsl(d),
	mta_sts: (d, o) => checkMtaSts(d, o),
	ns: (d, o) => checkNs(d, o),
	caa: (d, o) => checkCaa(d, o),
	bimi: (d, o) => checkBimi(d, o),
	tlsrpt: (d, o) => checkTlsrpt(d, o),
	http_security: (d) => checkHttpSecurity(d),
	dane: (d, o) => checkDane(d, o),
};

/** Verdict types for a validation check. */
export type ValidateFixVerdict = 'fixed' | 'partial' | 'not_fixed';

/** Result of validating a fix. */
export interface ValidateFixResult {
	domain: string;
	check: string;
	verdict: ValidateFixVerdict;
	liveRecord: string | null;
	expectedMatch: boolean | null;
	resolvedFindings: string[];
	remainingFindings: string[];
	newFindings: string[];
	hint: string | null;
}

/** Severity levels considered blocking for a "fixed" verdict. */
const BLOCKING_SEVERITIES = new Set<Severity>(['critical', 'high']);

/** Severity levels that indicate partial progress (not fully fixed but improved). */
const PARTIAL_SEVERITIES = new Set<Severity>(['medium', 'low']);

/**
 * Extract the most relevant live record from check result findings.
 * Looks for record content in finding details.
 */
function extractLiveRecord(findings: Finding[]): string | null {
	for (const f of findings) {
		// Look for common DNS record patterns in finding detail text
		if (f.detail && f.severity !== 'critical') {
			const recordPatterns = [
				/v=spf1[^"']*/i,
				/v=DMARC1[^"']*/i,
				/v=DKIM1[^"']*/i,
				/v=STSv1[^"']*/i,
				/v=TLSRPTv1[^"']*/i,
			];
			for (const pattern of recordPatterns) {
				const match = f.detail.match(pattern);
				if (match) return match[0].trim();
			}
		}
	}
	// Fallback: use first non-critical finding detail as the live record indicator
	const nonCritical = findings.find((f) => f.severity !== 'critical' && f.detail.length > 0);
	return nonCritical ? sanitizeOutputText(nonCritical.detail, 500) : null;
}

/**
 * Validate whether a DNS fix has been applied by re-running the relevant check.
 *
 * @param domain - Validated, sanitized domain
 * @param check - Check name (e.g., 'spf', 'dmarc')
 * @param expected - Optional expected DNS record value to verify
 * @param dnsOptions - Optional DNS query options
 * @returns Validation result with verdict
 */
export async function validateFix(
	domain: string,
	check: string,
	expected?: string,
	dnsOptions?: QueryDnsOptions,
): Promise<ValidateFixResult> {
	const checkFn = CHECK_FUNCTIONS[check];
	if (!checkFn) {
		throw new Error(`Invalid check name: ${check}`);
	}

	const result = await checkFn(domain, dnsOptions);

	// Classify findings by severity
	const blockingFindings = result.findings.filter((f: Finding) => BLOCKING_SEVERITIES.has(f.severity));
	const partialFindings = result.findings.filter((f: Finding) => PARTIAL_SEVERITIES.has(f.severity));
	const remainingTitles = [...blockingFindings, ...partialFindings].map((f) => f.title);
	const resolvedTitles: string[] = [];

	// Determine verdict
	let verdict: ValidateFixVerdict;
	if (blockingFindings.length === 0 && result.passed) {
		verdict = partialFindings.length > 0 ? 'partial' : 'fixed';
	} else {
		verdict = 'not_fixed';
	}

	// Extract live record from findings
	const liveRecord = extractLiveRecord(result.findings);

	// Check expected record match if provided
	let expectedMatch: boolean | null = null;
	if (expected !== undefined) {
		if (liveRecord) {
			expectedMatch = liveRecord.includes(expected) || expected.includes(liveRecord);
		} else {
			// Check if any finding detail contains the expected value
			expectedMatch = result.findings.some((f: Finding) => f.detail.includes(expected));
		}
	}

	// Generate a hint for not_fixed results
	let hint: string | null = null;
	if (verdict === 'not_fixed' && blockingFindings.length > 0) {
		const topFinding = blockingFindings[0];
		hint = `${topFinding.severity.toUpperCase()}: ${sanitizeOutputText(topFinding.title, 200)} — ${sanitizeOutputText(topFinding.detail, 300)}`;
	}

	return {
		domain,
		check,
		verdict,
		liveRecord,
		expectedMatch,
		resolvedFindings: resolvedTitles,
		remainingFindings: remainingTitles,
		newFindings: [],
		hint,
	};
}

/**
 * Format a ValidateFixResult as human-readable text.
 *
 * @param result - The validation result to format
 * @param format - Output format ('compact' or 'full')
 */
export function formatValidateFix(result: ValidateFixResult, format: OutputFormat = 'full'): string {
	const verdictLabel = result.verdict.toUpperCase().replace('_', ' ');

	if (format === 'compact') {
		const parts = [`Validate Fix: ${result.domain} [${result.check}] — ${verdictLabel}`];
		if (result.liveRecord) {
			parts.push(`Live: ${sanitizeOutputText(result.liveRecord, 200)}`);
		}
		if (result.expectedMatch !== null) {
			parts.push(`Expected match: ${result.expectedMatch ? 'yes' : 'no'}`);
		}
		if (result.remainingFindings.length > 0) {
			parts.push(`Remaining: ${result.remainingFindings.map((f) => sanitizeOutputText(f, 100)).join(', ')}`);
		}
		if (result.hint) {
			parts.push(`Hint: ${sanitizeOutputText(result.hint, 300)}`);
		}
		return parts.join('\n');
	}

	// Full format
	const lines: string[] = [];
	lines.push(`# Fix Validation: ${result.domain}`);
	lines.push(`Check: ${result.check}`);
	lines.push(`Verdict: ${verdictLabel}`);
	lines.push('');

	if (result.liveRecord) {
		lines.push('## Live Record');
		lines.push(`  ${sanitizeOutputText(result.liveRecord, 500)}`);
		lines.push('');
	}

	if (result.expectedMatch !== null) {
		lines.push(`Expected Record Match: ${result.expectedMatch ? 'YES' : 'NO'}`);
		lines.push('');
	}

	if (result.remainingFindings.length > 0) {
		lines.push('## Remaining Findings');
		for (const finding of result.remainingFindings) {
			lines.push(`  - ${sanitizeOutputText(finding, 200)}`);
		}
		lines.push('');
	}

	if (result.hint) {
		lines.push('## Suggested Next Step');
		lines.push(`  ${sanitizeOutputText(result.hint, 500)}`);
	}

	return lines.join('\n');
}
