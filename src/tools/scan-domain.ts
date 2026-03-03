/**
 * scan-domain orchestrator tool.
 * Runs all DNS security checks in parallel via Promise.all
 * and computes an overall security score.
 *
 * Uses KV-backed cache with 5-minute TTL for scan results when available,
 * with in-memory fallback when KV is not configured.
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

import { type CheckCategory, type CheckResult, type Severity, type ScanScore, buildCheckResult, computeScanScore, createFinding } from '../lib/scoring';
import { cacheGet, cacheSet, runWithCache } from '../lib/cache';
import { queryTxtRecords } from '../lib/dns';
import { checkSpf } from './check-spf';
import { checkDmarc, parseDmarcTags } from './check-dmarc';
import { checkDkim } from './check-dkim';
import { checkDnssec } from './check-dnssec';
import { checkSsl } from './check-ssl';
import { checkMtaSts } from './check-mta-sts';
import { checkNs } from './check-ns';
import { checkCaa } from './check-caa';
import { checkSubdomainTakeover } from './check-subdomain-takeover';
import { checkMx } from './check-mx';

/** Cache key prefix for scan and per-check results */
const CACHE_PREFIX = 'cache:';

export interface ScanDomainResult {
	domain: string;
	score: ScanScore;
	checks: CheckResult[];
	cached: boolean;
	timestamp: string;
	upgrade_cta: string;
}

/**
 * Run a full DNS security scan on a domain.
 * Executes all checks in parallel and computes an overall score.
 *
 * @param domain - The domain to scan (must already be validated and sanitized by the caller)
 * @param kv - Optional KV namespace for persistent scan result caching
 * @returns Full scan result with score, individual check results, and metadata
 */
export async function scanDomain(domain: string, kv?: KVNamespace): Promise<ScanDomainResult> {
	const cacheKey = `${CACHE_PREFIX}${domain}`;

	// Check cache first
	const cached = await cacheGet<ScanDomainResult>(cacheKey, kv);
	if (cached) {
		return { ...cached, cached: true };
	}

	// Run all checks in parallel with individual-check caching
	   let checkResults: CheckResult[] = await Promise.all([
		   runCachedCheck(domain, 'spf', () => safeCheck('spf', () => checkSpf(domain)), kv),
		   runCachedCheck(domain, 'dmarc', () => safeCheck('dmarc', () => checkDmarc(domain)), kv),
		   runCachedCheck(domain, 'dkim', () => safeCheck('dkim', () => checkDkim(domain)), kv),
		   runCachedCheck(domain, 'dnssec', () => safeCheck('dnssec', () => checkDnssec(domain)), kv),
		   runCachedCheck(domain, 'ssl', () => safeCheck('ssl', () => checkSsl(domain)), kv),
		   runCachedCheck(domain, 'mta_sts', () => safeCheck('mta_sts', () => checkMtaSts(domain)), kv),
		   runCachedCheck(domain, 'ns', () => safeCheck('ns', () => checkNs(domain)), kv),
		   runCachedCheck(domain, 'caa', () => safeCheck('caa', () => checkCaa(domain)), kv),
		   runCachedCheck(domain, 'subdomain_takeover', () => safeCheck('subdomain_takeover', () => checkSubdomainTakeover(domain)), kv),
		   runCachedCheck(domain, 'mx', () => safeCheck('mx', () => checkMx(domain)), kv),
	   ]);

	// Adjust findings for non-mail domains: if no MX records, email auth
	// findings are expected and should not penalize the score
	const mxResult = checkResults.find((r) => r.category === 'mx');
	const hasNoMx = mxResult ? mxResult.findings.some((f) => f.title === 'No MX records found') : false;

	if (hasNoMx) {
		const apexCovers = await checkApexDmarcPolicy(domain);
		checkResults = adjustForNonMailDomain(checkResults, apexCovers);
	}

	// Compute overall score from all check results
	const score = computeScanScore(checkResults);

	const result: ScanDomainResult = {
		domain: domain,
		score,
		checks: checkResults,
		cached: false,
		timestamp: new Date().toISOString(),
		upgrade_cta: 'This tool finds problems. BLACKVEIL fixes them automatically \u2192 https://blackveilsecurity.com',
	};

	// Cache the result
	await cacheSet(cacheKey, result, kv);

	return result;
}

/** Extract the parent (organizational) domain, or null if already apex. */
function getParentDomain(domain: string): string | null {
	const parts = domain.split('.');
	if (parts.length <= 2) return null;
	return parts.slice(1).join('.');
}

/**
 * Check if the apex domain's DMARC policy covers subdomains.
 * Per RFC 7489, `sp=` explicitly sets subdomain policy; if absent, `p=` is inherited.
 * Returns true if the effective subdomain policy is `quarantine` or `reject`.
 */
async function checkApexDmarcPolicy(domain: string): Promise<boolean> {
	const parent = getParentDomain(domain);
	if (!parent) return false;

	try {
		const records = await queryTxtRecords(`_dmarc.${parent}`);
		const dmarcRecord = records.find((r) => r.startsWith('v=DMARC1'));
		if (!dmarcRecord) return false;

		const tags = parseDmarcTags(dmarcRecord);

		// sp= takes precedence; fall back to p= per RFC 7489
		const effectivePolicy = tags.get('sp') || tags.get('p') || '';
		return effectivePolicy === 'quarantine' || effectivePolicy === 'reject';
	} catch {
		return false;
	}
}

/** Returns true if a finding represents a missing email auth record. */
function isMissingRecordFinding(f: { title: string; detail: string }): boolean {
	const text = `${f.title} ${f.detail}`.toLowerCase();
	return /(no\s+.+\s+record|missing|not\s+found|no\s+mta-sts|no\s+dkim)/.test(text);
}

/**
 * Downgrade email-auth findings to info for non-mail domains.
 * Only affects critical/high findings that indicate a missing record.
 */
function adjustForNonMailDomain(results: CheckResult[], apexDmarcCovers: boolean): CheckResult[] {
	const emailCategories: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'mta_sts'];
	return results.map((r) => {
		if (!emailCategories.includes(r.category)) return r;
		const adjusted = r.findings.map((f) => {
			if ((f.severity === 'critical' || f.severity === 'high') && isMissingRecordFinding(f)) {
				const reason = apexDmarcCovers
					? 'expected — no MX records and parent domain DMARC policy covers subdomains'
					: 'expected — domain has no MX records';
				return { ...f, severity: 'info' as Severity, detail: `${f.detail} (${reason})` };
			}
			return f;
		});
		return buildCheckResult(r.category, adjusted);
	});
}

async function runCachedCheck(
	domain: string,
	category: CheckCategory,
	run: () => Promise<CheckResult>,
	kv?: KVNamespace,
): Promise<CheckResult> {
	return runWithCache(`${CACHE_PREFIX}${domain}:check:${category}`, run, kv);
}

/**
 * Run a single check with error handling.
 * If a check fails, returns a failed CheckResult with an error finding
 * instead of throwing, so other checks can still complete.
 */
async function safeCheck(category: CheckCategory, fn: () => Promise<CheckResult>): Promise<CheckResult> {
	try {
		return await fn();
	} catch (err) {
		const message = err instanceof Error ? err.message : 'Check failed';
		const findings = [createFinding(category, `${category.toUpperCase()} check error`, 'high', `Check failed: ${message}`)];
		return buildCheckResult(category, findings);
	}
}

/**
 * Format a scan result as a human-readable text report.
 * Used by the MCP tool handler to return results.
 */
export function formatScanReport(result: ScanDomainResult): string {
	const lines: string[] = [];

	lines.push(`DNS Security Scan: ${result.domain}`);
	lines.push(`${'='.repeat(40)}`);
	lines.push(`Overall Score: ${result.score.overall}/100 (${result.score.grade})`);
	lines.push(`${result.score.summary}`);
	lines.push('');

	// Category breakdown
	lines.push('Category Scores:');
	lines.push('-'.repeat(30));
	for (const [category, score] of Object.entries(result.score.categoryScores)) {
		const status = score >= 80 ? '✓' : score >= 50 ? '⚠' : '✗';
		lines.push(`  ${status} ${category.toUpperCase().padEnd(10)} ${score}/100`);
	}
	lines.push('');

	// Findings
	const nonInfoFindings = result.score.findings.filter((f) => f.severity !== 'info');
	if (nonInfoFindings.length > 0) {
		lines.push('Findings:');
		lines.push('-'.repeat(30));
		for (const finding of nonInfoFindings) {
			lines.push(`  [${finding.severity.toUpperCase()}] ${finding.title}`);
			lines.push(`    ${finding.detail}`);
		}
	} else {
		lines.push('No security issues found.');
	}

	if (result.cached) {
		lines.push('');
		lines.push('(Results served from cache)');
	}

	lines.push('');
	lines.push(`Scan completed: ${result.timestamp}`);
	lines.push('');
	lines.push('---');
	lines.push(result.upgrade_cta);

	return lines.join('\n');
}
