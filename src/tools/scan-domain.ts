/**
 * scan-domain orchestrator tool.
 * Runs all DNS security checks in parallel via Promise.all
 * and computes an overall security score.
 *
 * Uses KV-backed cache with 5-minute TTL for scan results when available,
 * with in-memory fallback when KV is not configured.
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

import { type CheckCategory, type CheckResult, type ScanScore, buildCheckResult, computeScanScore, createFinding } from '../lib/scoring';
import { cacheGet, cacheSet } from '../lib/cache';
import { validateDomain, sanitizeDomain } from '../lib/sanitize';
import { checkSpf } from './check-spf';
import { checkDmarc } from './check-dmarc';
import { checkDkim } from './check-dkim';
import { checkDnssec } from './check-dnssec';
import { checkSsl } from './check-ssl';
import { checkMtaSts } from './check-mta-sts';
import { checkNs } from './check-ns';
import { checkCaa } from './check-caa';
import { checkSubdomainTakeover } from './check-subdomain-takeover';

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
 * @param domain - The domain to scan (will be validated and sanitized)
 * @param kv - Optional KV namespace for persistent scan result caching
 * @returns Full scan result with score, individual check results, and metadata
 * @throws Error if domain validation fails
 */
export async function scanDomain(domain: string, kv?: KVNamespace): Promise<ScanDomainResult> {
	// Validate domain
	const validation = validateDomain(domain);
	if (!validation.valid) {
		throw new Error(validation.error ?? 'Invalid domain');
	}

	const cleanDomain = sanitizeDomain(domain);
	const cacheKey = `${CACHE_PREFIX}${cleanDomain}`;

	// Check cache first
	const cached = await cacheGet<ScanDomainResult>(cacheKey, kv);
	if (cached) {
		return { ...cached, cached: true };
	}

	// Run all checks in parallel with individual-check caching
	   const checkResults = await Promise.all([
		   runCachedCheck(cleanDomain, 'spf', () => safeCheck('spf', () => checkSpf(cleanDomain)), kv),
		   runCachedCheck(cleanDomain, 'dmarc', () => safeCheck('dmarc', () => checkDmarc(cleanDomain)), kv),
		   runCachedCheck(cleanDomain, 'dkim', () => safeCheck('dkim', () => checkDkim(cleanDomain)), kv),
		   runCachedCheck(cleanDomain, 'dnssec', () => safeCheck('dnssec', () => checkDnssec(cleanDomain)), kv),
		   runCachedCheck(cleanDomain, 'ssl', () => safeCheck('ssl', () => checkSsl(cleanDomain)), kv),
		   runCachedCheck(cleanDomain, 'mta_sts', () => safeCheck('mta_sts', () => checkMtaSts(cleanDomain)), kv),
		   runCachedCheck(cleanDomain, 'ns', () => safeCheck('ns', () => checkNs(cleanDomain)), kv),
		   runCachedCheck(cleanDomain, 'caa', () => safeCheck('caa', () => checkCaa(cleanDomain)), kv),
		   runCachedCheck(cleanDomain, 'subdomain_takeover', () => safeCheck('subdomain_takeover', () => checkSubdomainTakeover(cleanDomain)), kv),
	   ]);

	// Compute overall score from all check results
	const score = computeScanScore(checkResults);

	const result: ScanDomainResult = {
		domain: cleanDomain,
		score,
		checks: checkResults,
		cached: false,
		timestamp: new Date().toISOString(),
		upgrade_cta: 'This tool finds problems. BLACKVEIL fixes them automatically \u2192 https://blackveil.co.nz',
	};

	// Cache the result
	await cacheSet(cacheKey, result, kv);

	return result;
}

async function runCachedCheck(
	domain: string,
	category: CheckCategory,
	run: () => Promise<CheckResult>,
	kv?: KVNamespace,
): Promise<CheckResult> {
	const checkKey = `${CACHE_PREFIX}${domain}:check:${category}`;
	const cached = await cacheGet<CheckResult>(checkKey, kv);
	if (cached) {
		return cached;
	}

	const result = await run();
	await cacheSet(checkKey, result, kv);
	return result;
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
