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
import { cacheGet, cacheSet, runWithCache } from '../lib/cache';
import { queryTxtRecords } from '../lib/dns';
import { detectProviderMatches, detectProviderMatchesBySelectors, loadProviderSignatures } from '../lib/provider-signatures';
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
import { resolveImpactNarrative } from './explain-finding';

/** Cache key prefix for scan and per-check results */
const CACHE_PREFIX = 'cache:';

export interface ScanDomainResult {
	domain: string;
	score: ScanScore;
	checks: CheckResult[];
	cached: boolean;
	timestamp: string;
}

interface ScanRuntimeOptions {
	providerSignaturesUrl?: string;
}

function extractSpfSignalDomains(result: CheckResult | undefined): string[] {
	if (!result) return [];

	const domains = new Set<string>();
	for (const finding of result.findings) {
		const metadata = finding.metadata;
		if (!metadata || typeof metadata !== 'object') continue;

		const includeDomains = metadata.includeDomains;
		if (Array.isArray(includeDomains)) {
			for (const domain of includeDomains) {
				if (typeof domain === 'string' && domain.trim().length > 0) {
					domains.add(domain.trim().toLowerCase());
				}
			}
		}

		const redirectDomain = metadata.redirectDomain;
		if (typeof redirectDomain === 'string' && redirectDomain.trim().length > 0) {
			domains.add(redirectDomain.trim().toLowerCase());
		}
	}

	return Array.from(domains);
}

function extractDkimSignalSelectors(result: CheckResult | undefined): string[] {
	if (!result) return [];

	const selectors = new Set<string>();
	for (const finding of result.findings) {
		const metadata = finding.metadata;
		if (!metadata || typeof metadata !== 'object') continue;

		const selectorsFound = metadata.selectorsFound;
		if (!Array.isArray(selectorsFound)) continue;

		for (const selector of selectorsFound) {
			if (typeof selector === 'string' && selector.trim().length > 0) {
				selectors.add(selector.trim().toLowerCase());
			}
		}
	}

	return Array.from(selectors);
}

function upsertCheckResult(results: CheckResult[], updated: CheckResult): CheckResult[] {
	return results.map((r) => (r.category === updated.category ? updated : r));
}

async function addOutboundProviderInference(results: CheckResult[], runtimeOptions?: ScanRuntimeOptions): Promise<CheckResult[]> {
	const spfResult = results.find((r) => r.category === 'spf');
	const dkimResult = results.find((r) => r.category === 'dkim');

	const signalDomains = extractSpfSignalDomains(spfResult);
	const dkimSelectors = extractDkimSignalSelectors(dkimResult);
	if (signalDomains.length === 0 && dkimSelectors.length === 0) return results;

	const signatures = await loadProviderSignatures({ sourceUrl: runtimeOptions?.providerSignaturesUrl });
	const signatureSet = signatures.outbound.length > 0 ? signatures.outbound : signatures.inbound;
	const hostMatches = detectProviderMatches(signalDomains, signatureSet);
	const selectorMatches = detectProviderMatchesBySelectors(dkimSelectors, signatureSet);

	const mergedMatches = new Map<string, Set<string>>();
	for (const match of [...hostMatches, ...selectorMatches]) {
		if (!mergedMatches.has(match.provider)) {
			mergedMatches.set(match.provider, new Set<string>());
		}
		for (const evidence of match.matches) {
			mergedMatches.get(match.provider)?.add(evidence);
		}
	}

	const outboundMatches = Array.from(mergedMatches.entries()).map(([provider, matches]) => ({
		provider,
		matches: Array.from(matches),
	}));
	if (outboundMatches.length === 0) return results;

	const providerNames = outboundMatches.map((m) => m.provider).join(', ');
	const evidence = outboundMatches.map((m) => `${m.provider}: ${m.matches.join(', ')}`).join('; ');
 	const signalBoost = signalDomains.length > 0 && dkimSelectors.length > 0 ? 0.05 : 0;
	const baseConfidence = signatures.source === 'runtime' ? 0.85 : signatures.source === 'stale' ? 0.7 : 0.65;
	const providerConfidence = Math.min(0.95, baseConfidence + signalBoost);

	const spfBaseline = spfResult ?? buildCheckResult('spf', []);

	const updatedSpf = buildCheckResult('spf', [
		...spfBaseline.findings,
		createFinding('spf', 'Outbound email provider inferred', 'info', `Outbound provider(s): ${providerNames}. Evidence: ${evidence}.`, {
			detectionType: 'outbound',
			providers: outboundMatches.map((m) => ({ name: m.provider, matches: m.matches })),
			signalsUsed: {
				spfDomains: signalDomains,
				dkimSelectors,
			},
			providerConfidence,
			signatureSource: signatures.source,
			signatureVersion: signatures.version,
			signatureFetchedAt: signatures.fetchedAt,
		}),
	]);

	return upsertCheckResult(results, updatedSpf);
}

/**
 * Run a full DNS security scan on a domain.
 * Executes all checks in parallel and computes an overall score.
 *
 * @param domain - The domain to scan (must already be validated and sanitized by the caller)
 * @param kv - Optional KV namespace for persistent scan result caching
 * @returns Full scan result with score, individual check results, and metadata
 */
export async function scanDomain(domain: string, kv?: KVNamespace, runtimeOptions?: ScanRuntimeOptions): Promise<ScanDomainResult> {
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
		runCachedCheck(domain, 'mx', () => safeCheck('mx', () => checkMx(domain, { providerSignaturesUrl: runtimeOptions?.providerSignaturesUrl })), kv),
	]);

	// Adjust findings for non-mail domains: if no MX records, email auth
	// findings are expected and should not penalize the score
	const mxResult = checkResults.find((r) => r.category === 'mx');
	const hasNoMx = mxResult ? mxResult.findings.some((f) => f.title === 'No MX records found') : false;

	if (hasNoMx) {
		const apexCovers = await checkApexDmarcPolicy(domain);
		checkResults = adjustForNonMailDomain(checkResults, apexCovers);
	}

	checkResults = await addOutboundProviderInference(checkResults, runtimeOptions);

	// Compute overall score from all check results
	const score = computeScanScore(checkResults);

	const result: ScanDomainResult = {
		domain: domain,
		score,
		checks: checkResults,
		cached: false,
		timestamp: new Date().toISOString(),
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
				return { ...f, severity: 'info' as const, detail: `${f.detail} (${reason})` };
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
			const verificationStatus =
				finding.category === 'subdomain_takeover' && finding.metadata?.verificationStatus
					? String(finding.metadata.verificationStatus)
					: undefined;
			if (verificationStatus) {
				lines.push(`    Takeover Verification: ${verificationStatus}`);
			}
			const narrative = resolveImpactNarrative({
				category: finding.category,
				severity: finding.severity,
				title: finding.title,
				detail: finding.detail,
			});
			if (narrative.impact) {
				lines.push(`    Potential Impact: ${narrative.impact}`);
			}
			if (narrative.adverseConsequences) {
				lines.push(`    Adverse Consequences: ${narrative.adverseConsequences}`);
			}
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
	return lines.join('\n');
}
