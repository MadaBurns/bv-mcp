// SPDX-License-Identifier: BUSL-1.1

/**
 * CSC product mapping tool (sales-upsell layer).
 * Maps a domain's observed security gaps to the four CSC commercial products.
 * Reads existing CheckResults (dmarc/ssl/dnssec) plus Spec A's RDAP lock posture.
 * Emits NO new security finding/severity — `priority` here is a SALES priority,
 * deliberately distinct from a security severity. Modeled on map-compliance.ts.
 */

import type { CheckResult } from '../lib/scoring';
import type { LockPosture } from './check-rdap-lookup';
import { checkRdapLookup, RDAP_LOOKUP_SYNC_BUDGET_MS } from './check-rdap-lookup';
import { scanDomain } from './scan-domain';
import type { ScanRuntimeOptions } from './scan/post-processing';
import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';

export type CscProductKey = 'csc_multilock' | 'managed_dmarc' | 'digital_certificates' | 'dnssec_management';

/** Sales-upsell priority — NOT a security severity. */
export type CscPriority = 'high' | 'medium' | 'low' | 'none';

export interface CscProductRecommendation {
	product: CscProductKey;
	productName: string;
	recommended: boolean;
	priority: CscPriority;
	justifyingGap: string;
	relatedFindings: string[];
}

export interface CscProductReport {
	domain: string;
	score: number;
	grade: string;
	lockPosture: LockPosture | null;
	recommendations: CscProductRecommendation[];
	recommendedCount: number;
}

const CSC_PRODUCT_NAMES: Record<CscProductKey, string> = {
	csc_multilock: 'CSC MultiLock',
	managed_dmarc: 'Managed DMARC',
	digital_certificates: 'Digital Certificates',
	dnssec_management: 'DNSSEC management',
};

/** Non-info finding titles from a failing CheckResult (mirrors map-compliance). */
function nonInfoTitles(result: CheckResult | undefined): string[] {
	if (!result) return [];
	return result.findings.filter((f) => f.severity !== 'info').map((f) => f.title);
}

/** MultiLock recommendation — reads the booleans, not `level` alone (Spec A handoff). */
function evalMultiLock(lockPosture: LockPosture | null): CscProductRecommendation {
	const base = { product: 'csc_multilock' as const, productName: CSC_PRODUCT_NAMES.csc_multilock, relatedFindings: [] as string[] };
	if (lockPosture == null || lockPosture.level === 'unknown') {
		return { ...base, recommended: false, priority: 'none', justifyingGap: 'Lock posture unobservable (RDAP unavailable/redacted)' };
	}
	if (lockPosture.registryLevel === true) {
		return { ...base, recommended: false, priority: 'none', justifyingGap: 'Registry lock already in effect' };
	}
	if (lockPosture.transferLocked === false) {
		return { ...base, recommended: true, priority: 'high', justifyingGap: 'Domain transfer not locked — no registry or registrar lock' };
	}
	// registrarLevel true (or defensive fallback): registrar lock only, no server lock.
	return { ...base, recommended: true, priority: 'medium', justifyingGap: 'Registrar lock only — no registry-level (server) lock' };
}

/** Scan-driven product (dmarc/ssl/dnssec). Missing category → low-priority "not observed" lead. */
function evalScanProduct(
	product: Exclude<CscProductKey, 'csc_multilock'>,
	result: CheckResult | undefined,
	gaps: { passing: string; failing: string; absent: string },
): CscProductRecommendation {
	const base = { product, productName: CSC_PRODUCT_NAMES[product] };
	if (result === undefined) {
		return { ...base, recommended: true, priority: 'low', justifyingGap: gaps.absent, relatedFindings: [] };
	}
	if (result.passed) {
		return { ...base, recommended: false, priority: 'none', justifyingGap: gaps.passing, relatedFindings: [] };
	}
	const titles = nonInfoTitles(result);
	const hasSevere = result.findings.some((f) => f.severity === 'critical' || f.severity === 'high');
	return { ...base, recommended: true, priority: hasSevere ? 'high' : 'medium', justifyingGap: gaps.failing, relatedFindings: titles };
}

/**
 * Evaluate CSC product recommendations from scan results + RDAP lock posture (PURE).
 * Exported for direct unit testing without mocking scanDomain/checkRdapLookup.
 */
export function evaluateCscProducts(
	checkResults: CheckResult[],
	lockPosture: LockPosture | null,
	domain: string,
	score: number,
	grade: string,
): CscProductReport {
	const byCategory = new Map<string, CheckResult>();
	for (const r of checkResults) byCategory.set(r.category, r);

	const recommendations: CscProductRecommendation[] = [
		evalMultiLock(lockPosture),
		evalScanProduct('managed_dmarc', byCategory.get('dmarc'), {
			passing: 'DMARC policy in effect',
			failing: 'DMARC present but not passing',
			absent: 'DMARC not observed',
		}),
		evalScanProduct('digital_certificates', byCategory.get('ssl'), {
			passing: 'TLS/SSL configuration healthy',
			failing: 'TLS/SSL issues detected',
			absent: 'TLS/SSL not observed',
		}),
		evalScanProduct('dnssec_management', byCategory.get('dnssec'), {
			passing: 'DNSSEC enabled',
			failing: 'DNSSEC not enabled',
			absent: 'DNSSEC not observed',
		}),
	];

	return {
		domain,
		score,
		grade,
		lockPosture,
		recommendations,
		recommendedCount: recommendations.filter((r) => r.recommended).length,
	};
}

/**
 * Extract the LockPosture from a check_rdap_lookup CheckResult.
 * Spec A attaches one shared `metadata` object (with `lockPosture`) to all RDAP
 * findings, so the first finding carrying it is authoritative. Returns null when
 * none (lookup_failed / redacted) — the MultiLock line then degrades to
 * "unobservable" while the scan-driven products still evaluate.
 */
export function extractLockPosture(rdap: CheckResult): LockPosture | null {
	for (const f of rdap.findings) {
		const meta = (f as { metadata?: Record<string, unknown> }).metadata;
		const posture = meta?.lockPosture;
		if (posture && typeof posture === 'object') return posture as LockPosture;
	}
	return null;
}

const CSC_PRODUCT_ORDER: CscProductKey[] = ['csc_multilock', 'managed_dmarc', 'digital_certificates', 'dnssec_management'];

/** Render a CSC product report for display. */
export function formatCscProducts(report: CscProductReport, format: OutputFormat = 'full'): string {
	const lines: string[] = [];
	const byKey = new Map(report.recommendations.map((r) => [r.product, r]));

	if (format === 'compact') {
		lines.push(`CSC products: ${sanitizeOutputText(report.domain, 253)} — ${report.score}/100 (${report.grade}) — ${report.recommendedCount} upsell(s)`);
		for (const key of CSC_PRODUCT_ORDER) {
			const r = byKey.get(key)!;
			const icon = r.recommended ? ' →' : ' ✓';
			const suffix = r.recommended ? ` [${r.priority}] ${sanitizeOutputText(r.justifyingGap, 80)}` : '';
			lines.push(`${icon} ${sanitizeOutputText(r.productName, 40)}${suffix}`);
		}
	} else {
		lines.push(`# CSC Product Recommendations: ${sanitizeOutputText(report.domain, 253)}`);
		lines.push(`**Score:** ${report.score}/100 (${report.grade}) | **${report.recommendedCount}** recommended`);
		lines.push('');
		for (const key of CSC_PRODUCT_ORDER) {
			const r = byKey.get(key)!;
			const icon = r.recommended ? '✅' : '➖';
			const tag = r.recommended ? ` — ${r.priority.toUpperCase()}` : ' — OK';
			lines.push(`${icon} **${sanitizeOutputText(r.productName, 40)}**${tag}`);
			lines.push(`  - ${sanitizeOutputText(r.justifyingGap, 160)}`);
			for (const f of r.relatedFindings) lines.push(`  - ${sanitizeOutputText(f, 120)}`);
		}
	}

	return lines.join('\n').trimEnd();
}

/** runtimeOptions accepted by the orchestrator — ScanRuntimeOptions plus the optional WHOIS binding the RDAP call threads. */
type CscRuntimeOptions = ScanRuntimeOptions & { whoisBinding?: { fetch: typeof fetch } };

/**
 * Map a domain's security gaps to CSC products (orchestrator — the only impure unit).
 * Runs a full scan (cached) + a budget-bounded RDAP lookup, then evaluates.
 */
export async function mapCscProducts(domain: string, kv?: KVNamespace, runtimeOptions?: CscRuntimeOptions): Promise<CscProductReport> {
	// Capture the deadline epoch BEFORE kicking off both calls so the RDAP budget
	// is not charged for scan elapsed time (the two calls are independent).
	const deadlineMs = Date.now() + RDAP_LOOKUP_SYNC_BUDGET_MS;
	const [scanResult, rdap] = await Promise.all([
		scanDomain(domain, kv, runtimeOptions),
		checkRdapLookup(domain, {
			whoisBinding: runtimeOptions?.whoisBinding,
			signal: AbortSignal.timeout(RDAP_LOOKUP_SYNC_BUDGET_MS),
			deadlineMs,
		}),
	]);
	const lockPosture = extractLockPosture(rdap);
	return evaluateCscProducts(scanResult.checks, lockPosture, domain, scanResult.score.overall, scanResult.score.grade);
}
