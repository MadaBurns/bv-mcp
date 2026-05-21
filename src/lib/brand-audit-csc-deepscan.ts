// SPDX-License-Identifier: BUSL-1.1

/**
 * Deep-scan orchestrator for CSC-complement view.
 *
 * For each top-N apex (default cap 25), runs scan_domain and discover_subdomains
 * via an injected internal-call function. Aggregates per-apex posture
 * (grade/score) and dangling-DNS findings (via scan_domain's internal
 * check_subdomain_takeover category) into the cscComplement payload.
 *
 * Parallel cap 5. Per-apex failures are partial: that apex is omitted from
 * the result, apexesScanned < apexesTotal, stage still reaches 'ready'.
 */

import type { BrandAuditCsc } from '../schemas/brand-audit-csc';

const MAX_APEXES = 25;
const PARALLEL_CAP = 5;
const SAMPLE_SUBDOMAIN_CAP = 10;

type InternalCallFn = (tool: string, args: { domain: string }) => Promise<unknown>;

interface ScanDomainStructured {
	domain: string;
	score: number;
	grade: string;
	categoryScores?: Record<string, { score?: number; findings?: Array<{ severity?: string; category?: string; detail?: string; subdomain?: string }> }>;
	findings?: Array<{ severity?: string; category?: string; detail?: string; subdomain?: string }>;
}

interface DiscoverSubdomainsStructured {
	domain: string;
	totalSubdomains: number;
	subdomains?: Array<{ subdomain?: string; name?: string }>;
}

interface InternalCallEnvelope<T> {
	structured?: T;
	content?: unknown;
}

export interface RunDeepScanInput {
	anchorApex: string;
	apexes: ReadonlyArray<string>;
	internalCall: InternalCallFn;
}

export interface RunDeepScanResult {
	postureSnapshot: BrandAuditCsc['postureSnapshot'];
	deepScan: BrandAuditCsc['deepScan'];
}

async function runWithConcurrency<T, U>(items: ReadonlyArray<T>, limit: number, worker: (item: T) => Promise<U>): Promise<U[]> {
	const results: U[] = new Array(items.length);
	let cursor = 0;
	const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
		while (true) {
			const i = cursor++;
			if (i >= items.length) return;
			results[i] = await worker(items[i]);
		}
	});
	await Promise.all(runners);
	return results;
}

function extractDanglingFromScan(apex: string, scan: ScanDomainStructured | undefined): BrandAuditCsc['deepScan']['danglingDns'] {
	if (!scan) return [];
	const findings = scan.categoryScores?.subdomain_takeover?.findings ?? scan.findings ?? [];
	const dangling: BrandAuditCsc['deepScan']['danglingDns'] = [];
	for (const f of findings) {
		if (f.category !== 'subdomain_takeover') continue;
		const sev = (f.severity ?? 'medium') as 'critical' | 'high' | 'medium' | 'low' | 'info';
		dangling.push({
			subdomain: f.subdomain ?? '',
			apex,
			recordType: 'CNAME',
			target: null,
			takeoverProvider: null,
			severity: sev,
			evidence: f.detail,
		});
	}
	return dangling;
}

function medianGrade(grades: string[]): string | null {
	if (grades.length === 0) return null;
	const sorted = [...grades].sort();
	return sorted[Math.floor(sorted.length / 2)];
}

function distribution(grades: string[]): Record<string, number> {
	const out: Record<string, number> = {};
	for (const g of grades) out[g] = (out[g] ?? 0) + 1;
	return out;
}

/**
 * Deep-scan top-N apexes via injected internalCall. Produces the postureSnapshot
 * + deepScan sections of a cscComplement payload. Per-apex failures degrade the
 * result to partial (apexesScanned < apexesTotal) without aborting siblings.
 */
export async function runDeepScan(input: RunDeepScanInput): Promise<RunDeepScanResult> {
	const apexes = input.apexes.slice(0, MAX_APEXES);

	const perApex = await runWithConcurrency(apexes, PARALLEL_CAP, async (apex) => {
		try {
			const [scanRes, discoverRes] = await Promise.all([
				input.internalCall('scan_domain', { domain: apex }) as Promise<InternalCallEnvelope<ScanDomainStructured>>,
				input.internalCall('discover_subdomains', { domain: apex }) as Promise<InternalCallEnvelope<DiscoverSubdomainsStructured>>,
			]);
			return { apex, scan: scanRes.structured, discover: discoverRes.structured, ok: true };
		} catch {
			return { apex, scan: undefined, discover: undefined, ok: false };
		}
	});

	const postureApexes: BrandAuditCsc['postureSnapshot']['apexes'] = [];
	const dangling: BrandAuditCsc['deepScan']['danglingDns'] = [];
	const inventory: BrandAuditCsc['deepScan']['subdomainInventoryByApex'] = {};
	const grades: string[] = [];

	for (const r of perApex) {
		if (!r.ok || !r.scan) continue;
		postureApexes.push({
			apex: r.apex,
			grade: r.scan.grade,
			score: r.scan.score,
			dmarc: null,
			spf: null,
			dnssec: null,
			dkim: null,
			mtaSts: null,
			scannedAt: new Date().toISOString(),
		});
		grades.push(r.scan.grade);
		const apexDangling = extractDanglingFromScan(r.apex, r.scan);
		dangling.push(...apexDangling);
		if (r.discover) {
			inventory[r.apex] = {
				total: r.discover.totalSubdomains,
				dangling: apexDangling.length,
				source: 'certificate_transparency',
				sample: (r.discover.subdomains ?? []).slice(0, SAMPLE_SUBDOMAIN_CAP).map((s) => s.subdomain ?? s.name ?? '').filter(Boolean),
				partial: false,
			};
		}
	}

	return {
		postureSnapshot: {
			stage: 'ready',
			apexesScanned: postureApexes.length,
			apexesTotal: apexes.length,
			apexes: postureApexes,
			medianGrade: medianGrade(grades),
			distribution: distribution(grades),
		},
		deepScan: {
			stage: 'ready',
			apexesScanned: postureApexes.length,
			apexesTotal: apexes.length,
			danglingDns: dangling,
			danglingDnsTotal: dangling.length,
			subdomainInventoryByApex: inventory,
		},
	};
}
