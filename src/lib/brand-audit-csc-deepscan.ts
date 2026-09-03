// SPDX-License-Identifier: BUSL-1.1

/**
 * Deep-scan orchestrator for CSC-complement view.
 *
 * For each top-N apex (default cap 25), runs scan_domain, discover_subdomains
 * and check_subdomain_takeover via an injected internal-call function.
 * Aggregates per-apex posture (grade/score), subdomain inventory, and
 * dangling-DNS findings into the cscComplement payload.
 *
 * The injected `internalCall` is `handleToolsCall` (see `src/index.ts` — the
 * brand-audit queue consumer's closure), so every response is an MCP tool
 * result: `{ content, structuredContent?, isError? }`. The machine-readable
 * payload lives in **`structuredContent`** — there is no `structured` field on
 * that path. Reading the wrong key yields `undefined` for every apex and the
 * whole deep-scan silently reports zero results, so the envelope shape is
 * pinned by `test/brand-audit-csc-deepscan.spec.ts` against payloads built by
 * the real production builders.
 *
 * Parallel cap 5. Per-apex failures are partial: a failed scan_domain omits
 * that apex (apexesScanned < apexesTotal); a failed discover_subdomains or
 * check_subdomain_takeover only drops that apex's inventory / dangling
 * section. Stage still reaches 'ready'.
 */

import type { BrandAuditCsc } from '../schemas/brand-audit-csc';

const MAX_APEXES = 25;
const PARALLEL_CAP = 5;
const SAMPLE_SUBDOMAIN_CAP = 10;

type InternalCallFn = (tool: string, args: { domain: string }) => Promise<unknown>;

/**
 * The subset of `scan_domain`'s `structuredContent` this orchestrator reads.
 * Mirrors `StructuredScanResult` (`src/tools/scan/format-report.ts`) — note
 * `categoryScores` values are plain numbers (or `null` for N/A categories),
 * and the payload carries **no per-finding array**, only `findingCounts`.
 * Dangling-DNS detail therefore has to come from `check_subdomain_takeover`.
 *
 * `score`/`grade` are nullable: an ungraded scan (zero checks ran, unresolvable
 * zone, scoring-bundle failure) emits `null` rather than a fabricated `0`/`'F'`.
 * This is a hand-written mirror, so widening the real type flags NOTHING here —
 * the abstain gate below has to be maintained by hand against `format-report.ts`.
 */
interface ScanDomainStructured {
	domain: string;
	score: number | null;
	grade: string | null;
	/**
	 * `false` = the scan ran ZERO checks, so whatever `score`/`grade` carry are
	 * placeholders, not measurements. Optional because older/other producers may
	 * omit it — absent is treated as measured, preserving prior behaviour.
	 */
	measured?: boolean;
	categoryScores?: Record<string, number | null>;
}

/** The subset of `discover_subdomains`' `structuredContent` this orchestrator reads. */
interface DiscoverSubdomainsStructured {
	domain: string;
	totalSubdomains: number;
	subdomains?: Array<{ subdomain?: string }>;
	/** Sync-budget tripped mid-pipeline — inventory is incomplete. */
	partial?: boolean;
	/** Certificate Transparency source could not be queried at all. */
	sourceUnavailable?: boolean;
	/**
	 * `'floor'` = recall was cut on that call (a source failed, an index was not
	 * read to the end, or the data is a stale re-serve) — `totalSubdomains` is a
	 * floor, not a count (#866). Absent on older producers → treated as a sample.
	 */
	countBasis?: 'sample' | 'floor';
}

/** A `CheckResult` finding as it appears in `check_subdomain_takeover`'s `structuredContent`. */
interface TakeoverFinding {
	category?: string;
	title?: string;
	severity?: string;
	detail?: string;
	metadata?: Record<string, unknown>;
}

/** The subset of `check_subdomain_takeover`'s `structuredContent` (a `CheckResult`) this orchestrator reads. */
interface SubdomainTakeoverStructured {
	category?: string;
	findings?: TakeoverFinding[];
}

/**
 * MCP tool-call result envelope as returned by `handleToolsCall`.
 * `structuredContent` is the machine-readable channel; `content` is the
 * human-readable text array.
 */
interface InternalCallEnvelope<T> {
	content?: unknown;
	structuredContent?: T;
	isError?: boolean;
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

/**
 * Unwrap one internal tool call. Returns `undefined` when the call rejected,
 * when the tool reported `isError`, or when the tool emitted no
 * `structuredContent` — every one of which is a per-section partial, never a
 * whole-scan abort.
 */
async function callStructured<T>(internalCall: InternalCallFn, tool: string, domain: string): Promise<T | undefined> {
	try {
		const envelope = (await internalCall(tool, { domain })) as InternalCallEnvelope<T> | null | undefined;
		if (!envelope || envelope.isError) return undefined;
		return envelope.structuredContent;
	} catch {
		return undefined;
	}
}

/**
 * Pull the dangling subdomain + CNAME target out of a takeover finding.
 *
 * `Finding` carries no dedicated `subdomain`/`target` field, so the FQDN is
 * recovered from the finding's own text. All three dangling-CNAME producers in
 * `packages/dns-checks/src/checks/subdomain-takeover-analysis.ts` emit one of:
 *   - title  `Dangling CNAME[ (operational drift)]: <fqdn> → <cname>`
 *   - title  `CNAME resolution failed: <fqdn> → <cname>`
 *   - detail `Subdomain <fqdn> points to <cname>, which …`
 *   - detail `Could not resolve CNAME target <cname> for <fqdn>.`
 * `metadata.subdomain` / `metadata.cnameTarget` are preferred if a future
 * package version starts emitting them.
 */
function parseTakeoverTarget(finding: TakeoverFinding): { subdomain: string; target: string | null } | null {
	const meta = finding.metadata ?? {};
	if (typeof meta.subdomain === 'string' && meta.subdomain.length > 0) {
		return { subdomain: meta.subdomain, target: typeof meta.cnameTarget === 'string' ? meta.cnameTarget : null };
	}

	const title = finding.title ?? '';
	const detail = finding.detail ?? '';

	const arrow = title.match(/([A-Za-z0-9._*-]+)\s*(?:→|->)\s*([A-Za-z0-9._-]+)/);
	if (arrow) return { subdomain: arrow[1], target: arrow[2] };

	const pointsTo = detail.match(/Subdomain\s+([A-Za-z0-9._*-]+)\s+points to\s+([A-Za-z0-9._-]+)/);
	if (pointsTo) return { subdomain: pointsTo[1], target: pointsTo[2] };

	const unresolved = detail.match(/Could not resolve CNAME target\s+([A-Za-z0-9._-]+)\s+for\s+([A-Za-z0-9._*-]+)/);
	if (unresolved) return { subdomain: unresolved[2], target: unresolved[1] };

	return null;
}

/** Provider name from a `Subdomain possible takeover signal (<provider>)` title, else null. */
function parseTakeoverProvider(finding: TakeoverFinding): string | null {
	const match = (finding.title ?? '').match(/takeover signal\s*\(([^)]+)\)/i);
	return match ? match[1] : null;
}

const DANGLING_SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);

/**
 * Map `check_subdomain_takeover`'s `CheckResult` findings onto dangling-DNS
 * entries. `info` findings (the "no dangling CNAME records found" all-clear)
 * and findings with no recoverable FQDN are skipped.
 */
function extractDangling(apex: string, takeover: SubdomainTakeoverStructured | undefined): BrandAuditCsc['deepScan']['danglingDns'] {
	if (!takeover) return [];
	const dangling: BrandAuditCsc['deepScan']['danglingDns'] = [];
	for (const f of takeover.findings ?? []) {
		if (f.category !== undefined && f.category !== 'subdomain_takeover') continue;
		const severity = (f.severity ?? 'medium').toLowerCase();
		if (!DANGLING_SEVERITIES.has(severity)) continue;
		const parsed = parseTakeoverTarget(f);
		if (!parsed) continue;
		dangling.push({
			subdomain: parsed.subdomain,
			apex,
			recordType: 'CNAME',
			target: parsed.target,
			takeoverProvider: parseTakeoverProvider(f),
			severity: severity as 'critical' | 'high' | 'medium' | 'low' | 'info',
			evidence: f.detail,
		});
	}
	return dangling;
}

/**
 * The abstain gate for an apex scan, matching the conjunction already used by
 * `batch_scan` and `compare_domains` (`!measured || score === null || grade === null`).
 *
 * Returns all-null rather than a placeholder so an unmeasured apex cannot appear in
 * the customer-visible grade distribution or be sorted into the portfolio median —
 * the retired string sentinel sorted lexically AFTER 'F', so counting it dragged the
 * median to the worst bucket, and a degenerate zero-check scan carries a literal 'A+'.
 */
function gradedApexPosture(scan: ScanDomainStructured): { score: number | null; grade: string | null } {
	if (scan.measured === false || scan.score === null || scan.grade === null) {
		return { score: null, grade: null };
	}
	return { score: scan.score, grade: scan.grade };
}

function medianGrade(grades: Array<string | null>): string | null {
	const present = grades.filter((g): g is string => g !== null);
	if (present.length === 0) return null;
	const sorted = [...present].sort();
	return sorted[Math.floor(sorted.length / 2)];
}

function distribution(grades: Array<string | null>): Record<string, number> {
	const out: Record<string, number> = {};
	for (const g of grades) {
		// An unmeasured apex contributes no grade — counting it would create a
		// literal "null" bucket in the customer-visible distribution.
		if (g === null) continue;
		out[g] = (out[g] ?? 0) + 1;
	}
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
		const [scan, discover, takeover] = await Promise.all([
			callStructured<ScanDomainStructured>(input.internalCall, 'scan_domain', apex),
			callStructured<DiscoverSubdomainsStructured>(input.internalCall, 'discover_subdomains', apex),
			callStructured<SubdomainTakeoverStructured>(input.internalCall, 'check_subdomain_takeover', apex),
		]);
		return { apex, scan, discover, takeover };
	});

	const postureApexes: BrandAuditCsc['postureSnapshot']['apexes'] = [];
	const dangling: BrandAuditCsc['deepScan']['danglingDns'] = [];
	const inventory: BrandAuditCsc['deepScan']['subdomainInventoryByApex'] = {};
	const grades: Array<string | null> = [];

	for (const r of perApex) {
		// scan_domain is the load-bearing call: without a posture there is nothing
		// to report for this apex, so it is omitted entirely (partial result).
		if (!r.scan) continue;
		const posture = gradedApexPosture(r.scan);
		postureApexes.push({
			apex: r.apex,
			grade: posture.grade,
			score: posture.score,
			dmarc: null,
			spf: null,
			dnssec: null,
			dkim: null,
			mtaSts: null,
			scannedAt: new Date().toISOString(),
		});
		grades.push(posture.grade);
		const apexDangling = extractDangling(r.apex, r.takeover);
		dangling.push(...apexDangling);
		if (r.discover) {
			inventory[r.apex] = {
				total: r.discover.totalSubdomains,
				dangling: apexDangling.length,
				source: 'certificate_transparency',
				sample: (r.discover.subdomains ?? [])
					.slice(0, SAMPLE_SUBDOMAIN_CAP)
					.map((s) => s.subdomain ?? '')
					.filter(Boolean),
				// A floor is an incomplete inventory by definition (#866) — publish it as
				// partial rather than as a confident `total`.
				partial: Boolean(r.discover.partial || r.discover.sourceUnavailable || r.discover.countBasis === 'floor'),
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
