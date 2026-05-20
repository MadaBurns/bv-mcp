// SPDX-License-Identifier: BUSL-1.1

import type { BrandAuditDepthSummary } from '../../src/lib/brand-audit-depth';
import type { BrandAuditMetricsSummary } from '../../src/lib/brand-audit-metrics';

type ReportBucket = 'consolidated' | 'shadowIt' | 'indeterminate' | 'impersonation' | 'impersonationSurface';
type SourceMode = 'mcp' | 'local';
type DiscoveryMode = 'classic' | 'tiered';
type TierStatus = 'ok' | 'degraded' | 'partial' | 'timeout' | 'skipped';
type DiscoveryTier = 0 | 1 | 2 | 3 | 4;

const BUCKETS: ReportBucket[] = ['consolidated', 'shadowIt', 'indeterminate', 'impersonation', 'impersonationSurface'];
const CLASSIC_BUCKETS: Array<Exclude<ReportBucket, 'impersonationSurface'>> = [
	'consolidated',
	'shadowIt',
	'indeterminate',
	'impersonation',
];
const SIGNAL_LABELS: Record<string, string> = {
	ns: 'NS Match',
	san: 'Cert SAN Match',
	san_recursive: 'Recursive SAN',
	dmarc_rua: 'DMARC RUA Match',
	dkim_key_reuse: 'DKIM Key Match',
	spf_include: 'SPF Include',
	spf_include_seed: 'SPF Seed Include',
	mx_overlap: 'MX Overlap',
	http_redirect: 'HTTP Redirect',
	cname_alignment: 'CNAME Alignment',
	markov_gen: 'Markov Variant',
};

export interface BrandAuditFindingLike {
	category: string;
	title: string;
	severity: string;
	detail: string;
	metadata?: Record<string, unknown>;
}

export interface BrandAuditResultLike {
	category: string;
	passed?: boolean;
	score?: number;
	findings: BrandAuditFindingLike[];
}

export interface DiscoveryReportCandidate {
	domain: string;
	bucket: ReportBucket;
	evidence: string;
	registrar: string;
	registrarSource: string;
	signals: string[];
	combinedConfidence: number | null;
	reasons: string[];
	/** Brand-discovery tier (0..4) — present iff pipeline emitted via tiered mode. */
	tier?: DiscoveryTier;
	/** Lookalike similarity score [0..1] — present on tier-4 impersonation-surface candidates. */
	lookalikeScore?: number;
	/** Score-alert provenance from tier-2 BV_INTEL_GATEWAY observations. */
	scoreAlertContext?: { alertType: string; transition: string };
	/** Tier-1 graph provenance used by report renderers to explain graph-surfaced evidence. */
	graphEvidence?: {
		signalTypes: string[];
		numSharedSignals: number;
		maxSpecificity: number;
		signalType?: string;
		signalValue?: string;
	};
}

/**
 * Classic-mode bucket map (4 keys). The optional tier-4 `impersonationSurface`
 * bucket is split out into `impersonationSurfaceCandidates` so the v1 sidecar's
 * `buckets` block stays byte-identical with the legacy shape.
 */
export type ClassicReportBucket = Exclude<ReportBucket, 'impersonationSurface'>;

export interface DiscoveryReportModel {
	target: string;
	primaryRegistrar: string;
	buckets: Record<ClassicReportBucket, DiscoveryReportCandidate[]>;
	counts: Record<ClassicReportBucket, number>;
	/**
	 * Tier-4 impersonation-surface candidates surfaced by `discovery_mode: 'tiered'`.
	 * Always present (empty in classic mode) — the v3 sidecar reads from here,
	 * the v1 sidecar ignores it (preserves byte-identical legacy output).
	 */
	impersonationSurfaceCandidates: DiscoveryReportCandidate[];
	arrOpportunity: {
		domainCount: number;
		domainRenewals: number;
		managedDns: number;
		securityMonitoring: number;
		total: number;
	};
	dataQuality: {
		unknownRegistrarCandidates: string[];
		redactedRegistrarCandidates: string[];
		notFoundRegistrarCandidates: string[];
		missingBucketCandidates: string[];
	};
	depth: BrandAuditDepthSummary | null;
}

export interface DiscoveryReportSidecarV3OwnedPortfolio {
	tenantDeclared: string[];
	graphSurfaced: string[];
	declaredEvidence: string[];
	inferred: {
		consolidated: string[];
		shadowIt: string[];
		indeterminate: string[];
	};
}

export interface DiscoveryReportSidecarV3ImpersonationEntry {
	domain: string;
	lookalikeScore: number;
	livenessSignals: string[];
	scoreAlertContext?: { alertType: string; transition: string };
}

export interface DiscoveryReportSidecarTiers {
	tier0Count: number;
	tier1Count: number;
	tier2Count: number;
	tier3Count: number;
	tier4Count: number;
	tier0Status: TierStatus;
	tier1Status: TierStatus;
	tier2Status: TierStatus;
	tier3FallbackTriggered: number;
	tier1Freshness?: { overallStaleness: 'fresh' | 'partial' | 'stale' | 'very_stale' };
	optOutsFiltered: number;
}

interface DiscoveryReportSidecarBase {
	target: string;
	auditId: string | null;
	runId: string;
	requestedAt: string;
	sourceMode: SourceMode;
	generatedAt: string;
	depthMode: 'standard' | 'deep';
	freshness: {
		runId: string;
		requestedAt: string;
		jsonGeneratedAt: string;
		pdfGeneratedAt: string;
		sameRun: boolean;
	};
	serverVersion: string;
	primaryRegistrar: string;
	counts: Record<ClassicReportBucket, number>;
	arrOpportunity: DiscoveryReportModel['arrOpportunity'];
	dataQuality: {
		unknownRegistrarCount: number;
		unknownRegistrarCandidates: string[];
		redactedRegistrarCount: number;
		redactedRegistrarCandidates: string[];
		notFoundRegistrarCount: number;
		notFoundRegistrarCandidates: string[];
		registrarSourceCounts: Record<string, number>;
		missingBucketCount: number;
		missingBucketCandidates: string[];
	};
	depth: BrandAuditDepthSummary | null;
	performance?: BrandAuditMetricsSummary;
	buckets: Record<ClassicReportBucket, DiscoveryReportCandidate[]>;
}

/**
 * Classic-mode (v1) sidecar. Byte-identical with the legacy shape — pinned by
 * `test/generate-discovery-report-model.spec.ts:132`.
 */
export interface DiscoveryReportSidecarV1 extends DiscoveryReportSidecarBase {
	qaSchemaVersion: 1;
}

/**
 * Tiered-mode (v3) sidecar. Splits the legacy single `buckets` block into:
 *
 * - `ownedPortfolio` (tier 0/1/2/3): 4 sub-buckets — tenantDeclared (tier 0),
 *   graphSurfaced (tier 1), declaredEvidence (tier 2), inferred (tier 3, with
 *   the legacy three Owned bins consolidated/shadowIt/indeterminate inside).
 * - `impersonationSurface` (tier 4): array of {domain, lookalikeScore,
 *   livenessSignals, scoreAlertContext?} — these never live in the Owned
 *   portfolio (mutual-exclusion enforced by the T8 classifier).
 *
 * `performance.tiers` is required in v3 (BSL invariance: only tiered mode runs
 * tier 0/1/2). `buckets` is preserved for backward-compat readers that haven't
 * migrated yet; they see the classic 4-key shape and can ignore the new keys.
 *
 * Pinned by `test/contracts/brand-report-sidecar-v3.contract.test.ts`.
 */
export interface DiscoveryReportSidecarV3 extends DiscoveryReportSidecarBase {
	qaSchemaVersion: 3;
	discoveryMode: 'tiered';
	ownedPortfolio: DiscoveryReportSidecarV3OwnedPortfolio;
	impersonationSurface: DiscoveryReportSidecarV3ImpersonationEntry[];
	performance: BrandAuditMetricsSummary & { tiers: DiscoveryReportSidecarTiers };
}

export type DiscoveryReportSidecar = DiscoveryReportSidecarV1 | DiscoveryReportSidecarV3;

function graphSignalLabel(signalType: string): string {
	return SIGNAL_LABELS[signalType] ?? signalType.toUpperCase().replace(/_/g, ' ');
}

export function formatEvidence(
	signals: string[],
	confidence: number | null = null,
	graphEvidence?: DiscoveryReportCandidate['graphEvidence'],
): string {
	if (graphEvidence) {
		const labels = graphEvidence.signalTypes.map(graphSignalLabel);
		const base = labels.length > 0 ? `Tier 1 Graph: ${labels.join(', ')}` : 'Tier 1 Graph';
		const specificity = `specificity ${graphEvidence.maxSpecificity.toFixed(2)}`;
		const sharedSignals = `shared signals ${graphEvidence.numSharedSignals}`;
		return confidence === null
			? `${base}; ${specificity}; ${sharedSignals}`
			: `${base}; ${specificity}; ${sharedSignals} (${confidence.toFixed(2)})`;
	}
	const labels = signals.map((signal) => SIGNAL_LABELS[signal] ?? signal.toUpperCase().replace(/_/g, ' '));
	const base = labels.length > 0 ? labels.join(', ') : 'No shared infrastructure';
	return confidence === null ? base : `${base} (${confidence.toFixed(2)})`;
}

function isBucket(value: unknown): value is ReportBucket {
	return typeof value === 'string' && (BUCKETS as string[]).includes(value);
}

function stringArray(value: unknown): string[] {
	return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function numberOrNull(value: unknown): number | null {
	return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function depthSummary(value: unknown): BrandAuditDepthSummary | null {
	if (!isRecord(value)) return null;
	if (!isRecord(value.candidateUniverse) || !isRecord(value.signalCoverage) || !isRecord(value.registrarCoverage)) return null;
	if (!Array.isArray(value.warnings)) return null;
	return value as unknown as BrandAuditDepthSummary;
}

function isTier(value: unknown): value is DiscoveryTier {
	return value === 0 || value === 1 || value === 2 || value === 3 || value === 4;
}

function scoreAlertContext(value: unknown): { alertType: string; transition: string } | undefined {
	if (!isRecord(value)) return undefined;
	if (typeof value.alertType !== 'string' || typeof value.transition !== 'string') return undefined;
	return { alertType: value.alertType, transition: value.transition };
}

function graphEvidence(value: unknown): DiscoveryReportCandidate['graphEvidence'] | undefined {
	if (!isRecord(value)) return undefined;
	const signalTypes = stringArray(value.signalTypes);
	const numSharedSignals = numberOrNull(value.numSharedSignals);
	const maxSpecificity = numberOrNull(value.maxSpecificity);
	if (signalTypes.length === 0 || numSharedSignals === null || maxSpecificity === null) return undefined;
	return {
		signalTypes,
		numSharedSignals,
		maxSpecificity,
		...(typeof value.signalType === 'string' ? { signalType: value.signalType } : {}),
		...(typeof value.signalValue === 'string' ? { signalValue: value.signalValue } : {}),
	};
}

export function buildDiscoveryReportModel(input: {
	target: string;
	primaryRegistrar: string;
	result: BrandAuditResultLike;
}): DiscoveryReportModel {
	const buckets: Record<ClassicReportBucket, DiscoveryReportCandidate[]> = {
		consolidated: [],
		shadowIt: [],
		indeterminate: [],
		impersonation: [],
	};
	const impersonationSurfaceCandidates: DiscoveryReportCandidate[] = [];
	const missingBucketCandidates: string[] = [];

	for (const finding of input.result.findings) {
		const metadata = finding.metadata;
		if (!metadata || typeof metadata.candidate !== 'string') continue;

		const rawBucket = metadata.bucket;
		const signals = stringArray(metadata.signals);
		const combinedConfidence = numberOrNull(metadata.combinedConfidence);
		const registrar = typeof metadata.registrar === 'string' && metadata.registrar.length > 0 ? metadata.registrar : 'Unknown';
		const registrarSource =
			typeof metadata.registrarSource === 'string' && metadata.registrarSource.length > 0
				? metadata.registrarSource
				: 'unknown';
		const candidateGraphEvidence = graphEvidence(metadata.graphEvidence);

		// `impersonationSurface` is tier-4 only; route it to the dedicated list so
		// the v1 sidecar's 4-key `buckets` block stays byte-identical.
		if (rawBucket === 'impersonationSurface') {
			impersonationSurfaceCandidates.push({
			domain: metadata.candidate,
			bucket: 'impersonationSurface',
			evidence: formatEvidence(signals, combinedConfidence, candidateGraphEvidence),
				registrar,
				registrarSource,
				signals,
				combinedConfidence,
				reasons: stringArray(metadata.reasons),
				...(isTier(metadata.tier) ? { tier: metadata.tier } : {}),
				...(typeof metadata.lookalikeScore === 'number' ? { lookalikeScore: metadata.lookalikeScore } : {}),
				...(scoreAlertContext(metadata.scoreAlertContext)
					? { scoreAlertContext: scoreAlertContext(metadata.scoreAlertContext) }
					: {}),
				...(candidateGraphEvidence ? { graphEvidence: candidateGraphEvidence } : {}),
			});
			continue;
		}

		const bucket: ClassicReportBucket =
			isBucket(rawBucket) && rawBucket !== 'impersonationSurface' ? (rawBucket as ClassicReportBucket) : 'indeterminate';
		if (!isBucket(rawBucket)) missingBucketCandidates.push(metadata.candidate);

		buckets[bucket].push({
			domain: metadata.candidate,
			bucket,
			evidence: formatEvidence(signals, combinedConfidence, candidateGraphEvidence),
			registrar,
			registrarSource,
			signals,
			combinedConfidence,
			reasons: stringArray(metadata.reasons),
			...(isTier(metadata.tier) ? { tier: metadata.tier } : {}),
			...(typeof metadata.lookalikeScore === 'number' ? { lookalikeScore: metadata.lookalikeScore } : {}),
			...(candidateGraphEvidence ? { graphEvidence: candidateGraphEvidence } : {}),
		});
	}

	const counts: Record<ClassicReportBucket, number> = {
		consolidated: buckets.consolidated.length,
		shadowIt: buckets.shadowIt.length,
		indeterminate: buckets.indeterminate.length,
		impersonation: buckets.impersonation.length,
	};
	const domainRenewals = counts.shadowIt * 150;
	const managedDns = counts.shadowIt * 2000;
	const securityMonitoring = counts.shadowIt * 1200;
	const allCandidates = [...CLASSIC_BUCKETS.flatMap((bucket) => buckets[bucket]), ...impersonationSurfaceCandidates];
	const unknownRegistrarCandidates = allCandidates
		.filter((candidate) => candidate.registrar === 'Unknown' || candidate.registrarSource === 'unknown')
		.map((candidate) => candidate.domain);
	const redactedRegistrarCandidates = allCandidates
		.filter((candidate) => candidate.registrarSource === 'redacted')
		.map((candidate) => candidate.domain);
	const notFoundRegistrarCandidates = allCandidates
		.filter((candidate) => candidate.registrarSource === 'notfound')
		.map((candidate) => candidate.domain);
	const summary = input.result.findings.find((finding) => finding.metadata?.summary === true);

	return {
		target: input.target,
		primaryRegistrar: input.primaryRegistrar,
		buckets,
		counts,
		impersonationSurfaceCandidates,
		arrOpportunity: {
			domainCount: counts.shadowIt,
			domainRenewals,
			managedDns,
			securityMonitoring,
			total: domainRenewals + managedDns + securityMonitoring,
		},
		dataQuality: {
			unknownRegistrarCandidates,
			redactedRegistrarCandidates,
			notFoundRegistrarCandidates,
			missingBucketCandidates,
		},
		depth: depthSummary(summary?.metadata?.depth),
	};
}

export function buildDiscoveryReportSidecar(
	model: DiscoveryReportModel,
	options: {
		auditId?: string | null;
		sourceMode: SourceMode;
		generatedAt: string;
		serverVersion: string;
		runId: string;
		requestedAt: string;
		depthMode: 'standard' | 'deep';
		performance?: BrandAuditMetricsSummary;
		/**
		 * Discovery mode threaded through from the pipeline. `'tiered'` emits the
		 * v3 sidecar (split portfolio + impersonation surface + `performance.tiers`).
		 * `'classic'` (default, omit) emits the v1 sidecar byte-identical with the
		 * legacy shape.
		 */
		discoveryMode?: DiscoveryMode;
		/**
		 * Per-tier counters + statuses for the v3 sidecar's `performance.tiers`
		 * block. Required when `discoveryMode === 'tiered'`; ignored otherwise.
		 * Pipeline forwards from `discoveryPerformance.tiers` (only populated in
		 * tiered mode — BSL invariance).
		 */
		tiers?: DiscoveryReportSidecarTiers;
	},
): DiscoveryReportSidecar {
	const allClassicCandidates = CLASSIC_BUCKETS.flatMap((bucket) => model.buckets[bucket]);
	const allCandidates = [...allClassicCandidates, ...model.impersonationSurfaceCandidates];
	const registrarSourceCounts: Record<string, number> = {
		rdap: 0,
		whois: 0,
		redacted: 0,
		notfound: 0,
		unknown: 0,
	};
	for (const candidate of allCandidates) {
		registrarSourceCounts[candidate.registrarSource] = (registrarSourceCounts[candidate.registrarSource] ?? 0) + 1;
	}
	const base: DiscoveryReportSidecarBase = {
		target: model.target,
		auditId: options.auditId ?? null,
		runId: options.runId,
		requestedAt: options.requestedAt,
		sourceMode: options.sourceMode,
		generatedAt: options.generatedAt,
		depthMode: options.depthMode,
		freshness: {
			runId: options.runId,
			requestedAt: options.requestedAt,
			jsonGeneratedAt: options.generatedAt,
			pdfGeneratedAt: options.generatedAt,
			sameRun: true,
		},
		serverVersion: options.serverVersion,
		primaryRegistrar: model.primaryRegistrar,
		counts: model.counts,
		arrOpportunity: model.arrOpportunity,
		dataQuality: {
			unknownRegistrarCount: model.dataQuality.unknownRegistrarCandidates.length,
			unknownRegistrarCandidates: model.dataQuality.unknownRegistrarCandidates,
			redactedRegistrarCount: model.dataQuality.redactedRegistrarCandidates.length,
			redactedRegistrarCandidates: model.dataQuality.redactedRegistrarCandidates,
			notFoundRegistrarCount: model.dataQuality.notFoundRegistrarCandidates.length,
			notFoundRegistrarCandidates: model.dataQuality.notFoundRegistrarCandidates,
			registrarSourceCounts,
			missingBucketCount: model.dataQuality.missingBucketCandidates.length,
			missingBucketCandidates: model.dataQuality.missingBucketCandidates,
		},
		depth: model.depth,
		...(options.performance === undefined ? {} : { performance: options.performance }),
		buckets: model.buckets,
	};

	if (options.discoveryMode === 'tiered') {
		// v3 sidecar: split owned portfolio + impersonation surface. `performance`
		// is required (T9 contract) and gains a `tiers` block.
		const ownedPortfolio = splitOwnedPortfolio(model);
		const impersonationSurface = model.impersonationSurfaceCandidates.map((c) => ({
			domain: c.domain,
			lookalikeScore: c.lookalikeScore ?? 0,
			livenessSignals: c.signals.slice(),
			...(c.scoreAlertContext ? { scoreAlertContext: c.scoreAlertContext } : {}),
		}));
		// Defensive: v3 requires tiers. If a caller forgets, fall back to zeros
		// + 'skipped' statuses so the schema parse fails LOUDLY at the caller's
		// contract test instead of silently emitting a v1-with-extra-keys hybrid.
		const tiersBlock: DiscoveryReportSidecarTiers = options.tiers ?? {
			tier0Count: 0,
			tier1Count: 0,
			tier2Count: 0,
			tier3Count: 0,
			tier4Count: 0,
			tier0Status: 'skipped',
			tier1Status: 'skipped',
			tier2Status: 'skipped',
			tier3FallbackTriggered: 0,
			optOutsFiltered: 0,
		};
		const performanceForV3: BrandAuditMetricsSummary & { tiers: DiscoveryReportSidecarTiers } = options.performance
			? { ...options.performance, tiers: tiersBlock }
			: {
					elapsedMs: 0,
					steps: [],
					stepStatusCounts: {},
					dns: { queries: 0, cacheHits: 0, errors: 0, cacheHitRatio: 0 },
					rdap: { queries: 0, cacheHits: 0, errors: 0, cacheHitRatio: 0 },
					warnings: [],
					tiers: tiersBlock,
				};
		const sidecarV3: DiscoveryReportSidecarV3 = {
			...base,
			qaSchemaVersion: 3,
			discoveryMode: 'tiered',
			ownedPortfolio,
			impersonationSurface,
			performance: performanceForV3,
		};
		return sidecarV3;
	}

	// v1 (classic) — byte-identical with the legacy shape. No new keys.
	const sidecarV1: DiscoveryReportSidecarV1 = {
		...base,
		qaSchemaVersion: 1,
	};
	return sidecarV1;
}

/**
 * Partition `model.buckets` into the v3 four-key ownedPortfolio shape using the
 * per-candidate `tier` field stamped by the pipeline. Tiered-mode pipeline
 * stamps `tier ∈ {0,1,2}` on consolidated candidates whose ownership routed via
 * the T8 tier short-circuit; un-tagged consolidated candidates fall through to
 * `inferred.consolidated` (tier-3 legacy classifier path).
 */
function splitOwnedPortfolio(model: DiscoveryReportModel): DiscoveryReportSidecarV3OwnedPortfolio {
	const tenantDeclared: string[] = [];
	const graphSurfaced: string[] = [];
	const declaredEvidence: string[] = [];
	const inferredConsolidated: string[] = [];
	for (const c of model.buckets.consolidated) {
		if (c.tier === 0) tenantDeclared.push(c.domain);
		else if (c.tier === 1) graphSurfaced.push(c.domain);
		else if (c.tier === 2) declaredEvidence.push(c.domain);
		else inferredConsolidated.push(c.domain); // tier 3 (legacy infra/signal classifier)
	}
	return {
		tenantDeclared,
		graphSurfaced,
		declaredEvidence,
		inferred: {
			consolidated: inferredConsolidated,
			shadowIt: model.buckets.shadowIt.map((c) => c.domain),
			indeterminate: model.buckets.indeterminate.map((c) => c.domain),
		},
	};
}
