// SPDX-License-Identifier: BUSL-1.1

import type { BrandAuditDepthSummary } from '../../src/lib/brand-audit-depth';
import type { BrandAuditMetricsSummary } from '../../src/lib/brand-audit-metrics';

type ReportBucket = 'consolidated' | 'shadowIt' | 'indeterminate' | 'impersonation';
type SourceMode = 'mcp' | 'local';

const BUCKETS: ReportBucket[] = ['consolidated', 'shadowIt', 'indeterminate', 'impersonation'];
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
}

export interface DiscoveryReportModel {
	target: string;
	primaryRegistrar: string;
	buckets: Record<ReportBucket, DiscoveryReportCandidate[]>;
	counts: Record<ReportBucket, number>;
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

export interface DiscoveryReportSidecar {
	qaSchemaVersion: 1;
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
	counts: Record<ReportBucket, number>;
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
	buckets: Record<ReportBucket, DiscoveryReportCandidate[]>;
}

export function formatEvidence(signals: string[], confidence: number | null = null): string {
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

export function buildDiscoveryReportModel(input: {
	target: string;
	primaryRegistrar: string;
	result: BrandAuditResultLike;
}): DiscoveryReportModel {
	const buckets: Record<ReportBucket, DiscoveryReportCandidate[]> = {
		consolidated: [],
		shadowIt: [],
		indeterminate: [],
		impersonation: [],
	};
	const missingBucketCandidates: string[] = [];

	for (const finding of input.result.findings) {
		const metadata = finding.metadata;
		if (!metadata || typeof metadata.candidate !== 'string') continue;

		const bucket = isBucket(metadata.bucket) ? metadata.bucket : 'indeterminate';
		if (!isBucket(metadata.bucket)) missingBucketCandidates.push(metadata.candidate);

		const signals = stringArray(metadata.signals);
		const combinedConfidence = numberOrNull(metadata.combinedConfidence);
		buckets[bucket].push({
			domain: metadata.candidate,
			bucket,
			evidence: formatEvidence(signals, combinedConfidence),
			registrar: typeof metadata.registrar === 'string' && metadata.registrar.length > 0 ? metadata.registrar : 'Unknown',
			registrarSource: typeof metadata.registrarSource === 'string' && metadata.registrarSource.length > 0 ? metadata.registrarSource : 'unknown',
			signals,
			combinedConfidence,
			reasons: stringArray(metadata.reasons),
		});
	}

	const counts: Record<ReportBucket, number> = {
		consolidated: buckets.consolidated.length,
		shadowIt: buckets.shadowIt.length,
		indeterminate: buckets.indeterminate.length,
		impersonation: buckets.impersonation.length,
	};
	const domainRenewals = counts.shadowIt * 150;
	const managedDns = counts.shadowIt * 2000;
	const securityMonitoring = counts.shadowIt * 1200;
	const allCandidates = BUCKETS.flatMap((bucket) => buckets[bucket]);
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
	},
): DiscoveryReportSidecar {
	const allCandidates = BUCKETS.flatMap((bucket) => model.buckets[bucket]);
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
	return {
		qaSchemaVersion: 1,
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
}
