// SPDX-License-Identifier: BUSL-1.1

/**
 * brand_audit_single — synchronous brand-portfolio audit for a single target.
 *
 * Composes three existing pieces:
 *   1. `discoverBrandDomains` (with all 8 signals by default) — finds candidate
 *      domains plausibly related to the target.
 *   2. `checkRdapLookup` per candidate (concurrency=10) — populates registrar
 *      and registrant for the classifier.
 *   3. `classifyCandidate` — buckets each candidate into one of:
 *        consolidated | shadowIt | indeterminate | impersonation
 *
 * Returns a `CheckResult` with one finding per candidate (bucket carried in
 * metadata + severity) plus a summary finding that aggregates per-bucket counts.
 *
 * Severity-by-bucket mapping (the audit's risk lens, not the discoverer's):
 *   consolidated   → info     (owned/operated by the brand — no action)
 *   indeterminate  → low      (insufficient evidence — review queue)
 *   shadowIt       → medium   (potentially-related, non-aligned ownership)
 *   impersonation  → high     (low confidence + no infra share — likely typo-squat)
 */

import { buildCheckResult, createFinding, type CheckResult, type Finding, type Severity } from '../lib/scoring';
import { discoverBrandDomains as defaultDiscoverBrandDomains } from './discover-brand-domains';
import { checkRdapLookup as defaultCheckRdapLookup } from './check-rdap-lookup';
import {
	classifyCandidate,
	normalizeRegistrar,
	type Bucket,
	type CandidateInput,
	type Classification,
	type RegistrarSource,
	type TargetContext,
} from '../lib/brand-classification';

/**
 * brand-audit findings emit under the existing `brand_discovery` category to
 * avoid adding a new CheckCategory to the scoring union. Adding one shifts the
 * hardening-tier denominator (every domain's perfect-pass score drops by 1)
 * for zero scoring benefit — this tool's value is the bucket classification,
 * not a score contribution. The bucket lives in `metadata.bucket`.
 */
const CATEGORY = 'brand_discovery';

/** Concurrency cap for parallel RDAP lookups across candidates. */
const RDAP_CONCURRENCY = 10;

/**
 * Defensive cap on per-audit candidate count. A pathological discovery output
 * (e.g. a seed that triggers wide crt.sh SAN matches on a multi-tenant CDN)
 * could otherwise fan out to thousands of RDAP fetches. 200 comfortably
 * accommodates the tier-1 brand baseline (~40 candidates per CLAUDE.md's
 * Known Constraints) with 5× headroom; over that, the consumer ack()s with
 * `truncated: true` rather than spending Workers CPU + outbound budget.
 */
const MAX_CANDIDATES_PER_AUDIT = 200;

const BUCKET_SEVERITY: Record<Bucket, Severity> = {
	consolidated: 'info',
	indeterminate: 'low',
	shadowIt: 'medium',
	impersonation: 'high',
};

export interface BrandAuditSingleOptions {
	/** Output format hint. The orchestrator always returns the full CheckResult; the formatter chooses what to surface. */
	format?: 'json' | 'markdown' | 'both';
	/** Minimum combined confidence threshold passed through to `discoverBrandDomains`. */
	min_confidence?: number;
}

/** Quota-check signature — the orchestrator calls this once per audit with `count=1`. */
export type EnforceBrandAuditQuota = (count: number) => Promise<{ allowed: boolean; remaining?: number; limit?: number; retryAfterMs?: number }>;

/** Injectable dependencies. Tests pass stubs; production omits these and the module imports win. */
export interface BrandAuditSingleDeps {
	discoverBrandDomains?: typeof defaultDiscoverBrandDomains;
	checkRdapLookup?: typeof defaultCheckRdapLookup;
	enforceQuota?: EnforceBrandAuditQuota;
	/** Optional service bindings threaded through to the inner tools. */
	certstream?: { fetch: typeof fetch };
	whoisBinding?: { fetch: typeof fetch };
}

interface RegistrarLookup {
	registrar: string;
	registrarSource: RegistrarSource;
	registrant: string | null;
}

/** Pull registrar + registrant out of a check-rdap-lookup result, mirroring `scripts/csc-brand-audit.spec.ts:lookupRegistrar`. */
function extractRegistrar(rdap: CheckResult): RegistrarLookup {
	const populated = rdap.findings.find(
		(f) => typeof f.metadata?.registrar === 'string' && (f.metadata.registrar as string).length > 0,
	);
	const registrantFinding = rdap.findings.find(
		(f) => typeof f.metadata?.registrant === 'string' && (f.metadata.registrant as string).length > 0,
	);
	const registrant = (registrantFinding?.metadata?.registrant as string | undefined) ?? null;

	if (populated) {
		const source = (populated.metadata?.registrarSource as RegistrarSource | undefined) ?? 'unknown';
		return { registrar: populated.metadata!.registrar as string, registrarSource: source, registrant };
	}
	const lastWithSource = [...rdap.findings].reverse().find((f) => typeof f.metadata?.registrarSource === 'string');
	const source = (lastWithSource?.metadata?.registrarSource as RegistrarSource | undefined) ?? 'unknown';
	return { registrar: 'Unknown', registrarSource: source, registrant };
}

/** Run `fn` over `items` with at most `limit` concurrent in-flight. Order preserved in the returned array. */
async function mapConcurrent<T, R>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
	const out: R[] = new Array(items.length);
	let next = 0;
	async function worker() {
		while (true) {
			const i = next++;
			if (i >= items.length) return;
			out[i] = await fn(items[i], i);
		}
	}
	const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, () => worker());
	await Promise.all(workers);
	return out;
}

/** Look up registrar + registrant for `domain` via injected checkRdapLookup; fails soft to Unknown/unknown. */
async function safeRegistrarLookup(domain: string, deps: BrandAuditSingleDeps): Promise<RegistrarLookup> {
	const rdapFn = deps.checkRdapLookup ?? defaultCheckRdapLookup;
	try {
		const result = await rdapFn(domain, deps.whoisBinding ? { whoisBinding: deps.whoisBinding } : {});
		return extractRegistrar(result);
	} catch {
		return { registrar: 'Unknown', registrarSource: 'unknown', registrant: null };
	}
}

/**
 * Run a brand audit on a single target.
 *
 * Programmer-error throws (invalid seed domain) propagate from `discoverBrandDomains`.
 * Discovery failures surface as a `missingControl: true` summary finding with zero candidates.
 */
export async function brandAuditSingle(
	target: string,
	options: BrandAuditSingleOptions = {},
	deps: BrandAuditSingleDeps = {},
): Promise<CheckResult> {
	const enforce = deps.enforceQuota;
	if (enforce) {
		const verdict = await enforce(1);
		if (!verdict.allowed) {
			const retryHint = typeof verdict.retryAfterMs === 'number' ? ` retry after ${Math.ceil(verdict.retryAfterMs / 1000)}s` : '';
			return buildCheckResult(CATEGORY, [
				createFinding(
					CATEGORY,
					'Brand-audit quota exceeded',
					'high',
					`Monthly quota of ${verdict.limit ?? 0} targets reached for this principal.${retryHint}`,
					{ quotaExceeded: true, target, limit: verdict.limit ?? 0, remaining: verdict.remaining ?? 0, retryAfterMs: verdict.retryAfterMs },
				),
			]);
		}
	}

	const seedDomain = target.trim().toLowerCase();
	const discover = deps.discoverBrandDomains ?? defaultDiscoverBrandDomains;
	const discoveryOpts = {
		min_confidence: options.min_confidence,
		certstream: deps.certstream,
	};

	const discovery = await discover(seedDomain, discoveryOpts);
	const allCandidateFindings = discovery.findings.filter((f) => typeof f.metadata?.candidate === 'string');
	const truncated = allCandidateFindings.length > MAX_CANDIDATES_PER_AUDIT;
	const candidateFindings = truncated ? allCandidateFindings.slice(0, MAX_CANDIDATES_PER_AUDIT) : allCandidateFindings;

	// Look up the target's own registrar first — drives Rule 4 (same registrar family corroboration).
	const targetLookup = await safeRegistrarLookup(seedDomain, deps);
	const targetCtx: TargetContext = {
		domain: seedDomain,
		registrar: targetLookup.registrar,
		registrarFamily: normalizeRegistrar(targetLookup.registrar),
		registrant: targetLookup.registrant,
	};

	if (candidateFindings.length === 0) {
		const discoverySummary = discovery.findings.find((f) => f.metadata?.summary === true);
		return buildCheckResult(CATEGORY, [
			createFinding(
				CATEGORY,
				`Brand audit: no candidates surfaced for ${seedDomain}`,
				'info',
				`Discovery returned 0 candidates at confidence ≥ ${options.min_confidence ?? 0.5}. Discovery signalStatus: ${JSON.stringify(discoverySummary?.metadata?.signalStatus ?? {})}.`,
				{
					summary: true,
					missingControl: true,
					target: seedDomain,
					consolidated: 0,
					shadowIt: 0,
					indeterminate: 0,
					impersonation: 0,
					targetRegistrar: targetLookup.registrar,
					targetRegistrarSource: targetLookup.registrarSource,
					targetRegistrant: targetLookup.registrant,
					discoverySignalStatus: discoverySummary?.metadata?.signalStatus,
				},
			),
		]);
	}

	// Look up registrar for every candidate in parallel (bounded).
	const lookups = await mapConcurrent(candidateFindings, RDAP_CONCURRENCY, (f) =>
		safeRegistrarLookup(f.metadata!.candidate as string, deps),
	);

	const bucketCounts: Record<Bucket, number> = { consolidated: 0, shadowIt: 0, indeterminate: 0, impersonation: 0 };
	const classifiedFindings: Finding[] = candidateFindings.map((f, i) => {
		const domain = f.metadata!.candidate as string;
		const signals = (f.metadata!.signals as string[]) ?? [];
		const confidence = (f.metadata!.combinedConfidence as number) ?? 0;
		const lookup = lookups[i];

		const candidate: CandidateInput = {
			domain,
			confidence,
			signals,
			registrar: lookup.registrar,
			registrarSource: lookup.registrarSource,
			registrant: lookup.registrant,
		};
		const classification: Classification = classifyCandidate(candidate, targetCtx);
		bucketCounts[classification.bucket]++;
		const severity = BUCKET_SEVERITY[classification.bucket];

		const detailParts = [
			`bucket=${classification.bucket}`,
			`confidence=${classification.confidenceTier}`,
			classification.note ? `note=${classification.note}` : null,
			`registrar=${lookup.registrar} (${lookup.registrarSource})`,
			`signals=[${signals.join(', ')}]`,
			classification.reasons.length > 0 ? `reasons: ${classification.reasons.join('; ')}` : null,
		].filter((p): p is string => p !== null);

		return createFinding(CATEGORY, `Brand candidate: ${domain}`, severity, detailParts.join(' — '), {
			candidate: domain,
			bucket: classification.bucket,
			confidenceTier: classification.confidenceTier,
			note: classification.note,
			reasons: classification.reasons,
			signals,
			combinedConfidence: confidence,
			registrar: lookup.registrar,
			registrarSource: lookup.registrarSource,
			registrant: lookup.registrant,
		});
	});

	const total = classifiedFindings.length;
	const summary = createFinding(
		CATEGORY,
		`Brand audit: ${total} candidate(s) classified for ${seedDomain}`,
		'info',
		`consolidated=${bucketCounts.consolidated} shadowIt=${bucketCounts.shadowIt} indeterminate=${bucketCounts.indeterminate} impersonation=${bucketCounts.impersonation}`,
		{
			summary: true,
			target: seedDomain,
			total,
			consolidated: bucketCounts.consolidated,
			shadowIt: bucketCounts.shadowIt,
			indeterminate: bucketCounts.indeterminate,
			impersonation: bucketCounts.impersonation,
			targetRegistrar: targetLookup.registrar,
			targetRegistrarSource: targetLookup.registrarSource,
			targetRegistrant: targetLookup.registrant,
			minConfidence: options.min_confidence ?? 0.5,
			truncated,
			truncatedAt: truncated ? MAX_CANDIDATES_PER_AUDIT : undefined,
			discoveredTotal: allCandidateFindings.length,
		},
	);

	return buildCheckResult(CATEGORY, [summary, ...classifiedFindings]);
}
