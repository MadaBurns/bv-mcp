// SPDX-License-Identifier: BUSL-1.1

import { buildCheckResult, createFinding, type CheckResult, type Finding, type Severity } from './scoring';
import { buildBrandAuditDepthSummary, type BrandAuditDepthInput, type CandidateUniverseDepth } from './brand-audit-depth';
import { summarizeBrandAuditMetrics, type BrandAuditStepTiming } from './brand-audit-metrics';
import { mapConcurrent } from './map-concurrent';
import {
	classifyCandidate,
	normalizeRegistrar,
	type Bucket,
	type CandidateInput,
	type Classification,
	type RegistrarSource,
	type TargetContext,
} from './brand-classification';
import { validateSprawlItem } from './sprawl-invariants';
import { evaluateDefensiveRegistration } from './brand-defensive-registration';
import type { BrandEvidenceObservation } from './brand-evidence';
import {
	discoverBrandDomains as defaultDiscoverBrandDomains,
	type BrandDiscoveryProgressEvent,
} from '../tools/discover-brand-domains';
import { checkRdapLookup as defaultCheckRdapLookup, type RdapCheckOptions } from '../tools/check-rdap-lookup';
import type { BrandAuditStepStore } from './brand-audit-step-store';
import type { Tier0Result } from './brand-tier0-enterprise';
import type { Tier1Result } from './brand-tier1-graph';
import type { Tier2Result } from './brand-tier2-evidence';

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
	// Task 8 — impersonationSurface is emitted only in tier-aware (tiered) mode.
	// The classic pipeline below does not currently feed tier-tagged observations
	// to the classifier, so this branch is unreachable today; the entry exists to
	// keep the exhaustive `Record<Bucket, Severity>` typecheck green now that
	// `Bucket` includes the impersonation-surface variant.
	impersonationSurface: 'high',
};

const STRONG_REGISTRAR_INDEPENDENT_SIGNALS = new Set(['san', 'ns', 'dkim_key_reuse']);

export interface BrandAuditPipelineOptions {
	/** Output format hint. The orchestrator always returns the full CheckResult; the formatter chooses what to surface. */
	format?: 'json' | 'markdown' | 'both';
	/** Minimum combined confidence threshold passed through to `discoverBrandDomains`. */
	min_confidence?: number;
	/** Discovery depth. `deep` expands deterministic candidate seeding. */
	depth?: 'standard' | 'deep';
	/** Planner mode for staged discovery fanout. */
	planner_mode?: 'off' | 'observe' | 'enforce';
	/**
	 * Discovery mode threaded through to `discoverBrandDomains`. Default
	 * `'classic'` preserves byte-identical legacy behavior; `'tiered'` enables
	 * Tier 0/1/2 lookups in front of the legacy sweep (BSL boundary — public
	 * default never flips).
	 */
	discovery_mode?: 'classic' | 'tiered';
	/**
	 * T13 — BlackVeil-production runtime environment overrides.
	 *
	 * `BRAND_AUDIT_DISCOVERY_MODE_DEFAULT === 'tiered'` flips the *runtime
	 * default* discovery mode to `'tiered'` when the caller omits
	 * `discovery_mode`. Unset, missing, or any other value → the public schema
	 * default (`'classic'`) wins, preserving the BSL boundary for self-hosted
	 * deployments. The env var is only set in the private wrangler overlay
	 * (`.dev/wrangler.deploy.jsonc`); the public `wrangler.jsonc` never carries
	 * it. An explicit caller-supplied `discovery_mode` always wins regardless
	 * of env.
	 */
	env?: {
		BRAND_AUDIT_DISCOVERY_MODE_DEFAULT?: string;
	};
	/** Public brand aliases, product labels, or legal-entity labels to seed. */
	brand_aliases?: string[];
	/** Caller-supplied candidate domains to corroborate. */
	candidate_domains?: string[];
	/** Stable audit identifier used for resumable step persistence. */
	auditId?: string;
	/** Optional persisted step store. Omit for one-shot in-memory execution. */
	stepStore?: BrandAuditStepStore;
	/** Epoch-ms deadline for returning a partial result before queue/runtime timeout. */
	deadlineMs?: number;
	/**
	 * Abort signal that interrupts the orchestrator at phase boundaries. The
	 * consumer wires this to a wall-clock timeout (240s of the 300s Worker
	 * budget) so the pipeline can flip the row to `failed` from this same
	 * Worker invocation instead of leaving it stuck in `running` for a cron
	 * reaper to mop up.
	 */
	signal?: AbortSignal;
	/**
	 * Skip all step-store cache reads — the pipeline re-runs discovery,
	 * registrar enrichment, and classification fresh. Phase 2b retry messages
	 * set this so the second pass actually re-fetches RDAP/WHOIS instead of
	 * reading back the cached lookup_failed result from the first pass.
	 * Mirrors the `force_refresh` knob in scan-domain's `runWithCache()`.
	 */
	force_refresh?: boolean;
	/** Clock override for deterministic tests. */
	now?: () => number;
}

/** Injectable dependencies. Tests pass stubs; production omits these and the module imports win. */
export interface BrandAuditPipelineDeps {
	discoverBrandDomains?: typeof defaultDiscoverBrandDomains;
	checkRdapLookup?: typeof defaultCheckRdapLookup;
	/** Optional service bindings threaded through to the inner tools. */
	certstream?: { fetch: typeof fetch };
	whoisBinding?: { fetch: typeof fetch };
	/**
	 * Tier 0 (tenant-declared portfolio) lookup closure, wrapping the
	 * `BV_ENTERPRISE` service binding. Provided at the production seam in
	 * `src/index.ts`; undefined on BSL self-hosts. Forwarded through to
	 * `discoverBrandDomains` via its `deps` arg.
	 */
	tier0Lookup?: (domain: string) => Promise<Tier0Result>;
	/**
	 * Tier 1 (bv-infrastructure-graph) lookup closure, wrapping the
	 * `BV_INFRA_GRAPH` service binding. Provided at the production seam in
	 * `src/index.ts`; undefined on BSL self-hosts. Forwarded through to
	 * `discoverBrandDomains` via its `deps` arg.
	 */
	tier1Lookup?: (domain: string) => Promise<Tier1Result>;
	/**
	 * Tier 2 (bv-intel-gateway declared-evidence) lookup closure, wrapping the
	 * `BV_INTEL_GATEWAY` RPC service binding. Provided at the production seam
	 * in `src/index.ts`; undefined on BSL self-hosts. Forwarded through to
	 * `discoverBrandDomains` via its `deps` arg.
	 */
	tier2Lookup?: (domain: string) => Promise<Tier2Result>;
}

interface RegistrarLookup {
	registrar: string;
	registrarIanaId: string | null;
	registrarSource: RegistrarSource;
	registrant: string | null;
	/** Set iff registrarSource === 'lookup_failed' — stable token identifying *why*. Consumed by the retry path. */
	registrarFailureReason?: string | null;
}

function registrarDisplayLabel(source: RegistrarSource): string {
	switch (source) {
		case 'lookup_failed':
			return 'Registrar lookup failed';
		case 'redacted':
			return 'Registrar redacted by registry';
		case 'notfound':
			return 'Registrar not found in registry';
		case 'unknown':
			return 'Registrar unavailable';
		case 'rdap':
		case 'whois':
			return 'Registrar unavailable';
	}
}

function isMeaningfulRegistrar(value: unknown): value is string {
	return typeof value === 'string' && value.trim().length > 0 && value.trim().toLowerCase() !== 'unknown';
}

type CandidateRegistrarLookupStatus = 'completed' | 'skipped_deadline' | 'needs_retry';

interface CandidateRegistrarLookup {
	candidate: string;
	lookup: RegistrarLookup;
	status?: CandidateRegistrarLookupStatus;
}

interface RegistrarEnrichmentPayload {
	targetLookup: RegistrarLookup;
	candidates: CandidateRegistrarLookup[];
	partial?: boolean;
	skippedCandidates?: string[];
	rdapQueries?: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function numberRecord(value: unknown): Record<string, number> {
	if (!isRecord(value)) return {};
	const out: Record<string, number> = {};
	for (const [key, raw] of Object.entries(value)) {
		if (typeof raw === 'number' && Number.isFinite(raw)) out[key] = raw;
	}
	return out;
}

function readDiscoveryCandidateUniverse(value: unknown, surfacedFallback: number): CandidateUniverseDepth {
	if (!isRecord(value)) {
		return {
			seeded: surfacedFallback,
			probed: surfacedFallback,
			surfaced: surfacedFallback,
			dropped: {},
			sources: {},
		};
	}
	return {
		seeded: typeof value.seeded === 'number' ? value.seeded : surfacedFallback,
		probed: typeof value.probed === 'number' ? value.probed : surfacedFallback,
		surfaced: typeof value.surfaced === 'number' ? value.surfaced : surfacedFallback,
		dropped: numberRecord(value.dropped),
		sources: numberRecord(value.sources),
	};
}

function readDiscoverySignalStatus(value: unknown): Record<string, { status: string; error?: string }> {
	if (!isRecord(value)) return {};
	const out: Record<string, { status: string; error?: string }> = {};
	for (const [signal, raw] of Object.entries(value)) {
		if (!isRecord(raw) || typeof raw.status !== 'string') continue;
		out[signal] = {
			status: raw.status,
			...(typeof raw.error === 'string' ? { error: raw.error } : {}),
		};
	}
	return out;
}

function readDiscoveryPlannerEfficiency(value: unknown): BrandAuditDepthInput['plannerEfficiency'] | undefined {
	if (!isRecord(value) || !isRecord(value.efficiency)) return undefined;
	const { efficiency } = value;
	const plannerMode = efficiency.plannerMode;
	if (plannerMode !== 'off' && plannerMode !== 'observe' && plannerMode !== 'enforce') return undefined;
	const candidateSignalProbes = efficiency.candidateSignalProbes;
	const baselineCandidateSignalProbes = efficiency.baselineCandidateSignalProbes;
	const surfacedCandidates = efficiency.surfacedCandidates;
	if (
		typeof candidateSignalProbes !== 'number' ||
		typeof baselineCandidateSignalProbes !== 'number' ||
		typeof surfacedCandidates !== 'number'
	) {
		return undefined;
	}
	const planner = isRecord(value.planner) ? value.planner : null;
	const wouldProbeBySignal = readNumericRecord(planner?.wouldProbeBySignal);
	const wouldDropBySignal = readNumericRecord(planner?.wouldDropBySignal);
	return {
		mode: plannerMode,
		candidateSignalProbes,
		baselineCandidateSignalProbes,
		surfacedCandidates,
		...(wouldProbeBySignal ? { wouldProbeBySignal } : {}),
		...(wouldDropBySignal ? { wouldDropBySignal } : {}),
	};
}

function readNumericRecord(value: unknown): Record<string, number> | undefined {
	if (!isRecord(value)) return undefined;
	const out: Record<string, number> = {};
	for (const [key, raw] of Object.entries(value)) {
		if (typeof raw === 'number' && Number.isFinite(raw)) out[key] = raw;
	}
	return Object.keys(out).length > 0 ? out : undefined;
}

function readEvidenceObservations(value: unknown): BrandEvidenceObservation[] | undefined {
	if (!Array.isArray(value)) return undefined;
	const observations: BrandEvidenceObservation[] = [];
	for (const raw of value) {
		if (!isRecord(raw) || typeof raw.signal !== 'string') continue;
		// Discovery emits per-observation tier + specificityScore INSIDE `metadata`
		// (see discover-brand-domains.ts:805 — Tier 1 stores them on the obs
		// metadata blob). The T8 classifier expects them as top-level fields on
		// the observation. Hoist on read so the tier short-circuit in
		// `classifyCandidate()` actually fires for tiered-mode runs — without this
		// hoist, `anyTierTagged` is always false and the `impersonationSurface`
		// bucket (plus the consolidated tier 0/1/2 routes) never fire from real
		// pipeline output, only from unit-test fixtures.
		const md = isRecord(raw.metadata) ? raw.metadata : undefined;
		const tier =
			md && (md.tier === 0 || md.tier === 1 || md.tier === 2 || md.tier === 3 || md.tier === 4)
				? (md.tier as 0 | 1 | 2 | 3 | 4)
				: undefined;
		const specificityScore = md && typeof md.specificityScore === 'number' ? md.specificityScore : undefined;
		observations.push({
			signal: raw.signal as BrandEvidenceObservation['signal'],
			...(typeof raw.confidence === 'number' ? { confidence: raw.confidence } : {}),
			...(md ? { metadata: md } : {}),
			...(tier !== undefined ? { tier } : {}),
			...(specificityScore !== undefined ? { specificityScore } : {}),
		});
	}
	return observations.length > 0 ? observations : undefined;
}

/** Per-tier counters + statuses surfaced by tiered-mode discovery. */
export interface BrandAuditTierStats {
	tier0Count: number;
	tier1Count: number;
	tier2Count: number;
	tier3Count: number;
	tier4Count: number;
	tier0Status: 'ok' | 'degraded' | 'partial' | 'timeout' | 'skipped';
	tier1Status: 'ok' | 'degraded' | 'partial' | 'timeout' | 'skipped';
	tier2Status: 'ok' | 'degraded' | 'partial' | 'timeout' | 'skipped';
	tier3FallbackTriggered: number;
	tier1Freshness?: { overallStaleness: 'fresh' | 'partial' | 'stale' | 'very_stale' };
	optOutsFiltered: number;
}

const TIER_STATUSES = new Set(['ok', 'degraded', 'partial', 'timeout', 'skipped']);

function readTierStatus(value: unknown): BrandAuditTierStats['tier0Status'] {
	return typeof value === 'string' && TIER_STATUSES.has(value) ? (value as BrandAuditTierStats['tier0Status']) : 'skipped';
}

/**
 * Read per-tier stats from the discovery summary's `discoveryPerformance.tiers`
 * block. Returns undefined when discovery_mode === 'classic' (BSL invariance —
 * discovery only attaches the tiers block in tiered mode).
 */
function readTierStats(value: unknown): BrandAuditTierStats | undefined {
	if (!isRecord(value) || !isRecord(value.tiers)) return undefined;
	const t = value.tiers;
	let tier1Freshness: BrandAuditTierStats['tier1Freshness'];
	if (
		isRecord(t.tier1Freshness) &&
		(t.tier1Freshness.overallStaleness === 'fresh' ||
			t.tier1Freshness.overallStaleness === 'partial' ||
			t.tier1Freshness.overallStaleness === 'stale' ||
			t.tier1Freshness.overallStaleness === 'very_stale')
	) {
		tier1Freshness = { overallStaleness: t.tier1Freshness.overallStaleness };
	}
	return {
		tier0Count: typeof t.tier0Count === 'number' ? t.tier0Count : 0,
		tier1Count: typeof t.tier1Count === 'number' ? t.tier1Count : 0,
		tier2Count: typeof t.tier2Count === 'number' ? t.tier2Count : 0,
		tier3Count: typeof t.tier3Count === 'number' ? t.tier3Count : 0,
		tier4Count: typeof t.tier4Count === 'number' ? t.tier4Count : 0,
		tier0Status: readTierStatus(t.tier0Status),
		tier1Status: readTierStatus(t.tier1Status),
		tier2Status: readTierStatus(t.tier2Status),
		tier3FallbackTriggered: typeof t.tier3FallbackTriggered === 'number' ? t.tier3FallbackTriggered : 0,
		...(tier1Freshness ? { tier1Freshness } : {}),
		optOutsFiltered: typeof t.optOutsFiltered === 'number' ? t.optOutsFiltered : 0,
	};
}

/** Pluck `{alertType, transition}` from a tier-4 observation's metadata blob (set by Tier-2 evidence). */
function scoreAlertContextFromObservations(
	observations: BrandEvidenceObservation[] | undefined,
): { alertType: string; transition: string } | undefined {
	if (!observations) return undefined;
	for (const obs of observations) {
		if (obs.tier !== 4) continue;
		const md = obs.metadata;
		if (!isRecord(md)) continue;
		if (typeof md.alertType === 'string' && typeof md.transition === 'string') {
			return { alertType: md.alertType, transition: md.transition };
		}
	}
	return undefined;
}

/**
 * Pluck candidate NS hostnames out of evidence observations. The `ns`
 * signal stores its co-ownership match as `sharedNs: string[]` in
 * observation metadata (see `discoverBrandDomains` → ns-correlator). When
 * present we surface it to the defensive-registration heuristic so a
 * candidate parked on `ns1.sedoparking.com` can be labelled even without
 * an additional DNS pass.
 *
 * Returns undefined when no `ns` observation carries `sharedNs` — the
 * heuristic then abstains on this signal.
 *
 * TODO(defensive): wire a candidate MX + HTTP HEAD enrichment pass for
 * label-distance≤2 candidates so the `no-mx` / `redirect-to-target`
 * branches can fire on the user-visible PDF path. Today only the NS
 * route lights up automatically.
 */
function nsHostsFromObservations(observations: BrandEvidenceObservation[] | undefined): string[] | undefined {
	if (!observations) return undefined;
	const hosts: string[] = [];
	for (const obs of observations) {
		if (obs.signal !== 'ns') continue;
		const md = obs.metadata;
		if (!isRecord(md)) continue;
		const shared = md.sharedNs;
		if (!Array.isArray(shared)) continue;
		for (const ns of shared) {
			if (typeof ns === 'string' && ns.length > 0) hosts.push(ns);
		}
	}
	return hosts.length > 0 ? hosts : undefined;
}

function graphEvidenceFromObservations(
	observations: BrandEvidenceObservation[] | undefined,
): { signalTypes: string[]; numSharedSignals: number; maxSpecificity: number; signalType?: string; signalValue?: string } | undefined {
	if (!observations) return undefined;
	for (const obs of observations) {
		if (obs.tier !== 1) continue;
		const md = obs.metadata;
		if (!isRecord(md)) continue;
		const signalTypes = Array.isArray(md.signalTypes)
			? md.signalTypes.filter((value): value is string => typeof value === 'string')
			: [];
		const numSharedSignals = md.numSharedSignals;
		const maxSpecificity = md.maxSpecificity;
		if (signalTypes.length === 0 || typeof numSharedSignals !== 'number' || typeof maxSpecificity !== 'number') continue;
		return {
			signalTypes,
			numSharedSignals,
			maxSpecificity,
			...(typeof md.signalType === 'string' ? { signalType: md.signalType } : {}),
			...(typeof md.signalValue === 'string' ? { signalValue: md.signalValue } : {}),
		};
	}
	return undefined;
}

/** Pull registrar + registrant out of a check-rdap-lookup result, mirroring `scripts/brand-audit-brand-audit.spec.ts:lookupRegistrar`. */
function extractRegistrar(rdap: CheckResult): RegistrarLookup {
	const populated = rdap.findings.find(
		(f) => isMeaningfulRegistrar(f.metadata?.registrar),
	);
	const registrantFinding = rdap.findings.find(
		(f) => typeof f.metadata?.registrant === 'string' && (f.metadata.registrant as string).length > 0,
	);
	const registrant = (registrantFinding?.metadata?.registrant as string | undefined) ?? null;

	if (populated) {
		const source = (populated.metadata?.registrarSource as RegistrarSource | undefined) ?? 'unknown';
		const registrarIanaId = typeof populated.metadata?.registrarIanaId === 'string' ? populated.metadata.registrarIanaId : null;
		const registrarFailureReason =
			source === 'lookup_failed' && typeof populated.metadata?.registrarFailureReason === 'string'
				? populated.metadata.registrarFailureReason
				: null;
		return { registrar: (populated.metadata!.registrar as string).trim(), registrarIanaId, registrarSource: source, registrant, registrarFailureReason };
	}
	const lastWithSource = [...rdap.findings].reverse().find((f) => typeof f.metadata?.registrarSource === 'string');
	const source = (lastWithSource?.metadata?.registrarSource as RegistrarSource | undefined) ?? 'unknown';
	const registrarIanaId = typeof lastWithSource?.metadata?.registrarIanaId === 'string' ? lastWithSource.metadata.registrarIanaId : null;
	const registrarFailureReason =
		source === 'lookup_failed' && typeof lastWithSource?.metadata?.registrarFailureReason === 'string'
			? lastWithSource.metadata.registrarFailureReason
			: null;
	return { registrar: registrarDisplayLabel(source), registrarIanaId, registrarSource: source, registrant, registrarFailureReason };
}

/** Look up registrar + registrant for `domain` via injected checkRdapLookup; fails soft to lookup_failed/exception. */
async function safeRegistrarLookup(domain: string, deps: BrandAuditPipelineDeps, signal?: AbortSignal): Promise<RegistrarLookup> {
	const rdapFn = deps.checkRdapLookup ?? defaultCheckRdapLookup;
	try {
		const opts: RdapCheckOptions = {};
		if (deps.whoisBinding) opts.whoisBinding = deps.whoisBinding;
		if (signal) opts.signal = signal;
		const result = await rdapFn(domain, opts);
		return extractRegistrar(result);
	} catch {
		return {
			registrar: registrarDisplayLabel('lookup_failed'),
			registrarIanaId: null,
			registrarSource: 'lookup_failed',
			registrant: null,
			registrarFailureReason: 'exception',
		};
	}
}

function readCompletedPayload<T>(record: { status: string; payload: unknown } | null): T | null {
	return record?.status === 'completed' ? (record.payload as T) : null;
}

function normalizeDomainKey(domain: string): string {
	return domain.trim().toLowerCase();
}

function unknownRegistrarLookup(): RegistrarLookup {
	return { registrar: registrarDisplayLabel('unknown'), registrarIanaId: null, registrarSource: 'unknown', registrant: null };
}

function hasRegistrarIndependentEvidence(domain: string, seedDomain: string, signals: string[]): boolean {
	return domain === seedDomain || domain.endsWith(`.${seedDomain}`) || signals.some((signal) => STRONG_REGISTRAR_INDEPENDENT_SIGNALS.has(signal));
}

function isRegistrarSource(value: unknown): value is RegistrarSource {
	return (
		value === 'rdap' ||
		value === 'whois' ||
		value === 'redacted' ||
		value === 'notfound' ||
		value === 'lookup_failed' ||
		value === 'unknown'
	);
}

function readRegistrarLookup(value: unknown): RegistrarLookup | null {
	if (!isRecord(value) || typeof value.registrar !== 'string' || !isRegistrarSource(value.registrarSource)) return null;
	const registrant = typeof value.registrant === 'string' ? value.registrant : null;
	const registrarIanaId = typeof value.registrarIanaId === 'string' ? value.registrarIanaId : null;
	const registrarFailureReason =
		value.registrarSource === 'lookup_failed' && typeof value.registrarFailureReason === 'string'
			? value.registrarFailureReason
			: null;
	return { registrar: value.registrar, registrarIanaId, registrarSource: value.registrarSource, registrant, registrarFailureReason };
}

function readCompletedRegistrarEnrichment(
	record: { status: string; payload: unknown } | null,
	candidateDomains: string[],
): RegistrarEnrichmentPayload | null {
	if (record?.status !== 'completed' || !isRecord(record.payload)) return null;
	const targetLookup = readRegistrarLookup(record.payload.targetLookup);
	if (!targetLookup || !Array.isArray(record.payload.candidates)) return null;

	const lookupByCandidate = new Map<string, CandidateRegistrarLookup>();
	for (const raw of record.payload.candidates) {
		if (!isRecord(raw) || typeof raw.candidate !== 'string') continue;
		const lookup = readRegistrarLookup(raw.lookup);
		if (!lookup) continue;
		lookupByCandidate.set(normalizeDomainKey(raw.candidate), { candidate: raw.candidate, lookup });
	}

	const candidates: CandidateRegistrarLookup[] = [];
	for (const candidate of candidateDomains) {
		const entry = lookupByCandidate.get(normalizeDomainKey(candidate));
		if (!entry) return null;
		candidates.push(entry);
	}

	return { targetLookup, candidates };
}

function recordStep(
	steps: BrandAuditStepTiming[],
	name: string,
	status: BrandAuditStepTiming['status'],
	startedAtMs: number,
	finishedAtMs: number,
): void {
	steps.push({ name, status, startedAtMs, finishedAtMs });
}

async function lookupCandidateRegistrars(
	candidateFindings: Finding[],
	deps: BrandAuditPipelineDeps,
	deadlineMs?: number,
	now: () => number = Date.now,
	signal?: AbortSignal,
): Promise<{ candidates: CandidateRegistrarLookup[]; partial: boolean; skippedCandidates: string[]; rdapQueries: number }> {
	const aborted = (): boolean => signal?.aborted === true;
	const statusForLookup = (lookup: RegistrarLookup): CandidateRegistrarLookupStatus =>
		lookup.registrarSource === 'lookup_failed' ? 'needs_retry' : 'completed';

	if (deadlineMs === undefined && !signal) {
		const candidates = await mapConcurrent(candidateFindings, RDAP_CONCURRENCY, async (f) => {
			const candidate = f.metadata!.candidate as string;
			const lookup = await safeRegistrarLookup(candidate, deps, signal);
			return { candidate, lookup, status: statusForLookup(lookup) };
		});
		return { candidates, partial: false, skippedCandidates: [], rdapQueries: candidates.length };
	}

	const candidates: CandidateRegistrarLookup[] = [];
	const skippedCandidates: string[] = [];
	let partial = false;
	for (const finding of candidateFindings) {
		const candidate = finding.metadata!.candidate as string;
		if (aborted() || (deadlineMs !== undefined && now() >= deadlineMs)) {
			partial = true;
			skippedCandidates.push(candidate);
			candidates.push({ candidate, lookup: unknownRegistrarLookup(), status: 'skipped_deadline' });
			continue;
		}
		const lookup = await safeRegistrarLookup(candidate, deps, signal);
		candidates.push({ candidate, lookup, status: statusForLookup(lookup) });
	}

	return {
		candidates,
		partial,
		skippedCandidates,
		rdapQueries: candidates.filter((entry) => entry.status === 'completed' || entry.status === 'needs_retry').length,
	};
}

/**
 * Run a brand audit on a single target.
 *
 * Programmer-error throws (invalid seed domain) propagate from `discoverBrandDomains`.
 * Discovery failures surface as a `missingControl: true` summary finding with zero candidates.
 */
export async function runBrandAuditPipeline(
	target: string,
	options: BrandAuditPipelineOptions = {},
	deps: BrandAuditPipelineDeps = {},
): Promise<CheckResult> {
	const now = options.now ?? Date.now;
	const auditStartedAtMs = now();
	const stepTimings: BrandAuditStepTiming[] = [];
	const seedDomain = target.trim().toLowerCase();
	const auditId = options.auditId ?? `local-${seedDomain}`;
	const stepStore = options.stepStore;
	const signal = options.signal;
	// Phase 2b: retry messages set force_refresh so a transient lookup_failed
	// from the first pass doesn't get served back from the cache.
	const readCachedStep = options.force_refresh ? null : stepStore;
	// T13 — resolve the effective discovery mode.
	// Caller-supplied `discovery_mode` always wins. If the caller omits it,
	// the BlackVeil-production runtime env (`BRAND_AUDIT_DISCOVERY_MODE_DEFAULT`)
	// can flip the default to `'tiered'`. Any other env value (including
	// `undefined`, `'classic'`, or junk) leaves it unset — `discoverBrandDomains`
	// then falls back to the schema default `'classic'`. BSL self-hosters never
	// set this var, so they get classic mode regardless.
	const effectiveDiscoveryMode: 'classic' | 'tiered' | undefined =
		options.discovery_mode ?? (options.env?.BRAND_AUDIT_DISCOVERY_MODE_DEFAULT === 'tiered' ? 'tiered' : undefined);
	const throwIfAborted = (): void => {
		if (signal?.aborted) {
			const reason = (signal as AbortSignal & { reason?: unknown }).reason;
			throw reason instanceof Error ? reason : new Error(typeof reason === 'string' ? reason : 'aborted');
		}
	};

	const cachedClassification = readCompletedPayload<CheckResult>(
		readCachedStep ? await readCachedStep.get(auditId, seedDomain, 'classification') : null,
	);
	if (cachedClassification) return cachedClassification;

	throwIfAborted();
	const cachedDiscovery = readCompletedPayload<CheckResult>(
		readCachedStep ? await readCachedStep.get(auditId, seedDomain, 'discovery') : null,
	);
	let discovery: CheckResult;
	if (cachedDiscovery) {
		const skippedAtMs = now();
		recordStep(stepTimings, 'discovery', 'skipped', skippedAtMs, skippedAtMs);
		discovery = cachedDiscovery;
	} else {
		const discoveryStartedAtMs = now();
		const discover = deps.discoverBrandDomains ?? defaultDiscoverBrandDomains;
		const discoveryTelemetry: BrandDiscoveryProgressEvent[] = [];
		let discoveryTelemetryWrite = Promise.resolve();
		const persistDiscoveryProgress = stepStore
			? (event: BrandDiscoveryProgressEvent): Promise<void> => {
					discoveryTelemetry.push(event);
					const events = discoveryTelemetry.slice();
					discoveryTelemetryWrite = discoveryTelemetryWrite
						.catch(() => undefined)
						.then(() =>
							stepStore.put({
								auditId,
								target: seedDomain,
								step: 'discovery',
								status: 'partial',
								payload: {
									telemetry: {
										events,
										latest: event,
									},
								},
							}),
						);
					return discoveryTelemetryWrite;
				}
			: undefined;
		const discoveryOpts = {
			min_confidence: options.min_confidence,
			depth: options.depth,
			planner_mode: options.planner_mode,
			discovery_mode: effectiveDiscoveryMode,
			brand_aliases: options.brand_aliases,
			candidate_domains: options.candidate_domains,
			certstream: deps.certstream,
			signal,
			deadlineMs: options.deadlineMs,
			onProgress: persistDiscoveryProgress,
		};
		// Forward tier closures via the 3rd `deps` arg. They're `undefined` on
		// BSL self-hosts (`tier_Lookup` keys absent from `deps`); the discoverer
		// falls back to classic-mode behaviour without them. Producing this seam
		// is the wiring half of T7 — the closures themselves are constructed at
		// the production binding sites in `src/index.ts`.
		//
		// `DiscoverBrandDomainsDeps` declares signal stubs as required; the
		// runtime tolerates partials (it merges with internal defaults). Existing
		// callers cast — match that pattern.
		const hasTierDeps = deps.tier0Lookup || deps.tier1Lookup || deps.tier2Lookup;
		const discoveryDeps = {
			...(deps.tier0Lookup ? { tier0Lookup: deps.tier0Lookup } : {}),
			...(deps.tier1Lookup ? { tier1Lookup: deps.tier1Lookup } : {}),
			...(deps.tier2Lookup ? { tier2Lookup: deps.tier2Lookup } : {}),
		} as Parameters<typeof discover>[2];
		discovery = hasTierDeps
			? await discover(seedDomain, discoveryOpts, discoveryDeps)
			: await discover(seedDomain, discoveryOpts);
		throwIfAborted();
		await stepStore?.put({ auditId, target: seedDomain, step: 'discovery', status: 'completed', payload: discovery });
		recordStep(stepTimings, 'discovery', 'completed', discoveryStartedAtMs, now());
	}
	const allCandidateFindings = discovery.findings.filter((f) => typeof f.metadata?.candidate === 'string');
	const discoverySummary = discovery.findings.find((f) => f.metadata?.summary === true);
	const discoverySignalStatus = readDiscoverySignalStatus(discoverySummary?.metadata?.signalStatus);
	const discoveryCandidateUniverse = readDiscoveryCandidateUniverse(
		discoverySummary?.metadata?.candidateUniverse,
		allCandidateFindings.length,
	);
	const discoveryPlannerEfficiency = readDiscoveryPlannerEfficiency(discoverySummary?.metadata?.discoveryPerformance);
	// T9 — per-tier stats from tiered-mode discovery (undefined in classic mode — BSL invariance).
	const tierStats = readTierStats(discoverySummary?.metadata?.discoveryPerformance);
	const truncated = allCandidateFindings.length > MAX_CANDIDATES_PER_AUDIT;
	const candidateFindings = truncated ? allCandidateFindings.slice(0, MAX_CANDIDATES_PER_AUDIT) : allCandidateFindings;

	const candidateDomains = candidateFindings.map((f) => f.metadata!.candidate as string);
	const cachedRegistrarEnrichment = readCompletedRegistrarEnrichment(
		readCachedStep ? await readCachedStep.get(auditId, seedDomain, 'registrar_enrichment') : null,
		candidateDomains,
	);
	let registrarEnrichment: RegistrarEnrichmentPayload;
	if (cachedRegistrarEnrichment) {
		const skippedAtMs = now();
		recordStep(stepTimings, 'registrar_enrichment', 'skipped', skippedAtMs, skippedAtMs);
		registrarEnrichment = cachedRegistrarEnrichment;
	} else {
		throwIfAborted();
		const registrarStartedAtMs = now();
		// Look up the target's own registrar first — drives Rule 4 (same registrar family corroboration).
		const targetLookup = await safeRegistrarLookup(seedDomain, deps, signal);
		const candidateLookups = await lookupCandidateRegistrars(candidateFindings, deps, options.deadlineMs, now, signal);
		registrarEnrichment = {
			targetLookup,
			candidates: candidateLookups.candidates,
			partial: candidateLookups.partial,
			skippedCandidates: candidateLookups.skippedCandidates,
			rdapQueries: 1 + candidateLookups.rdapQueries,
		};
		await stepStore?.put({
			auditId,
			target: seedDomain,
			step: 'registrar_enrichment',
			status: candidateLookups.partial ? 'partial' : 'completed',
			payload: registrarEnrichment,
		});
		recordStep(stepTimings, 'registrar_enrichment', candidateLookups.partial ? 'partial' : 'completed', registrarStartedAtMs, now());
	}
	const { targetLookup } = registrarEnrichment;
	const lookupByCandidate = new Map(
		registrarEnrichment.candidates.map((entry) => [normalizeDomainKey(entry.candidate), entry]),
	);
	const buildPerformance = () =>
		summarizeBrandAuditMetrics({
			startedAtMs: auditStartedAtMs,
			finishedAtMs: now(),
			steps: stepTimings,
			dns: { queries: 0, cacheHits: 0, errors: 0 },
			rdap: { queries: registrarEnrichment.rdapQueries ?? 0, cacheHits: 0, errors: 0 },
		});
	const targetCtx: TargetContext = {
		domain: seedDomain,
		registrar: targetLookup.registrar,
		registrarFamily: normalizeRegistrar(targetLookup.registrar),
		registrarIanaId: targetLookup.registrarIanaId,
		registrant: targetLookup.registrant,
	};

	if (candidateFindings.length === 0) {
		const classificationStartedAtMs = now();
		recordStep(stepTimings, 'classification', 'completed', classificationStartedAtMs, now());
		const performance = buildPerformance();
		const result = buildCheckResult(CATEGORY, [
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
					targetRegistrarIanaId: targetLookup.registrarIanaId,
					targetRegistrarSource: targetLookup.registrarSource,
					...(targetLookup.registrarSource === 'lookup_failed' && targetLookup.registrarFailureReason
						? { targetRegistrarFailureReason: targetLookup.registrarFailureReason }
						: {}),
					targetRegistrant: targetLookup.registrant,
					discoverySignalStatus: discoverySummary?.metadata?.signalStatus,
					performance,
					depth: buildBrandAuditDepthSummary({
						candidateUniverse: discoveryCandidateUniverse,
						signalStatus: discoverySignalStatus,
						registrarSources: [targetLookup.registrarSource],
						performance,
						plannerEfficiency: discoveryPlannerEfficiency,
					}),
					...(tierStats ? { tiers: tierStats } : {}),
					...(effectiveDiscoveryMode === 'tiered' ? { discoveryMode: 'tiered' as const } : {}),
				},
			),
		]);
		await stepStore?.put({ auditId, target: seedDomain, step: 'classification', status: 'completed', payload: result });
		return result;
	}

	const bucketCounts: Record<Bucket, number> = {
		consolidated: 0,
		shadowIt: 0,
		indeterminate: 0,
		impersonation: 0,
		// Task 8 — unreachable in classic-mode pipeline (no tier-tagged obs are
		// produced here); included to satisfy the exhaustive Record typecheck.
		impersonationSurface: 0,
	};
	const classificationStartedAtMs = now();
	const classifiedFindings: Finding[] = candidateFindings.map((f) => {
		const domain = f.metadata!.candidate as string;
		const signals = (f.metadata!.signals as string[]) ?? [];
		const confidence = (f.metadata!.combinedConfidence as number) ?? 0;
		const enrichmentEntry = lookupByCandidate.get(normalizeDomainKey(domain));
		const lookup = enrichmentEntry?.lookup ?? unknownRegistrarLookup();

		// Surface the cross-channel evidence fields the classifier reads for the
		// shadowIt / impersonation branches. The discoverer emits these on the
		// candidate finding's metadata; callers that don't yet populate them get
		// the safe defaults ([], null, 0) and the new branches simply don't fire.
		const md = f.metadata!;
		const sharedTxtVerifications = Array.isArray(md.sharedTxtVerifications)
			? (md.sharedTxtVerifications as string[])
			: [];
		const sharedMxPlatform = typeof md.sharedMxPlatform === 'string' ? (md.sharedMxPlatform as string) : null;
		const lookalikeScore = typeof md.lookalikeScore === 'number' ? (md.lookalikeScore as number) : 0;
		const callerAsserted = Array.isArray(md.candidateSeedSources) && (md.candidateSeedSources as string[]).includes('caller_candidate');
		const evidenceObservations = readEvidenceObservations(md.evidenceObservations);

		const candidate: CandidateInput = {
			domain,
			confidence,
			signals,
			registrar: lookup.registrar,
			registrarIanaId: lookup.registrarIanaId,
			registrarSource: lookup.registrarSource,
			registrant: lookup.registrant,
			sharedTxtVerifications,
			sharedMxPlatform,
			lookalikeScore,
			callerAsserted,
			evidenceObservations,
		};
		let classification: Classification = classifyCandidate(candidate, targetCtx);
		if (enrichmentEntry?.status === 'skipped_deadline' && !hasRegistrarIndependentEvidence(domain, seedDomain, signals)) {
			classification = {
				bucket: 'indeterminate',
				confidenceTier: classification.confidenceTier,
				relationshipType: 'manual_review',
				note: 'Registrar enrichment skipped by deadline',
				reasons: [...classification.reasons, 'registrar enrichment skipped by deadline'],
			};
		}
		// Sprawl quality gate — if the classifier routed to shadowIt /
		// owned_off_primary_registrar, the downstream sidecar will materialise this
		// as a user-visible "Real Shadow IT" claim with $-denominated ARR math
		// (test/helpers/discovery-report-model.ts builds registrarSprawl[] +
		// arrOpportunity from these). The classifier already filters on confidence
		// and signal mix, but nothing further upstream prevents a regression
		// (e.g. classifier-threshold drop, signal-counter bug, registrar lookup
		// degradation) from re-polluting Shadow IT with low-evidence items. Validate
		// the projected sprawl shape against the documented minimum-quality bar
		// (`sprawl-invariants.ts`); anything that fails is downgraded to
		// indeterminate/manual_review the same way enrichment-deadline misses are
		// handled directly above. The note + reasons trail makes the demotion
		// debuggable from the report sidecar.
		if (classification.bucket === 'shadowIt' && classification.relationshipType === 'owned_off_primary_registrar') {
			const projectedSprawlItem = {
				domain,
				bucket: classification.bucket,
				relationshipType: classification.relationshipType,
				// `evidence` is materialised downstream by the sidecar formatter; the
				// pipeline's contract here is the underlying signal/confidence/registrar
				// inputs. Synthesise a stand-in so the validator's `evidence` check
				// passes iff there is at least one signal to render — a sprawl claim
				// with zero signals would already fail the `signals.length >= 2` rule
				// below, making the stand-in a structural placeholder, not data.
				evidence: signals.length > 0 ? signals.join(', ') : '',
				registrar: lookup.registrar,
				registrarSource: lookup.registrarSource,
				signals,
				combinedConfidence: confidence,
				reasons: classification.reasons,
			};
			const sprawlCheck = validateSprawlItem(projectedSprawlItem);
			if (!sprawlCheck.ok) {
				classification = {
					bucket: 'indeterminate',
					confidenceTier: classification.confidenceTier,
					relationshipType: 'manual_review',
					note: `Sprawl invariants failed: ${sprawlCheck.reason}`,
					reasons: [...classification.reasons, `sprawl invariants failed: ${sprawlCheck.reason}`],
				};
			}
		}
		bucketCounts[classification.bucket]++;
		const severity = BUCKET_SEVERITY[classification.bucket];

		const detailParts = [
			`bucket=${classification.bucket}`,
			`confidence=${classification.confidenceTier}`,
			`relationship=${classification.relationshipType}`,
			classification.note ? `note=${classification.note}` : null,
			`registrar=${lookup.registrar} (${lookup.registrarSource})`,
			`signals=[${signals.join(', ')}]`,
			classification.reasons.length > 0 ? `reasons: ${classification.reasons.join('; ')}` : null,
		].filter((p): p is string => p !== null);

		// T9 — stamp tier provenance + impersonation-surface fields on classified
		// findings so the tiered sidecar renderer (and bv-web reader) can split the
		// owned portfolio + render the impersonationSurface[] array without
		// re-parsing observation metadata. `tier`/`scoreAlertContext` are
		// undefined in classic-mode runs (classification.tier never set), so the
		// v1 sidecar block stays byte-identical.
		const scoreAlertCtx =
			classification.bucket === 'impersonationSurface' ? scoreAlertContextFromObservations(evidenceObservations) : undefined;
		const graphEvidence = graphEvidenceFromObservations(evidenceObservations);
		// Defensive-registration label. We do NOT change `classification.bucket`;
		// this is a metadata annotation the renderers consume to mark close-typo
		// candidates with minimal infrastructure (e.g. `brandepsiln.com` parked at
		// sedoparking next to `brandepsilon.com`). Pure data-only call — the
		// heuristic abstains when minimal-infra inputs are absent.
		const candidateNsHosts = nsHostsFromObservations(evidenceObservations);
		const defensiveResult = evaluateDefensiveRegistration({
			candidateDomain: domain,
			targetDomain: seedDomain,
			...(candidateNsHosts ? { nsHosts: candidateNsHosts } : {}),
		});
		return createFinding(CATEGORY, `Brand candidate: ${domain}`, severity, detailParts.join(' — '), {
			candidate: domain,
			bucket: classification.bucket,
			confidenceTier: classification.confidenceTier,
			relationshipType: classification.relationshipType,
			note: classification.note,
			reasons: classification.reasons,
			signals,
			combinedConfidence: confidence,
			registrar: lookup.registrar,
			registrarIanaId: lookup.registrarIanaId,
			registrarSource: lookup.registrarSource,
			...(lookup.registrarSource === 'lookup_failed' && lookup.registrarFailureReason
				? { registrarFailureReason: lookup.registrarFailureReason }
				: {}),
			registrant: lookup.registrant,
			...(enrichmentEntry?.status ? { registrarEnrichmentStatus: enrichmentEntry.status } : {}),
			...(classification.tier !== undefined ? { tier: classification.tier } : {}),
			...(lookalikeScore > 0 ? { lookalikeScore } : {}),
			...(scoreAlertCtx ? { scoreAlertContext: scoreAlertCtx } : {}),
			...(graphEvidence ? { graphEvidence } : {}),
			...(defensiveResult.defensive
				? { defensive: true, ...(defensiveResult.reason ? { defensiveReason: defensiveResult.reason } : {}) }
				: {}),
		});
	});
	recordStep(stepTimings, 'classification', 'completed', classificationStartedAtMs, now());
	const performance = buildPerformance();

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
			...(bucketCounts.impersonationSurface > 0 ? { impersonationSurface: bucketCounts.impersonationSurface } : {}),
			targetRegistrar: targetLookup.registrar,
			targetRegistrarIanaId: targetLookup.registrarIanaId,
			targetRegistrarSource: targetLookup.registrarSource,
			...(targetLookup.registrarSource === 'lookup_failed' && targetLookup.registrarFailureReason
				? { targetRegistrarFailureReason: targetLookup.registrarFailureReason }
				: {}),
			targetRegistrant: targetLookup.registrant,
			minConfidence: options.min_confidence ?? 0.5,
			truncated,
			truncatedAt: truncated ? MAX_CANDIDATES_PER_AUDIT : undefined,
			discoveredTotal: allCandidateFindings.length,
			performance,
			depth: buildBrandAuditDepthSummary({
				candidateUniverse: discoveryCandidateUniverse,
				signalStatus: discoverySignalStatus,
				registrarSources: [targetLookup.registrarSource, ...registrarEnrichment.candidates.map(({ lookup }) => lookup.registrarSource)],
				performance,
				plannerEfficiency: discoveryPlannerEfficiency,
			}),
			// T9 — forward per-tier stats only when discovery_mode === 'tiered'
			// (tierStats === undefined in classic mode — BSL invariance).
			// T13 — env-defaulted tiered runs must stamp `discoveryMode: 'tiered'`
			// identically to explicit-tiered runs so `brand-audit-markdown.ts`
			// (and any other downstream reader keying on this field) treats the
			// report the same way regardless of how the mode was selected.
			...(tierStats ? { tiers: tierStats } : {}),
			...(effectiveDiscoveryMode === 'tiered' ? { discoveryMode: 'tiered' as const } : {}),
		},
	);

	const result = buildCheckResult(CATEGORY, [summary, ...classifiedFindings]);
	await stepStore?.put({ auditId, target: seedDomain, step: 'classification', status: 'completed', payload: result });
	return result;
}
