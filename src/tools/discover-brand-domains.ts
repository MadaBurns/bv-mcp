// SPDX-License-Identifier: BUSL-1.1

/**
 * Brand-domain discovery orchestrator (Phase-4 unified tool).
 *
 * Aggregates the four phase-4 discovery signals (SAN co-ownership via crt.sh,
 * NS-record correlation, DMARC RUA mining, DKIM key reuse) into a single
 * candidate list with multi-signal corroborated confidence scoring.
 *
 * The four signal modules already live under `src/tenants/discovery/*` and each
 * exposes its own typed result. This wrapper:
 *   1. Runs the requested signals in parallel via `Promise.allSettled`,
 *      so one failing signal doesn't kill the whole tool call.
 *   2. Aggregates per-candidate signals — when the same domain shows up under
 *      multiple signals, its confidence is corroborated, not averaged.
 *   3. Combines confidences via the design doc §2.4 formula:
 *        combined = 1 - prod(1 - signal_confidence)
 *      i.e. independent-events probability that *any* signal is correct.
 *   4. Filters by `min_confidence`, sorts descending, and returns a CheckResult
 *      with one finding per surviving candidate plus a summary finding.
 *
 * Severity policy on the candidate findings:
 *   - `low` for combined_confidence ≥ 0.85 (auto-include / strong signal)
 *   - `info` for everything else (review queue)
 *
 * DNS-failure resilience: if EVERY requested signal throws (or all return
 * empty without any successes), we surface a `missingControl: true` finding
 * mirroring the `check-spf.ts` reference pattern. Partial failures are noted
 * in metadata but don't degrade the rest of the result.
 */

import {
	correlateSans as defaultCorrelateSans,
	correlateNs as defaultCorrelateNs,
	mineDmarcRua as defaultMineDmarcRua,
	detectDkimKeyReuse as defaultDetectDkimKeyReuse,
	type SanCorrelationResult,
	type NsCorrelationResult,
	type DmarcRuaResult,
	type DkimKeyReuseResult,
} from '../tenants/discovery';
import type { OutputFormat } from '../handlers/tool-args';
import { buildCheckResult, createFinding, type CheckResult, type Finding, type Severity } from '../lib/scoring';
import { sanitizeOutputText } from '../lib/output-sanitize';
import { isSubdomainOf } from '../lib/sanitize';

/** All supported signal kinds. */
export type DiscoverSignal = 'san' | 'ns' | 'dmarc_rua' | 'dkim_key_reuse';

/** Default signal set used when the caller omits `signals`. */
const ALL_SIGNALS: DiscoverSignal[] = ['san', 'ns', 'dmarc_rua', 'dkim_key_reuse'];

/** Default cutoff: a candidate must reach this combined-confidence to surface. */
const DEFAULT_MIN_CONFIDENCE = 0.5;

/** Default per-signal confidence used when the underlying module doesn't supply one. */
const DEFAULT_SIGNAL_CONFIDENCE: Record<DiscoverSignal, number> = {
	san: 0.7, // SAN co-ownership — strong but not deterministic (see san-correlator.ts comments)
	ns: 0.8, // NS overlap — confidence comes from the module itself; this is the fallback
	dmarc_rua: 0.6, // matches `dmarc-rua-miner.ts` fixed value for `related` classification
	dkim_key_reuse: 0.95, // matches `dkim-key-reuse.ts` KEY_REUSE_CONFIDENCE
};

/** Threshold above which a candidate is considered auto-include rather than review. */
const AUTO_INCLUDE_THRESHOLD = 0.85;

/** Per-candidate aggregation state during collection. */
interface CandidateAggregator {
	domain: string;
	/** Per-signal confidences observed. Multiple values from the same signal kind are reduced to max(). */
	perSignalConfidence: Map<DiscoverSignal, number>;
	/** Free-form per-signal source notes — surfaced on the finding's metadata for downstream review. */
	sources: Record<string, unknown>;
}

/**
 * Injectable signal-module dependencies. Tests pass stubs; production omits
 * `deps` and the module-level imports are used.
 */
export interface DiscoverBrandDomainsDeps {
	correlateSans: typeof defaultCorrelateSans;
	correlateNs: typeof defaultCorrelateNs;
	mineDmarcRua: typeof defaultMineDmarcRua;
	detectDkimKeyReuse: typeof defaultDetectDkimKeyReuse;
}

/** Tool args shape — the Zod schema lives in `src/schemas/tool-args.ts`. */
export interface DiscoverBrandDomainsOptions {
	signals?: DiscoverSignal[];
	candidate_domains?: string[];
	dkim_selectors?: string[];
	min_confidence?: number;
}

/** Combine independent-event confidences: P(any signal correct). */
function combineConfidences(values: number[]): number {
	if (values.length === 0) return 0;
	let product = 1;
	for (const v of values) {
		const clamped = Math.max(0, Math.min(1, v));
		product *= 1 - clamped;
	}
	return 1 - product;
}

/** Round to 4 decimals for stable test/log output. */
function round4(n: number): number {
	return Math.round(n * 10_000) / 10_000;
}

/** Default deps wiring used when the caller doesn't inject. */
function defaultDeps(): DiscoverBrandDomainsDeps {
	return {
		correlateSans: defaultCorrelateSans,
		correlateNs: defaultCorrelateNs,
		mineDmarcRua: defaultMineDmarcRua,
		detectDkimKeyReuse: defaultDetectDkimKeyReuse,
	};
}

/** Add a per-signal candidate observation to the aggregator. */
function addObservation(
	agg: Map<string, CandidateAggregator>,
	domain: string,
	signal: DiscoverSignal,
	confidence: number,
	sourceNote: unknown,
): void {
	const lower = domain.trim().toLowerCase().replace(/\.$/, '');
	if (!lower) return;
	let entry = agg.get(lower);
	if (!entry) {
		entry = { domain: lower, perSignalConfidence: new Map(), sources: {} };
		agg.set(lower, entry);
	}
	const existing = entry.perSignalConfidence.get(signal);
	if (existing === undefined || confidence > existing) {
		entry.perSignalConfidence.set(signal, confidence);
	}
	entry.sources[signal] = sourceNote;
}

/** Run a single signal handler, swallowing errors into a typed status report. */
type SignalOutcome<R> = { ok: true; value: R } | { ok: false; error: string };

async function runSignal<R>(fn: () => Promise<R>): Promise<SignalOutcome<R>> {
	try {
		const value = await fn();
		return { ok: true, value };
	} catch (err) {
		return { ok: false, error: err instanceof Error ? err.message : String(err) };
	}
}

/**
 * Orchestrate brand-domain discovery across the four phase-4 signals.
 *
 * Programmer-error throws (invalid seed domain) propagate from the underlying
 * modules. All other failure modes are surfaced via `missingControl: true`
 * findings or per-signal status metadata, never thrown.
 */
export async function discoverBrandDomains(
	seedDomain: string,
	options: DiscoverBrandDomainsOptions = {},
	deps?: DiscoverBrandDomainsDeps,
): Promise<CheckResult> {
	const d = deps ?? defaultDeps();
	const signals = (options.signals && options.signals.length > 0 ? options.signals : ALL_SIGNALS).slice();
	const candidateDomains = options.candidate_domains ?? [];
	const dkimSelectors = options.dkim_selectors;
	const minConfidence = typeof options.min_confidence === 'number'
		? Math.max(0, Math.min(1, options.min_confidence))
		: DEFAULT_MIN_CONFIDENCE;

	// Pre-validate seed via the SAN correlator's strict guard. correlateSans
	// throws on invalid input (programmer error) — we let that escape.
	// We don't want to call it just for validation when 'san' isn't requested,
	// so reuse `validateDomain` directly.
	const { validateDomain } = await import('../lib/sanitize');
	const v = validateDomain(seedDomain);
	if (!v.valid) {
		throw new Error(`Domain validation failed: ${v.error ?? 'invalid domain'}`);
	}

	type Job = () => Promise<void>;
	const aggregator = new Map<string, CandidateAggregator>();
	const signalStatus: Record<string, { status: string; error?: string }> = {};
	const jobs: Job[] = [];

	if (signals.includes('san')) {
		jobs.push(async () => {
			const out = await runSignal<SanCorrelationResult>(() => d.correlateSans(seedDomain));
			if (!out.ok) {
				signalStatus.san = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.san = { status: out.value.queryStatus };
			for (const dom of out.value.coOwnedDomains) {
				addObservation(aggregator, dom, 'san', DEFAULT_SIGNAL_CONFIDENCE.san, {
					seed: out.value.seedDomain,
					certIds: out.value.certIds.slice(0, 5),
				});
			}
		});
	}

	if (signals.includes('ns')) {
		jobs.push(async () => {
			const out = await runSignal<NsCorrelationResult>(() => d.correlateNs(seedDomain, { candidateDomains }));
			if (!out.ok) {
				signalStatus.ns = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.ns = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'ns', c.confidence, {
					sharedNs: c.sharedNs,
					nsConfidence: c.confidence,
				});
			}
		});
	}

	if (signals.includes('dmarc_rua')) {
		jobs.push(async () => {
			const out = await runSignal<DmarcRuaResult>(() => d.mineDmarcRua(seedDomain));
			if (!out.ok) {
				signalStatus.dmarc_rua = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.dmarc_rua = { status: out.value.queryStatus };
			for (const r of out.value.ruaDomains) {
				if (r.classification !== 'related') continue;
				addObservation(aggregator, r.domain, 'dmarc_rua', r.confidence, {
					classification: r.classification,
				});
			}
		});
	}

	if (signals.includes('dkim_key_reuse')) {
		jobs.push(async () => {
			const out = await runSignal<DkimKeyReuseResult>(() =>
				d.detectDkimKeyReuse(seedDomain, candidateDomains, dkimSelectors ? { selectors: dkimSelectors } : {}),
			);
			if (!out.ok) {
				signalStatus.dkim_key_reuse = { status: 'failed', error: out.error };
				return;
			}
			signalStatus.dkim_key_reuse = { status: out.value.queryStatus };
			for (const c of out.value.coOwnedDomains) {
				addObservation(aggregator, c.domain, 'dkim_key_reuse', c.confidence, {
					sharedSelectors: c.sharedSelectors,
					sharedKeys: c.sharedKeys,
				});
			}
		});
	}

	await Promise.allSettled(jobs.map((j) => j()));

	// Did every requested signal blow up? If yes, surface a missingControl finding.
	const allFailed = signals.length > 0 && signals.every((s) => signalStatus[s]?.status === 'failed');
	if (allFailed) {
		return buildCheckResult('brand_discovery', [
			createFinding(
				'brand_discovery',
				'Brand-domain discovery could not complete',
				'high',
				`All ${signals.length} requested signal(s) failed; see signalStatus metadata for details.`,
				{
					missingControl: true,
					confidence: 'heuristic',
					errorKind: 'dns_error',
					signalStatus,
				},
			),
		]);
	}

	// Build candidate findings.
	const candidateFindings: Finding[] = [];
	const surviving: Array<{ domain: string; combined: number; signals: DiscoverSignal[]; sources: Record<string, unknown> }> = [];
	for (const entry of aggregator.values()) {
		// Drop the seed or its subdomains if they accidentally appear (e.g. self-referenced rua=).
		if (isSubdomainOf(entry.domain, seedDomain)) continue;
		const perSignal = Array.from(entry.perSignalConfidence.entries());
		const combined = round4(combineConfidences(perSignal.map(([, c]) => c)));
		if (combined < minConfidence) continue;
		const signalKinds = perSignal.map(([k]) => k).sort() as DiscoverSignal[];
		surviving.push({ domain: entry.domain, combined, signals: signalKinds, sources: entry.sources });
	}

	surviving.sort((a, b) => b.combined - a.combined || a.domain.localeCompare(b.domain));

	for (const cand of surviving) {
		const severity: Severity = cand.combined >= AUTO_INCLUDE_THRESHOLD ? 'low' : 'info';
		candidateFindings.push(
			createFinding(
				'brand_discovery',
				`Discovered candidate: ${cand.domain}`,
				severity,
				`Found via ${cand.signals.length} signal(s): ${cand.signals.join(', ')}; combined confidence ${cand.combined.toFixed(2)}.`,
				{
					candidate: cand.domain,
					signals: cand.signals,
					combinedConfidence: cand.combined,
					sources: cand.sources,
				},
			),
		);
	}

	// Always emit a summary finding so the formatter has something to print.
	const summary = createFinding(
		'brand_discovery',
		`Brand-domain discovery: ${candidateFindings.length} candidate(s) at confidence ≥ ${minConfidence}`,
		'info',
		`Seed=${seedDomain.trim().toLowerCase()} signals=[${signals.join(', ')}] aggregated_total=${aggregator.size} surfaced=${candidateFindings.length}`,
		{
			summary: true,
			signals,
			signalStatus,
			minConfidence,
			totalAggregated: aggregator.size,
			surfaced: candidateFindings.length,
		},
	);

	return buildCheckResult('brand_discovery', [summary, ...candidateFindings]);
}

/** Format a discoverBrandDomains CheckResult as human-readable text. */
export function formatDiscoverBrandDomains(result: CheckResult, format: OutputFormat = 'full'): string {
	const summary = result.findings.find((f) => f.metadata?.summary === true);
	const candidates = result.findings.filter((f) => f.metadata?.candidate);

	if (format === 'compact') {
		const lines: string[] = [];
		lines.push(`Brand discovery — ${candidates.length} candidate(s)`);
		if (summary) {
			lines.push(`  ${sanitizeOutputText(summary.detail, 240)}`);
		}
		for (const c of candidates) {
			const conf = c.metadata?.combinedConfidence as number | undefined;
			const signals = (c.metadata?.signals as string[] | undefined)?.join(',') ?? '';
			lines.push(
				`  - ${sanitizeOutputText(c.metadata?.candidate as string, 80)} (conf=${conf?.toFixed(2) ?? '?'}, signals=${signals})`,
			);
		}
		return lines.join('\n');
	}

	const lines: string[] = [];
	lines.push('# Brand-Domain Discovery');
	if (summary) {
		lines.push(sanitizeOutputText(summary.detail, 400));
	}
	lines.push('');
	if (candidates.length === 0) {
		lines.push('No candidate domains surfaced above the confidence threshold.');
	} else {
		lines.push('## Candidates');
		for (const c of candidates) {
			const icon = c.severity === 'low' ? '🟡' : '🔵';
			const conf = c.metadata?.combinedConfidence as number | undefined;
			const signals = (c.metadata?.signals as string[] | undefined)?.join(', ') ?? '';
			lines.push(`${icon} **${sanitizeOutputText(c.metadata?.candidate as string, 80)}** — confidence ${conf?.toFixed(2) ?? '?'}`);
			lines.push(`  signals: ${signals}`);
		}
	}
	const missing = result.findings.find((f) => f.metadata?.missingControl);
	if (missing) {
		lines.push('');
		lines.push(`🔴 ${sanitizeOutputText(missing.title, 200)}: ${sanitizeOutputText(missing.detail, 400)}`);
	}
	return lines.join('\n');
}
