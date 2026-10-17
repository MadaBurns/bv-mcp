// SPDX-License-Identifier: BUSL-1.1

/**
 * Certificate-Transparency COVERAGE contract.
 *
 * WHY THIS EXISTS
 * ---------------
 * `discover_subdomains` used to answer with `enumerationComplete: boolean`. The
 * flag's authored meaning was narrow and true — "the ONE source that answered
 * was paginated to the end of its index" — but its NAME asserts something much
 * larger, and every reasonable consumer read `true` as "this is the estate".
 *
 * Measured against production on 2026-07-27 (bnz.co.nz):
 *   - the tool returned 165 unique names with `sources: ["certspotter"]`,
 *     `truncated: false`, `enumerationComplete: true`;
 *   - crt.sh's unfiltered CT history for the same estate holds 420 unique names;
 *   - `ams.privatebank`, `realme`, `cardsecurity` and `myaccess` .bnz.co.nz are
 *     absent from the tool's answer and all four resolve to live production IPs.
 * A `true` completeness flag therefore accompanied a ~60%-short answer about a
 * bank's external attack surface.
 *
 * THE CEILING IS STRUCTURAL, NOT A BUG TO OUTRUN
 * ----------------------------------------------
 * No amount of pagination makes a CT sweep an inventory:
 *   - a host that never had a publicly-logged certificate never appears in CT
 *     at all — an entire class of asset is invisible by construction;
 *   - Certspotter's unauthenticated feed is a ROLLING WINDOW (measured
 *     2025-07-07 → 2026-07-27 for bnz.co.nz, ~1 year), so exhausting its index
 *     still cannot see older issuance;
 *   - crt.sh is queried with `exclude=expired`, so even a healthy crt.sh only
 *     shows currently-valid certificates — that single parameter is where the
 *     254 missing bnz.co.nz names went.
 *
 * So the honest contract cannot be "did we finish?" — it must be "what did we
 * actually look at, and what could that possibly have seen?". Hence:
 *   - {@link CtCoverage.basis} is the LITERAL `'ct-sample'`, a one-member union.
 *     There is no representable value meaning "complete inventory"; a consumer
 *     cannot branch its way into the old misreading.
 *   - every source is reported individually with its outcome, whether we read
 *     its index to the end, and the slice of CT history it can see AT ALL.
 *   - sources that were never consulted are named explicitly, so a fast-path
 *     single-source answer cannot masquerade as a multi-source consensus.
 *
 * Pure module — no I/O, no bindings. Safe to unit-test in isolation.
 */

/** Per-source health outcome, shared with the tool's `ct_source` health log. */
/**
 * `rate_limited` is split out from `http_error` on purpose (#735). A 429 is the
 * one upstream failure where the correct caller response is the OPPOSITE of the
 * usual one: retrying extends the lockout and burns a quota shared with every
 * other domain scanned next. Measured 2026-08-21 — after Certspotter 504s on a
 * large estate it 429s the same unauthenticated caller, and the lockout outlived
 * a 75-second wait.
 *
 * `provider_restricted` and `access_denied` split HTTP 403 out for the same
 * reason. Measured 2026-09-14 — CertSpotter answered a query for a public-suffix
 * apex with HTTP 403 in 0.65s and the machine-readable code
 * `not_allowed_by_plan`: a categorical refusal of that query, identical on every
 * retry, forever. Folded into `http_error` it earned "may be transient — a retry
 * is worthwhile", the opposite of the truth. The two new members are told apart
 * by EVIDENCE, not by remediation (neither is retryable as issued):
 *
 *  - `provider_restricted` — the provider DECLARED the restriction itself, as a
 *    recognized machine-readable code in its own error body.
 *  - `access_denied`       — a 403 whose body declares nothing recognizable
 *    (absent, malformed, over-cap, or an unknown code). The refusal is observed;
 *    the REASON is not established, so no restriction may be claimed from it.
 *
 * Neither carries upstream text: only the code is read, under a byte cap, and it
 * is never re-emitted to a caller.
 */
export type CtSourceOutcome =
	| 'ok'
	| 'empty'
	| 'http_error'
	| 'rate_limited'
	| 'provider_restricted'
	| 'access_denied'
	| 'timeout'
	| 'error';

/**
 * How much of CT history a source can see AT ALL, independent of whether we
 * finished reading it. This is the bound that pagination cannot lift.
 *
 *  - `unexpired-only`  — only currently-valid certificates are visible (crt.sh
 *                        as queried, i.e. with `exclude=expired`).
 *  - `recent-window`   — a rolling recent window only (Certspotter's free tier).
 *  - `forward-from`    — the owned CT index (`bv-ct-index`, US-12): it only holds
 *                        names it OBSERVED since `indexStartedAt`; nothing issued
 *                        and logged before then is visible, and it has no backfill.
 *  - `unknown`         — an upstream aggregator whose retention we do not
 *                        control or publish (a legacy certstream worker).
 */
export type CtHistoryWindow = 'unexpired-only' | 'recent-window' | 'forward-from' | 'unknown';

/** The `coverage.source` value an owned-index response carries. */
export const OWNED_CT_INDEX_SOURCE = 'bv-ct-index';

/**
 * Days after `indexStartedAt` at which the owned index is treated as covering the
 * unexpired certificate population (SQ-340: ~87% at d90, ~97% at d180, ~100% at
 * d200). A younger index is a CONTRIBUTING but NOT exhaustive source, so it must
 * never suppress crt.sh / CertSpotter.
 */
export const OWNED_INDEX_MATURITY_DAYS = 200;

/** What an owned-index (`bv-ct-index`) response says about its own coverage. */
export interface OwnedIndexCoverage {
	/** ISO instant the index began observing; absent when the response omitted or garbled it. */
	indexStartedAt?: string;
	/** ISO instant of the newest indexed batch. */
	freshThrough?: string;
	/** The route returned only a page of what it holds (`/enumerate` caps at 500 names). */
	truncated: boolean;
}

export function isoOrUndefined(value: unknown): string | undefined {
	if (typeof value !== 'string') return undefined;
	const ms = Date.parse(value);
	return Number.isNaN(ms) ? undefined : new Date(ms).toISOString();
}

/**
 * Read the `coverage` object of a certstream-binding response. Returns null for a
 * legacy upstream (no `coverage`, or a different `source`), which keeps today's
 * behaviour. Dates are re-serialised, never echoed, because they reach
 * caller-visible prose.
 */
export function parseOwnedIndexCoverage(raw: unknown): OwnedIndexCoverage | null {
	if (typeof raw !== 'object' || raw === null) return null;
	const c = raw as Record<string, unknown>;
	if (c.source !== OWNED_CT_INDEX_SOURCE) return null;
	const indexStartedAt = isoOrUndefined(c.indexStartedAt);
	const freshThrough = isoOrUndefined(c.freshThrough);
	return {
		...(indexStartedAt ? { indexStartedAt } : {}),
		...(freshThrough ? { freshThrough } : {}),
		truncated: c.truncated === true,
	};
}

/**
 * True when an owned-index answer must NOT be treated as exhaustive: the page was
 * truncated, or the index is younger than {@link OWNED_INDEX_MATURITY_DAYS}. An
 * unknown or future start date counts as young — no proof of maturity is not
 * maturity.
 */
export function ownedIndexIsPartial(c: OwnedIndexCoverage, nowMs: number = Date.now()): boolean {
	if (c.truncated || !c.indexStartedAt) return true;
	const ageDays = (nowMs - Date.parse(c.indexStartedAt)) / 86_400_000;
	return !(ageDays >= OWNED_INDEX_MATURITY_DAYS);
}

/** What one CT source contributed to this answer. */
export interface CtSourceCoverage {
	source: string;
	outcome: CtSourceOutcome;
	/** True when this source's names are in the returned set. */
	contributed: boolean;
	/**
	 * True when WE read this source's index to the end (no pagination cap, no
	 * budget stop, no upstream truncation flag). Narrow and per-source — it says
	 * nothing about the estate. Undefined when the source never answered.
	 */
	indexExhausted?: boolean;
	/** The slice of CT history this source can see even in the best case. */
	historyWindow: CtHistoryWindow;
	/** Owned index only: when it began observing (`historyWindow: 'forward-from'`). */
	indexStartedAt?: string;
	/** Owned index only: commit time of its newest indexed batch. */
	freshThrough?: string;
}

/**
 * The completeness contract that replaces `enumerationComplete`.
 *
 * `basis` is deliberately a one-member literal union. Widening it to add a
 * second member (e.g. `'inventory'`) would reintroduce the exact defect this
 * type exists to prevent — don't.
 */
export interface CtCoverage {
	/** Always `'ct-sample'`. A CT sweep is evidence, never an asset inventory. */
	basis: 'ct-sample';
	/** Every source attempted on this call, in attempt order. */
	perSource: CtSourceCoverage[];
	/** Sources whose names are in the returned set. */
	contributing: string[];
	/** Sources attempted that produced nothing usable (failed or empty). */
	unavailable: string[];
	/** Known sources never asked on this call (e.g. skipped by a fast path). */
	notConsulted: string[];
	/**
	 * True when at least one known source was unavailable or never consulted —
	 * i.e. recall on this call is below what this tool can normally reach. NOT a
	 * completeness claim when false; `basis` still governs.
	 */
	degraded: boolean;
	/** Always-populated prose stating the sample caveat. Never omitted. */
	caveat: string;
}

/**
 * Every CT source this tool can reach. Used to compute `notConsulted`, so a
 * fast-path answer names the sources it skipped rather than implying consensus.
 */
export const KNOWN_CT_SOURCES = ['certstream', 'crtsh', 'certspotter'] as const;

/** Static per-source history bound (see {@link CtHistoryWindow}). */
const SOURCE_HISTORY_WINDOW: Record<string, CtHistoryWindow> = {
	crtsh: 'unexpired-only',
	certspotter: 'recent-window',
	certstream: 'unknown',
};

/** The history bound for a source name; unknown sources are assumed opaque. */
export function historyWindowFor(source: string): CtHistoryWindow {
	return SOURCE_HISTORY_WINDOW[source] ?? 'unknown';
}

/** One recorded source attempt, as the tool observes it. */
export interface CtSourceAttempt {
	source: string;
	outcome: CtSourceOutcome;
	contributed: boolean;
	indexExhausted?: boolean;
	/** Set when the source answered from the owned CT index: its history window becomes `forward-from`. */
	ownedIndex?: OwnedIndexCoverage;
}

/**
 * Build the coverage record from the attempts actually made.
 *
 * `totalReturned` only shapes the wording — the caveat is emitted regardless,
 * because the dangerous case is precisely the one that looks healthy.
 */
export function buildCtCoverage(attempts: CtSourceAttempt[]): CtCoverage {
	const perSource: CtSourceCoverage[] = attempts.map((a) => ({
		source: a.source,
		outcome: a.outcome,
		contributed: a.contributed,
		...(a.indexExhausted === undefined ? {} : { indexExhausted: a.indexExhausted }),
		historyWindow: a.ownedIndex ? 'forward-from' : historyWindowFor(a.source),
		...(a.ownedIndex?.indexStartedAt ? { indexStartedAt: a.ownedIndex.indexStartedAt } : {}),
		...(a.ownedIndex?.freshThrough ? { freshThrough: a.ownedIndex.freshThrough } : {}),
	}));

	const contributing = perSource.filter((s) => s.contributed).map((s) => s.source);
	const unavailable = perSource.filter((s) => !s.contributed).map((s) => s.source);
	const attempted = new Set(perSource.map((s) => s.source));
	const notConsulted = KNOWN_CT_SOURCES.filter((s) => !attempted.has(s));

	return {
		basis: 'ct-sample',
		perSource,
		contributing,
		unavailable,
		notConsulted: [...notConsulted],
		degraded: unavailable.length > 0 || notConsulted.length > 0,
		caveat: coverageCaveat(contributing, unavailable, [...notConsulted], perSource),
	};
}

/**
 * The prose the caller actually reads. Three sentences, in descending order of
 * what a security consumer would get wrong:
 *   1. this is a sample and the count is a LOWER BOUND;
 *   2. which sources answered and which did not;
 *   3. what those sources structurally cannot see even when healthy.
 */
function coverageCaveat(contributing: string[], unavailable: string[], notConsulted: string[], perSource: CtSourceCoverage[]): string {
	const parts: string[] = [
		'This is a Certificate Transparency SAMPLE, not an inventory of the estate — the subdomain count is a LOWER BOUND. A host that has never had a publicly-logged certificate does not appear in CT at all.',
	];

	parts.push(
		contributing.length > 0 ? `Sources that answered: ${contributing.join(', ')}.` : 'No CT source contributed names on this call.',
	);
	if (unavailable.length > 0) parts.push(`Attempted but returned nothing usable: ${unavailable.join(', ')}.`);
	if (notConsulted.length > 0) parts.push(`Not consulted on this call: ${notConsulted.join(', ')}.`);

	// An owned index that answered "nothing" is still bounded evidence: it saw nothing SINCE its start.
	const bounds = perSource
		.filter((s) => (s.contributed || (s.historyWindow === 'forward-from' && s.outcome === 'empty')) && s.historyWindow !== 'unknown')
		.map((s) => {
			if (s.historyWindow === 'unexpired-only') return `${s.source} shows currently-valid certificates only`;
			if (s.historyWindow === 'forward-from') return forwardFromBound(s);
			return `${s.source} covers a recent rolling window only`;
		});
	if (bounds.length > 0) parts.push(`Source history bounds: ${bounds.join('; ')}.`);

	return parts.join(' ');
}

/** Prose for an owned-index source: names it observed since its start, and how fresh it is. */
function forwardFromBound(s: CtSourceCoverage): string {
	const since = s.indexStartedAt ? `names observed since ${s.indexStartedAt}` : 'names observed since an unknown start date';
	const fresh = s.freshThrough ? `, fresh through ${s.freshThrough}` : '';
	const partial = s.indexExhausted === false ? '; its answer is partial, so older or unindexed issuance is not covered' : '';
	return `${s.source} is the owned CT index, ${since}${fresh}${partial}`;
}

/**
 * One-line rendering of the coverage record for the human/LLM-readable output.
 * Emitted on EVERY result — including the clean single-source path, which is
 * exactly the shape that previously read as authoritative.
 */
export function formatCoverageLine(coverage: CtCoverage): string {
	const bits: string[] = [];
	for (const s of coverage.perSource) {
		const exhausted = s.indexExhausted === true ? ' index-exhausted' : s.indexExhausted === false ? ' index-partial' : '';
		bits.push(`${s.source}=${s.outcome}${exhausted}`);
	}
	for (const s of coverage.notConsulted) bits.push(`${s}=not-consulted`);
	return `Coverage [${coverage.basis}]: ${bits.join(', ')}`;
}
