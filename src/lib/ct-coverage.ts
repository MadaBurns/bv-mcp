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
 */
export type CtSourceOutcome = 'ok' | 'empty' | 'http_error' | 'rate_limited' | 'timeout' | 'error';

/**
 * How much of CT history a source can see AT ALL, independent of whether we
 * finished reading it. This is the bound that pagination cannot lift.
 *
 *  - `unexpired-only`  — only currently-valid certificates are visible (crt.sh
 *                        as queried, i.e. with `exclude=expired`).
 *  - `recent-window`   — a rolling recent window only (Certspotter's free tier).
 *  - `unknown`         — an upstream aggregator whose retention we do not
 *                        control or publish (the certstream worker).
 */
export type CtHistoryWindow = 'unexpired-only' | 'recent-window' | 'unknown';

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
		historyWindow: historyWindowFor(a.source),
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

	const bounds = perSource
		.filter((s) => s.contributed && s.historyWindow !== 'unknown')
		.map((s) =>
			s.historyWindow === 'unexpired-only'
				? `${s.source} shows currently-valid certificates only`
				: `${s.source} covers a recent rolling window only`,
		);
	if (bounds.length > 0) parts.push(`Source history bounds: ${bounds.join('; ')}.`);

	return parts.join(' ');
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
