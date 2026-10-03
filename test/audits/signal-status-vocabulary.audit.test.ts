// SPDX-License-Identifier: BUSL-1.1

/**
 * Signal-status vocabulary audit (#1190).
 *
 * `discoverBrandDomains` reports a signal's outcome twice: as the consumer-visible
 * `signalStatus[signal].status` and as the phase telemetry recorded by
 * `recordInstantPhase(signal, status)`. `brand-audit-depth.ts` string-matches the
 * former to decide which operator warnings fire, so a status the file emits but the
 * rest of the system does not know about is a silent coverage hole.
 *
 * The abort branch once wrote `signalStatus.san_recursive = skipped_no_first_order`
 * and recorded the phase as `skipped_aborted` — each literal a legitimate member of
 * the vocabulary, the PAIR wrong (a copy-paste that updated one string). So there
 * are two assertions, and the second is what catches that class:
 *
 *   1. Membership — every `status: '<literal>'` assigned into `signalStatus`/
 *      `preSignalStatus` and every `recordInstantPhase(<signal>, '<status>')`
 *      second argument is a member of the exported `SignalStatusValue` union.
 *   2. Agreement — where an assignment into `signalStatus.<x>` is immediately
 *      followed by `recordInstantPhase('<x>', ...)`, the two statuses are equal.
 *
 * The union is a TYPE (erased at runtime) and the Workers pool sandboxes `node:fs`,
 * so both the union members and the emission sites are recovered from the raw source
 * via `import.meta.glob(?raw)`, the same mechanism as
 * `completed-predicate-agreement.audit.test.ts`.
 */

import { describe, it, expect } from 'vitest';

const SOURCES = import.meta.glob('../../src/tools/discover-brand-domains.ts', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;
const SOURCE = Object.values(SOURCES)[0] ?? '';

function unionMembers(source: string): string[] {
	const decl = source.match(/export type SignalStatusValue\s*=([^;]+);/);
	if (!decl) return [];
	return [...decl[1].matchAll(/'([a-z_]+)'/g)].map((m) => m[1]);
}

interface Site {
	line: number;
	signal: string;
	status: string;
}

function lineOf(source: string, index: number): number {
	return source.slice(0, index).split('\n').length;
}

/** `signalStatus.x = { status: '…' }`, `signalStatus[s] ??= { status: '…' }`, `preSignalStatus.x = …`. */
function statusAssignments(source: string): Site[] {
	const re = /\b(?:pre)?[sS]ignalStatus(?:\.(\w+)|\[(\w+)\])\s*(?:\?\?=|=)\s*\{\s*status:\s*'([a-z_]+)'/g;
	return [...source.matchAll(re)].map((m) => ({ line: lineOf(source, m.index ?? 0), signal: m[1] ?? m[2], status: m[3] }));
}

/** A ternary arm such as `? { status: 'partial', error: … }` belongs to a signalStatus assignment too. */
function ternaryStatusLiterals(source: string): Site[] {
	const re = /\b(?:pre)?[sS]ignalStatus\.(\w+)\s*=\s*\n?\s*[^;]*?\?\s*\{\s*status:\s*'([a-z_]+)'/g;
	return [...source.matchAll(re)].map((m) => ({ line: lineOf(source, m.index ?? 0), signal: m[1], status: m[2] }));
}

function instantPhases(source: string): Site[] {
	const re = /recordInstantPhase\(\s*'(\w+)'\s*,\s*'([a-z_]+)'/g;
	return [...source.matchAll(re)].map((m) => ({ line: lineOf(source, m.index ?? 0), signal: m[1], status: m[2] }));
}

describe('signal-status vocabulary (audit)', () => {
	const members = unionMembers(SOURCE);
	const memberSet = new Set(members);

	it('positive controls: the source, the union and the emission sites were actually found', () => {
		// A regex that silently matches nothing would read as "all clean".
		expect(SOURCE.length).toBeGreaterThan(0);
		expect(members.length).toBeGreaterThanOrEqual(10);
		expect(new Set(members).size).toBe(members.length);
		expect(statusAssignments(SOURCE).length).toBeGreaterThanOrEqual(15);
		expect(instantPhases(SOURCE).length).toBeGreaterThanOrEqual(5);
	});

	it('every status literal assigned into signalStatus is a member of SignalStatusValue', () => {
		const sites = [...statusAssignments(SOURCE), ...ternaryStatusLiterals(SOURCE)];
		const violations = sites.filter((s) => !memberSet.has(s.status));
		expect(
			violations.map((v) => `  discover-brand-domains.ts:${v.line}  ${v.signal} = '${v.status}'`),
			`signalStatus literal(s) outside SignalStatusValue — add the member (and check brand-audit-depth.ts handles it) or fix the typo`,
		).toEqual([]);
	});

	it('every recordInstantPhase status is a member of SignalStatusValue', () => {
		const violations = instantPhases(SOURCE).filter((s) => !memberSet.has(s.status));
		expect(
			violations.map((v) => `  discover-brand-domains.ts:${v.line}  recordInstantPhase('${v.signal}', '${v.status}')`),
			`recordInstantPhase status(es) outside SignalStatusValue`,
		).toEqual([]);
	});

	it('a signalStatus assignment and the recordInstantPhase that follows it for the same signal agree', () => {
		// `signalStatus.x = { status: 'S', … };` then `await recordInstantPhase('x', 'S'…`.
		const re =
			/signalStatus\.(\w+)\s*(?:\?\?=|=)\s*\{\s*status:\s*'([a-z_]+)'[^}]*\};\s*\n\s*await recordInstantPhase\(\s*'(\w+)'\s*,\s*'([a-z_]+)'/g;
		const pairs = [...SOURCE.matchAll(re)].map((m) => ({
			line: lineOf(SOURCE, m.index ?? 0),
			payloadSignal: m[1],
			payload: m[2],
			phaseSignal: m[3],
			phase: m[4],
		}));
		// Positive control: the skipped_deadline, failed and no-first-order branches all have this shape.
		expect(pairs.length).toBeGreaterThanOrEqual(3);
		const disagreements = pairs.filter((p) => p.payloadSignal !== p.phaseSignal || p.payload !== p.phase);
		expect(
			disagreements.map(
				(p) => `  discover-brand-domains.ts:${p.line}  signalStatus.${p.payloadSignal}='${p.payload}' but phase ${p.phaseSignal}='${p.phase}'`,
			),
			`payload status and phase telemetry disagree for the same signal`,
		).toEqual([]);
	});
});
