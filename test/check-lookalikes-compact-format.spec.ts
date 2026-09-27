// SPDX-License-Identifier: BUSL-1.1

/**
 * #1130 — `check_lookalikes` ignored `format: "compact"`. On google.com (76
 * findings, one or two per registered candidate) the tool returned a 69,120-byte
 * body in compact mode and the MCP client refused it, so an agent caller never
 * saw the result at all. Same defect class as #687 (`batch_scan`).
 *
 * Contract pinned here:
 *  1. compact returns every RUN-LEVEL finding (the rollup, scan-status notices)
 *     plus a bounded, severity-ordered top-N of the per-candidate findings, on
 *     BOTH channels (`content` text and `structuredContent`) — the 69 KB body
 *     was the JSON, so shrinking only the prose would not have fixed it;
 *  2. compact carries counts (registered / mail-capable / brand-held /
 *     third-party) derived from the predicates the check already emits, and
 *     `truncated: true` + the total when the list was capped;
 *  3. `score` / `passed` are the full result's, untouched;
 *  4. full mode is unchanged.
 *
 * The fixture is a synthetic CheckResult assembled from the REAL finding
 * builders and seeded into the check cache, so the handler serves it through
 * the production dispatch path without 200 mocked DNS lookups.
 */

import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import type { CheckResult, Finding } from '../src/lib/scoring';
import type { OwnershipAssessment } from '../src/lib/ownership-attribution';
import type { LookalikeResult } from '../src/tools/lookalike-dns';
import type { LookalikeSeverity, LookalikeSignals } from '../src/tools/lookalike-severity';
import type { ThreatRollupMember } from '../src/tools/lookalike-summary-findings';

const SEED = 'examplebrand.com';

const OWNED = 5;
const DARK = 15;
const BRAND_HELD = 4;
const ACTIVE_THIRD_PARTY = 50;
const ACTIVE_UNATTRIBUTED = 6;
const REGISTERED = OWNED + DARK + BRAND_HELD + ACTIVE_THIRD_PARTY + ACTIVE_UNATTRIBUTED;

function ownership(verdict: OwnershipAssessment['verdict']): OwnershipAssessment {
	return {
		verdict,
		strength: verdict === 'owned_by_seed' ? 'strong' : 'none',
		signals: verdict === 'owned_by_seed' ? ['ns_set_match'] : [],
		rationale:
			verdict === 'owned_by_seed'
				? `its nameservers are the same set as ${SEED}`
				: `The candidate delegates to nameservers that share no host with ${SEED}, and no other ownership signal links the two zones.`,
	};
}

function candidate(i: number, hasA: boolean, hasMX: boolean): LookalikeResult {
	return {
		domain: `examp1ebrand-${i}.com`,
		hasA,
		hasMX,
		mxExchanges: hasMX ? [`mx.examp1ebrand-${i}.com`] : [],
		aAddresses: hasA ? ['192.0.2.10'] : [],
		probeDegraded: false,
	};
}

/** Build the synthetic large-brand result from the production finding builders. */
async function buildFixture(): Promise<{ result: CheckResult; expected: { mailCapable: number; thirdParty: number } }> {
	const lf = await import('../src/tools/lookalike-findings');
	const ls = await import('../src/tools/lookalike-summary-findings');
	const { buildCheckResult } = await import('../src/lib/scoring');

	const findings: Finding[] = [];
	const members: ThreatRollupMember[] = [];
	let n = 0;
	let mailCapable = 0;
	let thirdParty = 0;

	for (let i = 0; i < OWNED; i++) {
		findings.push(lf.buildOwnedBySeedFinding(candidate(n++, true, true), SEED, ownership('owned_by_seed')));
	}
	for (let i = 0; i < DARK; i++) {
		findings.push(lf.buildRegisteredDarkFinding(candidate(n++, false, false), SEED, ownership('third_party')));
		thirdParty++;
	}

	const addActive = (verdict: OwnershipAssessment['verdict'], idx: number, brandHeld: boolean) => {
		const hasMX = idx % 2 === 0;
		const c = candidate(n++, true, hasMX);
		const severity: LookalikeSeverity = hasMX ? (idx % 4 === 0 ? 'high' : 'medium') : 'low';
		const signals: LookalikeSignals = {
			hasA: true,
			hasMX,
			registrationDays: idx % 3 === 0 ? 30 : null,
			registrationLookup: idx % 3 === 0 ? 'ok' : 'not_attempted',
			mxOnDisposable: false,
			hasWebContent: idx % 4 !== 0,
		};
		const reasons = lf.describeCorroborators(signals);
		const own = ownership(verdict);
		const held = { registrarIanaId: '292', registrarName: 'MarkMonitor Inc.', reason: 'no-mx' as const };
		if (brandHeld) {
			findings.push(lf.buildBrandHeldFinding(c, SEED, own, held));
		} else {
			findings.push(lf.applyOwnershipGate(lf.buildRawAttributionFinding(c, SEED, severity, signals, reasons), own, 'examplebrand', false));
		}
		findings.push(
			lf.buildThreatObservationFinding(
				c.domain,
				SEED,
				severity,
				signals,
				own,
				reasons,
				undefined,
				brandHeld ? { registrarIanaId: '292' } : undefined,
			),
		);
		members.push({
			domain: c.domain,
			hasMX,
			severity,
			ownershipVerdict: verdict,
			registrationDays: signals.registrationDays,
			attributionConfidence: 'corroborated',
		} satisfies ThreatRollupMember);
		if (hasMX) mailCapable++;
		if (verdict === 'third_party') thirdParty++;
	};
	for (let i = 0; i < BRAND_HELD; i++) addActive('third_party', i, true);
	for (let i = 0; i < ACTIVE_THIRD_PARTY; i++) addActive('third_party', i, false);
	for (let i = 0; i < ACTIVE_UNATTRIBUTED; i++) addActive('unattributed', i, false);

	const enumeration = {
		permutationsGenerated: 400,
		permutationsProbed: 380,
		candidatesResolved: REGISTERED,
		unresolvedCount: 0,
		complete: true,
	};
	const rollup = ls.buildThreatRollupFinding({ seedDomain: SEED, seedLabel: 'examplebrand', members, enumeration });
	if (rollup.finding) findings.push(rollup.finding);

	return { result: buildCheckResult('lookalikes', findings), expected: { mailCapable, thirdParty } };
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

async function seedCache(result: CheckResult): Promise<void> {
	const { IN_MEMORY_CACHE, buildCheckCacheKey } = await import('../src/lib/cache');
	IN_MEMORY_CACHE.clear();
	IN_MEMORY_CACHE.set(buildCheckCacheKey(SEED, 'lookalikes'), result);
}

async function call(format: 'compact' | 'full') {
	const { handleToolsCall } = await import('../src/handlers/tools');
	return handleToolsCall({ name: 'check_lookalikes', arguments: { domain: SEED, format } });
}

describe('check_lookalikes format: "compact" (#1130)', () => {
	beforeEach(async () => {
		const { IN_MEMORY_CACHE } = await import('../src/lib/cache');
		IN_MEMORY_CACHE.clear();
	});
	afterEach(async () => {
		const { IN_MEMORY_CACHE } = await import('../src/lib/cache');
		IN_MEMORY_CACHE.clear();
	});

	it('the fixture reproduces the overflow shape (sanity: full mode is large)', async () => {
		const { result } = await buildFixture();
		await seedCache(result);
		const full = await call('full');
		expect(result.findings.length).toBeGreaterThan(100);
		expect(JSON.stringify(full).length).toBeGreaterThan(60_000);
	});

	it('compact output is bounded on BOTH channels and carries a severity-ordered top-N', async () => {
		const { result } = await buildFixture();
		await seedCache(result);
		const compact = await call('compact');
		const { LOOKALIKE_COMPACT_TOP_N } = await import('../src/tools/lookalike-compact');

		expect(compact.isError).toBeUndefined();
		const body = JSON.stringify(compact);
		expect(body.length).toBeLessThan(25_000);
		expect(compact.content[0].text.length).toBeLessThan(12_000);
		expect(JSON.stringify(compact.structuredContent).length).toBeLessThan(15_000);

		const sc = compact.structuredContent as Record<string, unknown> & { findings: Finding[] };
		const perCandidate = sc.findings.filter((f) => typeof f.metadata?.lookalikeDomain === 'string');
		expect(perCandidate).toHaveLength(LOOKALIKE_COMPACT_TOP_N);
		const ranks = perCandidate.map((f) => SEVERITY_RANK[f.severity]);
		expect(ranks).toEqual([...ranks].sort((a, b) => b - a));
		// Every `high` in the full result outranks everything shown below it.
		expect(perCandidate[0].severity).toBe('high');

		// The rollup survives compaction.
		expect(sc.findings.some((f) => f.metadata?.mailCapableCount !== undefined)).toBe(true);
	});

	it('compact carries counts from the existing predicates and flags truncation', async () => {
		const { result, expected } = await buildFixture();
		await seedCache(result);
		const compact = await call('compact');
		const { LOOKALIKE_COMPACT_TOP_N } = await import('../src/tools/lookalike-compact');
		const summary = (compact.structuredContent as Record<string, unknown>).compact as Record<string, unknown>;

		const perCandidateTotal = result.findings.filter((f) => typeof f.metadata?.lookalikeDomain === 'string').length;
		expect(summary).toMatchObject({
			registered: REGISTERED,
			mailCapable: expected.mailCapable,
			brandHeld: BRAND_HELD,
			thirdParty: expected.thirdParty,
			truncated: true,
			totalFindings: result.findings.length,
			candidateFindingsTotal: perCandidateTotal,
			candidateFindingsShown: LOOKALIKE_COMPACT_TOP_N,
		});
		// The rollup's own #779 count agrees with the compact mail-capable count.
		const rollup = result.findings.find((f) => f.metadata?.mailCapableCount !== undefined);
		expect(rollup?.metadata?.mailCapableCount).toBe(expected.mailCapable);

		const text = compact.content[0].text;
		expect(text).toContain(`${REGISTERED} registered`);
		expect(text).toMatch(/truncated/i);
	});

	it('compact leaves score and passed exactly as the full result reports them', async () => {
		const { result } = await buildFixture();
		await seedCache(result);
		const compact = await call('compact');
		const sc = compact.structuredContent as Record<string, unknown>;
		expect(sc.score).toBe(result.score);
		expect(sc.passed).toBe(result.passed);
		expect(sc.category).toBe('lookalikes');
		// Status line is computed from the FULL finding set, not the shortlist.
		const { formatCheckResult } = await import('../src/handlers/tool-formatters');
		const fullCompactStatus = formatCheckResult(result, 'compact').split('\n')[1];
		expect(compact.content[0].text.split('\n')[1]).toBe(fullCompactStatus);
	});

	it('a small result is not truncated and keeps every finding', async () => {
		const { buildCheckResult } = await import('../src/lib/scoring');
		const ls = await import('../src/tools/lookalike-summary-findings');
		const small = buildCheckResult('lookalikes', [ls.buildNoRegisteredCandidatesFinding(SEED, 120)]);
		await seedCache(small);
		const compact = await call('compact');
		const sc = compact.structuredContent as Record<string, unknown> & { findings: Finding[]; compact: Record<string, unknown> };
		expect(sc.findings).toHaveLength(1);
		expect(sc.compact).toMatchObject({ truncated: false, registered: 0, candidateFindingsTotal: 0 });
	});

	it('full mode is unchanged: complete findings array and the pre-#1130 rendering', async () => {
		const { result } = await buildFixture();
		await seedCache(result);
		const full = await call('full');
		const { formatCheckResult } = await import('../src/handlers/tool-formatters');
		const sc = full.structuredContent as Record<string, unknown> & { findings: Finding[] };
		expect(sc.findings).toEqual(result.findings);
		expect(sc).not.toHaveProperty('compact');
		expect(full.content[0].text).toBe(formatCheckResult(result, 'full'));
		expect(full.content[1].text).toBe(`<!-- STRUCTURED_RESULT\n${JSON.stringify(result)}\nSTRUCTURED_RESULT -->`);
	});
});
