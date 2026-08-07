// SPDX-License-Identifier: BUSL-1.1

/**
 * The two abstain branches inside `scanDomain`'s post-scoring block: the
 * maturity-cap bypass and the adaptive-weight telemetry gate. Both key off
 * `score.overall === null`.
 *
 * Reaching them needs the SCORING ENGINE to return a null `overall`. The engine
 * does not do that yet (`computeScanScore` always grades what it is given — the
 * degenerate zero-check case is ruled to a later slice), and the three producer
 * short-circuits that DO emit null (NXDOMAIN, unresolvable zone, scoring-bundle
 * failure) all return before this block. So the engine call is mocked, exactly as
 * `scan-domain-scoring-catch.spec.ts` mocks it to throw — the seam is the module
 * boundary; everything from `applyInteractionPenalties` onward is the real code.
 *
 * `computeMaturityStage` is mocked to a stage-4 raw result so the cap assertions
 * DISCRIMINATE: with a raw stage of 0 (what an empty-DNS fixture produces),
 * `capMaturityStage(raw, 0)` and "don't cap at all" return the identical object
 * and no assertion on the output could tell the two implementations apart.
 * `capMaturityStage` itself stays real.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import type { ScanScore } from '@blackveil/dns-checks/scoring';
import type { MaturityStage } from '../src/tools/scan/maturity-staging';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();

const mockScanScore = vi.fn();
const mockMaturityStage = vi.fn();

vi.mock('@blackveil/dns-checks/scoring', async (importOriginal) => {
	const orig = await importOriginal<typeof import('@blackveil/dns-checks/scoring')>();
	return { ...orig, computeScanScore: (...args: unknown[]) => mockScanScore(...args) };
});

vi.mock('../src/tools/scan/maturity-staging', async (importOriginal) => {
	const orig = await importOriginal<typeof import('../src/tools/scan/maturity-staging')>();
	return { ...orig, computeMaturityStage: (...args: unknown[]) => mockMaturityStage(...args) };
});

function installEmptyDnsFetch() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = String(input instanceof Request ? input.url : input);
		if (/dns-query|\/resolve|dns-json|dns\.google|cloudflare-dns/.test(url)) {
			return Promise.resolve(createDohResponse([], []));
		}
		return Promise.resolve(new Response('', { status: 200 }));
	}) as unknown as typeof globalThis.fetch;
}

function ungradedScore(): ScanScore {
	// Mocks the engine returning null outright — "could not be scored" carries no
	// measurement behind it, so evidence is honestly zero rather than a fabricated
	// full or partial ratio.
	return {
		overall: null,
		grade: null,
		categoryScores: {} as ScanScore['categoryScores'],
		findings: [],
		summary: 'Scan could not be scored.',
		evidence: { attempted: 0, completed: 0, ratio: 0 },
	};
}

function gradedScore(overall: number, grade: string): ScanScore {
	// Control representing a normal, fully measured scan — evidence is honestly full.
	return {
		overall,
		grade,
		categoryScores: {} as ScanScore['categoryScores'],
		findings: [],
		summary: `Measured. Grade: ${grade}`,
		evidence: { attempted: 19, completed: 19, ratio: 1 },
	};
}

const HARDENED_STAGE: MaturityStage = {
	stage: 4,
	label: 'Hardened',
	description: 'Comprehensive email and DNS security posture with defense in depth.',
	nextStep: '',
};

afterEach(() => {
	restore();
	IN_MEMORY_CACHE.clear();
	mockScanScore.mockReset();
	mockMaturityStage.mockReset();
});

describe('scanDomain post-scoring — maturity cap on an ungraded score', () => {
	it('leaves the raw stage uncapped rather than capping it against a coerced zero', async () => {
		installEmptyDnsFetch();
		mockScanScore.mockReturnValue(ungradedScore());
		mockMaturityStage.mockReturnValue(HARDENED_STAGE);

		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain('maturity-uncapped.example', undefined, { forceRefresh: true });

		expect(result.score.overall).toBeNull();
		// `capMaturityStage(raw, score.overall ?? 0)` — the plausible wrong form —
		// reads the missing score as an F and rewrites this to stage 2
		// "Monitoring (score-capped)", asserting a maturity downgrade the scan never
		// measured.
		expect(result.maturity.stage).toBe(4);
		expect(result.maturity.label).toBe('Hardened');
	});

	it('still caps the same raw stage when the scan DID produce a failing score (control)', async () => {
		installEmptyDnsFetch();
		mockScanScore.mockReturnValue(gradedScore(20, 'F'));
		mockMaturityStage.mockReturnValue(HARDENED_STAGE);

		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain('maturity-capped.example', undefined, { forceRefresh: true });

		// Without this the assertion above would hold under an implementation that
		// never capped at all.
		expect(result.score.overall).toBe(20);
		expect(result.maturity.stage).toBe(2);

		// #640 follow-up: this fixture serves EMPTY DNS for every query, so the domain
		// has no MX and is profiled onto the WEB-ONLY ladder. It therefore reads
		// "Transport-Hardened (score-capped)", not the mail ladder's "Monitoring
		// (score-capped)" this used to assert — telling a domain with no mail service
		// that it is "Monitoring" (i.e. running DMARC in report-only) was a claim about
		// a control it does not have. The cap now words the stage with the same ladder
		// that produced it.
		expect(result.context?.profile).toBe('web_only');
		expect(result.maturity.label).toBe('Transport-Hardened (score-capped)');
		expect(result.maturity.label).toContain('(score-capped)');
	});
});

describe('scanDomain post-scoring — adaptive-weight telemetry on an ungraded score', () => {
	/** A ProfileAccumulator stub: records /ingest bodies, misses on /weights. */
	function accumulatorStub(ingestBodies: string[]) {
		return {
			idFromName: (name: string) => name,
			get: () => ({
				fetch: async (request: Request) => {
					if (request.url.includes('/ingest')) {
						ingestBodies.push(await request.text());
						return new Response('{}', { status: 200 });
					}
					// /weights miss → scanDomain falls back to static weights.
					return new Response('{}', { status: 500 });
				},
			}),
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} as any;
	}

	it('does not train the EMA with a scan that carries no measurement', async () => {
		installEmptyDnsFetch();
		mockScanScore.mockReturnValue(ungradedScore());
		mockMaturityStage.mockReturnValue(HARDENED_STAGE);

		const ingestBodies: string[] = [];
		const pending: Promise<unknown>[] = [];
		const { scanDomain } = await import('../src/tools/scan-domain');
		await scanDomain('telemetry-ungraded.example', undefined, {
			forceRefresh: true,
			profileAccumulator: accumulatorStub(ingestBodies),
			waitUntil: (p: Promise<unknown>) => pending.push(p),
		});
		await Promise.allSettled(pending);

		// `overallScore: score.overall ?? 0` — the plausible wrong form — posts a
		// fabricated 0 that pulls every domain in this profile's EMA downward.
		expect(ingestBodies).toEqual([]);
	});

	it('still posts telemetry for a measured scan through the same stub (control)', async () => {
		installEmptyDnsFetch();
		mockScanScore.mockReturnValue(gradedScore(78, 'B'));
		mockMaturityStage.mockReturnValue(HARDENED_STAGE);

		const ingestBodies: string[] = [];
		const pending: Promise<unknown>[] = [];
		const { scanDomain } = await import('../src/tools/scan-domain');
		await scanDomain('telemetry-graded.example', undefined, {
			forceRefresh: true,
			profileAccumulator: accumulatorStub(ingestBodies),
			waitUntil: (p: Promise<unknown>) => pending.push(p),
		});
		await Promise.allSettled(pending);

		// Without this the assertion above would hold under an implementation that
		// never posted telemetry at all.
		expect(ingestBodies.length).toBeGreaterThan(0);
		expect(JSON.parse(ingestBodies[0]).overallScore).toBe(78);
	});
});
