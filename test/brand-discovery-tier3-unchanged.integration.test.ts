// SPDX-License-Identifier: BUSL-1.1

/**
 * T12 — Tier-3 byte-identical regression check.
 *
 * Goal: prove that `discoverBrandDomains` produces byte-identical Tier 3
 * output when run in `discovery_mode: 'tiered'` with empty Tier 0/1/2 deps,
 * compared to `discovery_mode: 'classic'` — after stripping the tier metadata
 * that is *expected* to differ (the `tiers` block and tier-named phases).
 *
 * Why this matters: T13 will flip the BlackVeil production default from
 * `'classic'` to `'tiered'`. Before that flip, we need a regression test
 * that proves the Tier 3 legacy-sweep path was not modified by the T1–T8
 * tier wiring. Any unintended drift in the Tier 3 path fails this test.
 *
 * Plan wording note: the plan (line 749) says "Tier 3 consolidated/shadowIt/
 * indeterminate output". Those buckets are *classifier* output
 * (brand-classification.ts), not orchestrator output. The orchestrator
 * (`discoverBrandDomains`) returns candidate findings. This test asserts
 * byte-identical orchestrator output, which is what feeds the classifier
 * downstream — so any unintended drift would propagate through.
 *
 * Stripper removes (these are *expected* to differ):
 *   - `discoveryPerformance.tiers` (whole block — tiered-mode-only)
 *   - tier-named phases (`tiered_lookup`, `tier0_tenant`, `tier1_graph`,
 *     `tier2_evidence`)
 *   - all timing fields (`elapsedMs`, `startedAtMs`, `finishedAtMs`)
 *
 * Layer: Integration — exercises the orchestrator across its dep-injection
 * seam (network/DNS boundaries). The dep stubs are *boundary* mocks, not
 * collaborator mocks: every stubbed module performs DNS/HTTP I/O in prod.
 * Mocking these is required by Principle 8 (mock at slow/external boundaries).
 */

import { describe, it, expect } from 'vitest';
import type { DiscoverBrandDomainsDeps, DiscoverBrandDomainsOptions } from '../src/tools/discover-brand-domains';
import type { CheckResult, Finding } from '../packages/dns-checks/src/types';

// ---------------------------------------------------------------------------
// Deterministic boundary stubs. Each `vi.fn()` here replaces a module that
// performs DNS or HTTP I/O in production — the dep-injection seam exists
// precisely so tests can mock at these external boundaries.
// ---------------------------------------------------------------------------

const SEED = 'example.com';
const EMPTY_OK = { coOwnedDomains: [], queryStatus: 'ok' as const };

const SAN_HIT = {
	seedDomain: SEED,
	coOwnedDomains: ['sister.com'],
	certIds: [],
	queryStatus: 'ok' as const,
};
const SAN_RECURSIVE_EMPTY = {
	seedDomain: SEED,
	crossConfirmed: [],
	probed: [],
	queryStatus: 'ok' as const,
};
const NS_EMPTY = { seedDomain: SEED, seedNs: ['ns1.example.com'], coOwnedDomains: [], queryStatus: 'ok' as const };
const RUA_EMPTY = {
	seedDomain: SEED,
	dmarcPresent: true,
	ruaUris: [],
	ruaDomains: [],
	queryStatus: 'ok' as const,
};
const DKIM_HIT = {
	seedDomain: SEED,
	seedSelectors: ['default'],
	coOwnedDomains: [
		{ domain: 'sister.com', sharedKeys: ['abc123'], sharedSelectors: ['default'], confidence: 0.95 },
	],
	queryStatus: 'ok' as const,
};
const TXT_EMPTY = { seedDomain: SEED, coOwnedDomains: [], queryStatus: 'ok' as const };
const MX_PLATFORM_EMPTY = { seedDomain: SEED, coOwnedDomains: [], queryStatus: 'ok' as const };
const SPF_SEED_EMPTY = { seedDomain: SEED, candidates: [], queryStatus: 'ok' as const };
const LOOKALIKES_EMPTY = { category: 'lookalikes' as const, score: 100, passed: true, findings: [] };

function makeBoundaryDeps(): DiscoverBrandDomainsDeps {
	// One factory: every external-I/O module replaced with a deterministic
	// resolved value. Two of the stubs (SAN + DKIM) return the same candidate
	// to surface a corroborated finding (combined confidence 0.955 > 0.85 → 'low').
	// Stubs that return identical empty payloads share a single fn instance,
	// since their return values are interchangeable for this test.
	const asyncStub = <T>(value: T) => (async () => value) as never;
	const syncStub = <T>(value: T) => (() => value) as never;
	return {
		correlateSans: asyncStub(SAN_HIT),
		correlateSansRecursive: asyncStub(SAN_RECURSIVE_EMPTY),
		correlateNs: asyncStub(NS_EMPTY),
		mineDmarcRua: asyncStub(RUA_EMPTY),
		detectDkimKeyReuse: asyncStub(DKIM_HIT),
		detectHttpRedirect: asyncStub(EMPTY_OK),
		detectMxOverlap: asyncStub(EMPTY_OK),
		detectSharedTxtVerifications: asyncStub(TXT_EMPTY),
		detectSharedMxPlatform: asyncStub(MX_PLATFORM_EMPTY),
		detectSpfInclude: asyncStub(EMPTY_OK),
		extractSeedSpfIncludes: asyncStub(SPF_SEED_EMPTY),
		detectCnameAlignment: asyncStub(EMPTY_OK),
		generateMarkovLookalikes: syncStub([] as string[]),
		checkLookalikes: asyncStub(LOOKALIKES_EMPTY),
		domainLabelSimilarity: syncStub(0),
	};
}

// ---------------------------------------------------------------------------
// Stripper — remove fields that are *expected* to differ between modes.
// Anything outside this list MUST match byte-for-byte.
// ---------------------------------------------------------------------------

const TIER_PHASE_NAMES = new Set(['tiered_lookup', 'tier0_tenant', 'tier1_graph', 'tier2_evidence']);

function stripPhase(phase: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(phase)) {
		if (k === 'startedAtMs' || k === 'finishedAtMs' || k === 'elapsedMs') continue;
		out[k] = v;
	}
	return out;
}

function stripDiscoveryPerformance(perf: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
	if (!perf) return perf;
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(perf)) {
		if (k === 'tiers') continue; // tiered-mode-only
		if (k === 'elapsedMs') continue; // wall-clock noise
		if (k === 'phases' && Array.isArray(v)) {
			out[k] = v
				.filter((p) => {
					const name = (p as { name?: unknown }).name;
					return typeof name !== 'string' || !TIER_PHASE_NAMES.has(name);
				})
				.map((p) => stripPhase(p as Record<string, unknown>));
			continue;
		}
		out[k] = v;
	}
	return out;
}

function stripFinding(finding: Finding): Finding {
	const meta = finding.metadata as Record<string, unknown> | undefined;
	if (!meta) return finding;
	const newMeta: Record<string, unknown> = { ...meta };
	if (meta.summary === true && meta.discoveryPerformance) {
		newMeta.discoveryPerformance = stripDiscoveryPerformance(meta.discoveryPerformance as Record<string, unknown>);
	}
	return { ...finding, metadata: newMeta };
}

function stripResult(result: CheckResult): CheckResult {
	return { ...result, findings: result.findings.map(stripFinding) };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('discoverBrandDomains — Tier 3 byte-identical regression (T12)', () => {
	function makeClock(): () => number {
		let t = 1_800_000_000_000;
		return () => {
			t += 1;
			return t;
		};
	}

	const baseOptions: DiscoverBrandDomainsOptions = {
		signals: ['san', 'dkim_key_reuse'],
		candidate_domains: ['sister.com'],
		min_confidence: 0.5,
	};

	it('classic vs tiered-with-empty-Tier-0/1/2-deps: byte-identical after stripping tier metadata', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');

		// Run 1: classic mode
		const classicResult = await discoverBrandDomains(
			SEED,
			{ ...baseOptions, discovery_mode: 'classic', now: makeClock() },
			makeBoundaryDeps(),
		);

		// Run 2: tiered mode with empty Tier 0/1/2 deps
		const tieredDeps: DiscoverBrandDomainsDeps = {
			...makeBoundaryDeps(),
			tier0Lookup: async () => ({ observations: [], status: 'skipped', optedOut: false }) as never,
			tier1Lookup: async () => ({ observations: [], status: 'skipped', triggerTier3Fallback: false }) as never,
			tier2Lookup: async () => ({ observations: [], status: 'skipped' }) as never,
		};
		const tieredResult = await discoverBrandDomains(
			SEED,
			{ ...baseOptions, discovery_mode: 'tiered', now: makeClock() },
			tieredDeps,
		);

		// --- Premise checks: fail loudly if the test's assumptions break ---

		// 1. Tiered run actually triggered Tier 3 fallback (otherwise the
		//    "byte-identical Tier 3 output" claim is vacuously true).
		const tieredSummary = tieredResult.findings.find(
			(f) => (f.metadata as { summary?: boolean } | undefined)?.summary === true,
		);
		const tieredPerf = tieredSummary?.metadata?.discoveryPerformance as
			| { tiers?: { tier3FallbackTriggered?: number; tier0Count?: number; tier1Count?: number; tier2Count?: number } }
			| undefined;
		expect(tieredPerf?.tiers).toBeDefined();
		expect(tieredPerf?.tiers?.tier3FallbackTriggered).toBe(1);
		expect(tieredPerf?.tiers?.tier0Count).toBe(0);
		expect(tieredPerf?.tiers?.tier1Count).toBe(0);
		expect(tieredPerf?.tiers?.tier2Count).toBe(0);

		// 2. Classic run does NOT carry a `tiers` block (BSL invariance).
		const classicSummary = classicResult.findings.find(
			(f) => (f.metadata as { summary?: boolean } | undefined)?.summary === true,
		);
		const classicPerf = classicSummary?.metadata?.discoveryPerformance as Record<string, unknown> | undefined;
		expect(classicPerf && 'tiers' in classicPerf).toBe(false);

		// 3. Both runs surface the corroborated sister.com candidate. A test
		//    where both return zero candidates would trivially pass byte-identical
		//    but exercise nothing — refuse that.
		const classicCandidates = classicResult.findings.filter(
			(f) => (f.metadata as { candidate?: unknown } | undefined)?.candidate,
		);
		const tieredCandidates = tieredResult.findings.filter(
			(f) => (f.metadata as { candidate?: unknown } | undefined)?.candidate,
		);
		expect(classicCandidates).toHaveLength(1);
		expect(tieredCandidates).toHaveLength(1);
		expect(classicCandidates[0].metadata?.candidate).toBe('sister.com');
		expect(tieredCandidates[0].metadata?.candidate).toBe('sister.com');

		// --- The actual regression check ---
		const strippedClassic = stripResult(classicResult);
		const strippedTiered = stripResult(tieredResult);
		expect(strippedTiered).toEqual(strippedClassic);
	});
});
