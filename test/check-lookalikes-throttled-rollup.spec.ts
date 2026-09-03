// SPDX-License-Identifier: BUSL-1.1

/**
 * #865 — a THROTTLED `check_lookalikes` run must not publish a hard threat
 * rollup count at `high` severity.
 *
 * Measured 2026-08-31 (openai.com, engine 1.29.0): `enumeration` said
 * 90 probed / 12 resolved / 77 unresolved / `complete: false`, yet the same
 * payload carried "6 lookalike domains showing pre-phishing staging signals"
 * at `high` with `mailCapableCount: 8` and "8 can send mail in total". The
 * scan_status finding said the list was a sample; the rollup — the finding a
 * consumer keys on, at higher severity — stated the integer as fact. Across
 * eight providers the same day the unresolved rate ranged 1.2% → 86%, so
 * side-by-side counts reported a rate-limiting artifact as a security
 * difference between named companies.
 *
 * Contract pinned here:
 *  1. at or above `ROLLUP_ABSTAIN_UNRESOLVED_RATIO` the rollup ABSTAINS — a
 *     not-assessed `scan_status` finding, no integer count, never `high`;
 *  2. whenever it DOES emit, the enumeration stats travel INSIDE the rollup
 *     finding's own metadata (flat, not only under `enumeration`);
 *  3. an incomplete run reports its count as a FLOOR, never a bare N;
 *  4. members whose registration age could not be fetched are counted in
 *     `ageUnknownCount` and named as such in the prose — never dropped.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Parse the DoH query name and type from a fetch URL (same helper as check-lookalikes.spec.ts). */
function parseDohQuery(input: string | URL | Request): { name: string; type: string } {
	const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
	const parsed = new URL(url);
	return {
		name: parsed.searchParams.get('name') ?? '',
		type: parsed.searchParams.get('type') ?? '',
	};
}

const isNs = (type: string) => type === 'NS' || type === '2';
const isMx = (type: string) => type === 'MX' || type === '15';

function nsResponse(name: string, hosts: string[]) {
	return createDohResponse(
		[{ name, type: 2 }],
		hosts.map((data) => ({ name, type: 2, TTL: 300, data })),
	);
}

function mxResponse(name: string, exchange: string) {
	return createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: `10 ${exchange}` }]);
}

function empty() {
	return createDohResponse([], []);
}

async function run(domain = 'testco.com') {
	const { checkLookalikes } = await import('../src/tools/check-lookalikes');
	return checkLookalikes(domain);
}

/**
 * Seed `testco.com` on its own NS; candidate `twstco.com` on unrelated NS with
 * a working mail host. `mx.mailgun.org` sits in DISPOSABLE_MX_PROVIDERS, so the
 * #264 matrix reaches HIGH without an RDAP mock — which also leaves
 * `registrationDays: null` (age unknown), the shape #867 is about.
 *
 * `rejectOthers` controls how much of the permutation space is throttled:
 *  - `'all'`   → every other permutation's NS lookup REJECTS (openai shape, ~99%)
 *  - a number  → only the first N distinct other names reject; the rest
 *                answer empty (a partial run well below the abstain threshold)
 *  - `0`       → nothing rejects (a complete run)
 */
function mockRun(opts: { rejectOthers: 'all' | number; candidateMx?: string }): void {
	const { rejectOthers, candidateMx = 'mx.mailgun.org.' } = opts;
	const rejected = new Set<string>();
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const { name, type } = parseDohQuery(input);
		if (name === 'testco.com' && isNs(type)) {
			return Promise.resolve(nsResponse(name, ['ns1.primary-dns.com.']));
		}
		if (name === 'twstco.com') {
			if (isNs(type)) return Promise.resolve(nsResponse(name, ['ns1.unrelated-dns.com.']));
			if (isMx(type)) return Promise.resolve(mxResponse(name, candidateMx));
			return Promise.resolve(empty());
		}
		if (isNs(type) && name !== '' && name !== 'testco.com') {
			if (rejectOthers === 'all' || rejected.has(name) || rejected.size < rejectOthers) {
				rejected.add(name);
				return Promise.reject(new Error('DNS timeout'));
			}
		}
		return Promise.resolve(empty());
	});
}

const STAGING_TITLE = /lookalike domains? showing pre-phishing staging signals/i;
const MAIL_HOST_TITLE = /lookalike domains? with a working mail host/i;

/** The aggregate rollup: a threat_observation that names a LIST, not a single candidate. */
function findRollup(findings: Awaited<ReturnType<typeof run>>['findings']) {
	return findings.find((f) => f.metadata?.findingAxis === 'threat_observation' && f.metadata?.lookalikeDomain === undefined);
}

describe('checkLookalikes - throttled runs abstain from the threat rollup (#865)', () => {
	it('abstains at or above the unresolved-ratio threshold: not-assessed, no integer, never high', async () => {
		mockRun({ rejectOthers: 'all' });
		const result = await run('testco.com');

		// The two aggregate rollups are both withheld.
		expect(result.findings.some((f) => STAGING_TITLE.test(f.title))).toBe(false);
		expect(result.findings.some((f) => MAIL_HOST_TITLE.test(f.title))).toBe(false);
		expect(findRollup(result.findings)).toBeUndefined();

		// In their place: a not-assessed scan_status notice that reuses the
		// repo's "probe never reached the origin" vocabulary.
		const abstained = result.findings.find((f) => f.metadata?.notAssessedReason === 'enumeration_throttled');
		expect(abstained, 'an abstention must be VISIBLE, not silent').toBeDefined();
		expect(abstained!.severity).toBe('info');
		expect(abstained!.metadata?.findingAxis).toBe('scan_status');
		expect(abstained!.metadata?.inconclusive).toBe(true);
		expect(abstained!.metadata?.errorKind).toBe('dns_error');
		// No count of any kind on the abstention.
		expect(abstained!.metadata?.lookalikeDomainCount).toBeUndefined();
		expect(abstained!.metadata?.mailCapableCount).toBeUndefined();
		expect(abstained!.metadata?.lookalikeDomains).toBeUndefined();
		expect(abstained!.metadata?.mailCapableDomains).toBeUndefined();
		expect(abstained!.title).not.toMatch(/\d+ lookalike domain/);
		// The enumeration stats a consumer needs to judge the abstention are on
		// the finding itself.
		expect(abstained!.metadata?.complete).toBe(false);
		expect(abstained!.metadata?.permutationsProbed as number).toBeGreaterThan(0);
		expect(abstained!.metadata?.unresolvedCount as number).toBeGreaterThan(0);
		expect(abstained!.metadata?.candidatesResolved).toBe(1);

		// No aggregate finding anywhere carries a bare count in its title.
		for (const f of result.findings) {
			if (f.metadata?.lookalikeDomain !== undefined) continue;
			expect(f.title).not.toMatch(/^\d+ lookalike domain/);
			expect(f.title).not.toMatch(/^At least \d+/);
		}
	});

	it('an abstained run is marked partial so the non-answer is not cached for the TTL (#847 law)', async () => {
		mockRun({ rejectOthers: 'all' });
		const result = await run('testco.com');
		expect(result.partial).toBe(true);
	});

	it('the mail-capable-only (medium) rollup abstains under the same threshold', async () => {
		mockRun({ rejectOthers: 'all', candidateMx: 'mail.twstco.com.' });
		const result = await run('testco.com');
		expect(result.findings.some((f) => MAIL_HOST_TITLE.test(f.title))).toBe(false);
		expect(result.findings.some((f) => STAGING_TITLE.test(f.title))).toBe(false);
		expect(result.findings.find((f) => f.metadata?.notAssessedReason === 'enumeration_throttled')).toBeDefined();
	});

	it('below the threshold an incomplete run still emits, but as a FLOOR with the enumeration stats inside the rollup', async () => {
		mockRun({ rejectOthers: 3 });
		const result = await run('testco.com');

		const rollup = result.findings.find((f) => STAGING_TITLE.test(f.title));
		expect(rollup, 'a mildly incomplete run must not be silenced').toBeDefined();
		expect(rollup!.metadata?.findingAxis).toBe('threat_observation');
		// Floor wording, not a bare integer.
		expect(rollup!.title).toMatch(/^At least 1 lookalike domain showing pre-phishing staging signals/);
		expect(rollup!.detail).toMatch(/floor/i);
		expect(rollup!.detail).toMatch(/of \d+ probed/);
		expect(rollup!.metadata?.countIsFloor).toBe(true);
		expect(rollup!.metadata?.lookalikeDomainCount).toBe(1);
		expect(rollup!.metadata?.lookalikeDomains).toEqual(['twstco.com']);
		// The four enumeration stats are FLAT on the rollup — a consumer reading
		// only this finding cannot miss them.
		expect(rollup!.metadata?.complete).toBe(false);
		expect(rollup!.metadata?.unresolvedCount).toBe(3);
		expect(rollup!.metadata?.permutationsProbed as number).toBeGreaterThan(3);
		expect(rollup!.metadata?.candidatesResolved).toBe(1);
		expect(rollup!.metadata?.confidence).toBe('heuristic');
		// No abstention notice when the rollup did emit.
		expect(result.findings.some((f) => f.metadata?.notAssessedReason === 'enumeration_throttled')).toBe(false);
	});

	it('names how many counted members could not be age-checked, without dropping them', async () => {
		mockRun({ rejectOthers: 3 });
		const result = await run('testco.com');
		const rollup = result.findings.find((f) => STAGING_TITLE.test(f.title));
		expect(rollup).toBeDefined();
		// No RDAP mock → registrationDays null for the one mail-capable member.
		expect(rollup!.metadata?.ageUnknownCount).toBe(1);
		expect(rollup!.metadata?.mailCapableCount).toBe(1);
		expect(rollup!.metadata?.mailCapableDomains).toEqual(['twstco.com']);
		expect(rollup!.detail).toMatch(/1 of 1 .*could not be age-checked/i);
	});

	it('a complete run is unchanged: bare count, no floor marker, stats say complete', async () => {
		mockRun({ rejectOthers: 0 });
		const result = await run('testco.com');

		const rollup = result.findings.find((f) => STAGING_TITLE.test(f.title));
		expect(rollup).toBeDefined();
		expect(rollup!.title).toBe('1 lookalike domain showing pre-phishing staging signals');
		expect(rollup!.severity).toBe('high');
		expect(rollup!.detail).not.toMatch(/floor/i);
		expect(rollup!.metadata?.countIsFloor).toBeFalsy();
		expect(rollup!.metadata?.complete).toBe(true);
		expect(rollup!.metadata?.unresolvedCount).toBe(0);
		expect(rollup!.metadata?.confidence).toBe('deterministic');
		expect(rollup!.metadata?.lookalikeDomainCount).toBe(1);
		expect(result.findings.some((f) => f.metadata?.notAssessedReason === 'enumeration_throttled')).toBe(false);
		expect(result.partial).toBeFalsy();
	});

	it('the mail-capable-only (medium) rollup carries the same floor + stats contract when incomplete', async () => {
		mockRun({ rejectOthers: 3, candidateMx: 'mail.twstco.com.' });
		const result = await run('testco.com');
		const rollup = result.findings.find((f) => MAIL_HOST_TITLE.test(f.title));
		expect(rollup).toBeDefined();
		expect(rollup!.severity).toBe('medium');
		expect(rollup!.title).toMatch(/^At least 1 lookalike domain with a working mail host/);
		expect(rollup!.metadata?.countIsFloor).toBe(true);
		expect(rollup!.metadata?.complete).toBe(false);
		expect(rollup!.metadata?.unresolvedCount).toBe(3);
		expect(rollup!.metadata?.ageUnknownCount).toBe(1);
		expect(rollup!.detail).toMatch(/floor/i);
	});
});

describe('lookalike-summary-findings - abstain threshold (#865)', () => {
	it('is a named constant at 50%: the unobserved share may never exceed the observed one', async () => {
		const { ROLLUP_ABSTAIN_UNRESOLVED_RATIO, isRollupCoverageDegraded } = await import('../src/tools/lookalike-summary-findings');
		expect(ROLLUP_ABSTAIN_UNRESOLVED_RATIO).toBe(0.5);
		const at = (unresolvedCount: number, permutationsProbed = 100) => ({
			permutationsGenerated: permutationsProbed,
			permutationsProbed,
			candidatesResolved: permutationsProbed - unresolvedCount,
			unresolvedCount,
			complete: unresolvedCount === 0,
		});
		// The issue's measured table: amazon 1/82 and cohere 40/94 emit; microsoft
		// 48/95, meta 41/66, google 60/89 and openai 77/90 abstain.
		expect(isRollupCoverageDegraded(at(1, 82))).toBe(false);
		expect(isRollupCoverageDegraded(at(40, 94))).toBe(false);
		expect(isRollupCoverageDegraded(at(48, 95))).toBe(true);
		expect(isRollupCoverageDegraded(at(41, 66))).toBe(true);
		expect(isRollupCoverageDegraded(at(60, 89))).toBe(true);
		expect(isRollupCoverageDegraded(at(77, 90))).toBe(true);
		// Boundary: exactly half abstains; one under emits.
		expect(isRollupCoverageDegraded(at(50))).toBe(true);
		expect(isRollupCoverageDegraded(at(49))).toBe(false);
		// Nothing probed → nothing to be degraded about.
		expect(isRollupCoverageDegraded(at(0, 0))).toBe(false);
	});
});
