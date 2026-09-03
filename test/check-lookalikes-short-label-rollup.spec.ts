// SPDX-License-Identifier: BUSL-1.1

/**
 * #863 — a SHORT seed label makes the whole TLD "confusable", and the threat
 * rollup must not turn that into an attack-preparation claim about named
 * companies.
 *
 * Measured 2026-08-31 on `x.ai` (enumeration complete, 25/25 probed): the
 * per-domain findings hedged correctly — `attributionConfidence:
 * "uncorroborated"`, "The shared label is under 5 characters and nothing else
 * corroborates a link, so the name similarity alone means little." — but the
 * rollup dropped the hedge and published "1 lookalike domain showing
 * pre-phishing staging signals" at `high`, naming `z.ai` (Zhipu AI) with
 * `mailCapableDomains: ["c.ai", "s.ai", "z.ai"]` (Character.AI, a personal
 * site, Zhipu AI). None is a typosquat: at one character every single-letter
 * domain is one edit away, so edit distance cannot separate a typosquat from
 * an independent registration. `meta.com` (4 chars) returned 16 mail-capable /
 * 9 staging-flagged in the same sweep for the same reason.
 *
 * Contract pinned here:
 *  1. below `MIN_ATTRIBUTION_LABEL_LENGTH` — the SAME constant the per-domain
 *     hedge already cites — the rollup ABSTAINS (not-assessed, no count, no
 *     `high`), and the abstention is structural, so the run is NOT partial;
 *  2. the rollup never exceeds the confidence of what it aggregates: an
 *     `uncorroborated` member is excluded from `lookalikeDomains` /
 *     `mailCapableDomains` / the counts, and its presence caps the rollup's
 *     severity below `high`;
 *  3. a seed at or above the threshold is unchanged.
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

async function run(domain: string) {
	const { checkLookalikes } = await import('../src/tools/check-lookalikes');
	return checkLookalikes(domain);
}

/**
 * Seed on its own NS; each named candidate on unrelated NS with a mail host
 * on a DISPOSABLE provider, so the #264 matrix reaches HIGH per domain and the
 * staging rollup WOULD fire if nothing stopped it. Everything else resolves
 * empty (a complete run — coverage is not the variable here).
 */
function mockSeedWithCandidates(seed: string, candidates: string[]): void {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const { name, type } = parseDohQuery(input);
		if (name === seed && isNs(type)) return Promise.resolve(nsResponse(name, ['ns1.primary-dns.com.']));
		if (candidates.includes(name)) {
			if (isNs(type)) return Promise.resolve(nsResponse(name, ['ns1.unrelated-dns.com.']));
			if (isMx(type)) return Promise.resolve(mxResponse(name, 'mx.mailgun.org.'));
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

describe('checkLookalikes - short seed labels abstain from the threat rollup (#863)', () => {
	it('x.ai (1-char label): per-domain hedge is present, the rollup abstains, and no aggregate high is published', async () => {
		mockSeedWithCandidates('x.ai', ['z.ai', 'c.ai']);
		const result = await run('x.ai');

		// The tool already knew: the per-domain attribution finding hedges.
		const zAttribution = result.findings.find((f) => f.metadata?.findingAxis === 'attribution' && f.metadata?.lookalikeDomain === 'z.ai');
		expect(zAttribution).toBeDefined();
		expect(zAttribution!.metadata?.attributionConfidence).toBe('uncorroborated');

		// The rollup no longer drops that hedge.
		expect(result.findings.some((f) => STAGING_TITLE.test(f.title))).toBe(false);
		expect(result.findings.some((f) => MAIL_HOST_TITLE.test(f.title))).toBe(false);
		expect(findRollup(result.findings)).toBeUndefined();
		// Nothing aggregate names z.ai / c.ai in a list.
		for (const f of result.findings) {
			if (f.metadata?.lookalikeDomain !== undefined) continue;
			expect(f.metadata?.lookalikeDomains).toBeUndefined();
			expect(f.metadata?.mailCapableDomains).toBeUndefined();
			expect(f.severity).not.toBe('high');
		}

		const abstained = result.findings.find((f) => f.metadata?.notAssessedReason === 'seed_label_too_short');
		expect(abstained, 'the abstention must be VISIBLE, not silent').toBeDefined();
		expect(abstained!.severity).toBe('info');
		expect(abstained!.metadata?.findingAxis).toBe('scan_status');
		expect(abstained!.metadata?.seedLabel).toBe('x');
		expect(abstained!.metadata?.seedLabelLength).toBe(1);
		expect(abstained!.metadata?.lookalikeDomainCount).toBeUndefined();
		expect(abstained!.metadata?.mailCapableCount).toBeUndefined();
		expect(abstained!.title).not.toMatch(/\d+ lookalike domain/);
		expect(abstained!.detail).toMatch(/every .*one edit away|cannot separate/i);
	});

	it('cites the SAME threshold constant the per-domain hedge uses — one number, one home', async () => {
		const { MIN_ATTRIBUTION_LABEL_LENGTH } = await import('../src/lib/ownership-attribution');
		mockSeedWithCandidates('x.ai', ['z.ai']);
		const result = await run('x.ai');
		const abstained = result.findings.find((f) => f.metadata?.notAssessedReason === 'seed_label_too_short');
		expect(abstained!.metadata?.minLabelLength).toBe(MIN_ATTRIBUTION_LABEL_LENGTH);
		expect(abstained!.detail).toContain(`under ${MIN_ATTRIBUTION_LABEL_LENGTH} characters`);
		const hedge = result.findings.find((f) => f.metadata?.attributionConfidence === 'uncorroborated');
		expect(hedge!.detail).toContain(`under ${MIN_ATTRIBUTION_LABEL_LENGTH} characters`);
	});

	it('a short-label abstention is structural, so the run is NOT marked partial (cacheable — every run would abstain)', async () => {
		mockSeedWithCandidates('x.ai', ['z.ai']);
		const result = await run('x.ai');
		expect(result.partial).toBeFalsy();
	});

	it('meta.com (4-char label): abstains too — the blast-radius case from the issue', async () => {
		mockSeedWithCandidates('meta.com', ['mata.com', 'meta.co']);
		const result = await run('meta.com');
		expect(result.findings.some((f) => STAGING_TITLE.test(f.title))).toBe(false);
		expect(findRollup(result.findings)).toBeUndefined();
		const abstained = result.findings.find((f) => f.metadata?.notAssessedReason === 'seed_label_too_short');
		expect(abstained).toBeDefined();
		expect(abstained!.metadata?.seedLabelLength).toBe(4);
	});

	it('control: a 6-char seed label is unchanged — the staging rollup fires at high with its bare count', async () => {
		mockSeedWithCandidates('testco.com', ['twstco.com']);
		const result = await run('testco.com');
		const rollup = result.findings.find((f) => STAGING_TITLE.test(f.title));
		expect(rollup).toBeDefined();
		expect(rollup!.title).toBe('1 lookalike domain showing pre-phishing staging signals');
		expect(rollup!.severity).toBe('high');
		expect(rollup!.metadata?.lookalikeDomains).toEqual(['twstco.com']);
		expect(rollup!.metadata?.uncorroboratedExcludedCount).toBe(0);
		expect(result.findings.some((f) => f.metadata?.notAssessedReason !== undefined)).toBe(false);
	});
});

describe('buildThreatRollupFinding - never exceeds the confidence of what it aggregates (#863)', () => {
	const enumeration = { permutationsGenerated: 10, permutationsProbed: 10, candidatesResolved: 2, unresolvedCount: 0, complete: true };
	const member = (domain: string, attributionConfidence: 'corroborated' | 'uncorroborated', severity: 'high' | 'medium' = 'high') => ({
		domain,
		hasMX: true,
		severity,
		ownershipVerdict: 'third_party' as const,
		registrationDays: 400,
		attributionConfidence,
	});

	it('excludes an uncorroborated member from every list and count, and caps the rollup below high', async () => {
		const { buildThreatRollupFinding } = await import('../src/tools/lookalike-summary-findings');
		const { finding, notAssessedReason } = buildThreatRollupFinding({
			seedDomain: 'testco.com',
			seedLabel: 'testco',
			members: [member('twstco.com', 'corroborated'), member('tstco.com', 'uncorroborated')],
			enumeration,
		});
		expect(notAssessedReason).toBeNull();
		expect(finding).not.toBeNull();
		expect(finding!.metadata?.lookalikeDomains).toEqual(['twstco.com']);
		expect(finding!.metadata?.mailCapableDomains).toEqual(['twstco.com']);
		expect(finding!.metadata?.lookalikeDomainCount).toBe(1);
		expect(finding!.metadata?.mailCapableCount).toBe(1);
		expect(finding!.metadata?.uncorroboratedExcludedCount).toBe(1);
		// The aggregate cannot be more confident than its weakest member.
		expect(finding!.severity).toBe('medium');
		expect(finding!.metadata?.severityCappedBy).toBe('attribution_confidence');
		expect(finding!.detail).toMatch(/1 further .*excluded/i);
	});

	it('with no corroborated member left, abstains rather than publishing an empty or hedged count', async () => {
		const { buildThreatRollupFinding } = await import('../src/tools/lookalike-summary-findings');
		const { finding, notAssessedReason } = buildThreatRollupFinding({
			seedDomain: 'testco.com',
			seedLabel: 'testco',
			members: [member('tstco.com', 'uncorroborated'), member('tesco.com', 'uncorroborated', 'medium')],
			enumeration,
		});
		expect(notAssessedReason).toBe('members_uncorroborated');
		expect(finding).not.toBeNull();
		expect(finding!.severity).toBe('info');
		expect(finding!.metadata?.findingAxis).toBe('scan_status');
		expect(finding!.metadata?.notAssessedReason).toBe('members_uncorroborated');
		expect(finding!.metadata?.lookalikeDomains).toBeUndefined();
		expect(finding!.metadata?.mailCapableDomains).toBeUndefined();
	});

	/**
	 * Review finding on #863: the exclusion/cap path above is UNREACHABLE from
	 * `checkLookalikesCore` today, because the rollup's label gate and the
	 * classifier's corroboration bar are the same constant on the same string.
	 * Pin that coupling from the CLASSIFIER side too: at exactly the threshold
	 * length, with no other corroboration, the verdict is `'corroborated'`. If
	 * someone splits the two thresholds this goes red and points at the rollup
	 * path that would silently become live.
	 */
	it('classifier-side pin: a label of exactly MIN_ATTRIBUTION_LABEL_LENGTH chars is corroborated with no other signal', async () => {
		const { attributionConfidence, MIN_ATTRIBUTION_LABEL_LENGTH } = await import('../src/lib/ownership-attribution');
		const { MIN_ROLLUP_SEED_LABEL_LENGTH } = await import('../src/tools/lookalike-summary-findings');
		const atThreshold = 'a'.repeat(MIN_ATTRIBUTION_LABEL_LENGTH);
		const belowThreshold = 'a'.repeat(MIN_ATTRIBUTION_LABEL_LENGTH - 1);
		for (const verdict of ['third_party', 'unattributed', 'unmeasured'] as const) {
			expect(attributionConfidence(verdict, atThreshold, false)).toBe('corroborated');
			expect(attributionConfidence(verdict, belowThreshold, false)).toBe('uncorroborated');
		}
		// Therefore every member of a seed that passes the rollup's label gate is
		// corroborated: the gate and the classifier bar are the same number.
		expect(atThreshold.length >= MIN_ROLLUP_SEED_LABEL_LENGTH).toBe(true);
		expect(belowThreshold.length < MIN_ROLLUP_SEED_LABEL_LENGTH).toBe(true);
	});

	it('the short-label gate runs before member filtering and before the coverage gate', async () => {
		const { buildThreatRollupFinding, MIN_ROLLUP_SEED_LABEL_LENGTH } = await import('../src/tools/lookalike-summary-findings');
		const { MIN_ATTRIBUTION_LABEL_LENGTH } = await import('../src/lib/ownership-attribution');
		// One constant, re-exported — not a second number.
		expect(MIN_ROLLUP_SEED_LABEL_LENGTH).toBe(MIN_ATTRIBUTION_LABEL_LENGTH);
		const { finding, notAssessedReason } = buildThreatRollupFinding({
			seedDomain: 'x.ai',
			seedLabel: 'x',
			members: [member('z.ai', 'corroborated')],
			enumeration: { ...enumeration, unresolvedCount: 9, candidatesResolved: 1, complete: false },
		});
		expect(notAssessedReason).toBe('seed_label_too_short');
		expect(finding!.metadata?.notAssessedReason).toBe('seed_label_too_short');
	});
});
