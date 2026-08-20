// SPDX-License-Identifier: BUSL-1.1

/**
 * MTA-STS scoring ladder — partial deployment must beat no deployment.
 *
 * Measured defect (2026-08-20 prose-hazard audit): a domain that DEPLOYED MTA-STS and got
 * one RFC-required field wrong scored 0/failed, while a domain with no MTA-STS at all
 * scored 85/passed and a domain publishing `mode: none` (protection switched OFF) also
 * scored 85/passed. The cause was accidental, not designed: four policy-defect findings
 * carry the word "missing" in their TITLE, which `MISSING_CONTROL_REGEX` in
 * `scoring/model.ts` matches. At `high` severity + `deterministic` confidence that ZEROES
 * the whole `mta_sts` category instead of deducting.
 *
 * The tell that it was prose and not intent: the MX-not-covered branch is named in the same
 * design comment, is the same class of defect, carries the same `high` severity — and did
 * NOT zero, purely because its wording says "is not matched by any mx: entry" rather than
 * "missing".
 *
 * This file pins the ORDERING, not just the numbers, so the invariant survives future
 * tuning of individual penalties:
 *
 *     enforcing valid  >  partial/misconfigured  >  mode:none  >=  no MTA-STS at all
 *
 * and pins `scoreIndicatesMissingControl(findings) === false` for every one of these
 * findings, so a future copy edit cannot silently re-arm the zeroing. The TEST is the
 * guarantee; the source comment in `mta-sts-analysis.ts` is documentation only (its
 * predecessor asserted these findings "already carry no `missingControl`" — which was
 * false for four of them).
 */

import { describe, it, expect } from 'vitest';
import { checkMTASTS } from '../../checks/check-mta-sts';
import { scoreIndicatesMissingControl } from '../../scoring/model';
import type { CheckResult, DNSQueryFunction } from '../../types';

const DOMAIN = 'example.com';
const MX = ['10 mail.example.com'];
const TLSRPT = ['v=TLSRPTv1; rua=mailto:t@example.com'];
const STS_TXT = ['v=STSv1; id=1'];

/** A fully valid, enforcing policy that covers the domain's own MX. */
const POLICY_VALID_ENFORCE = 'version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800';

interface Scenario {
	/** TXT at `_mta-sts.<domain>`. */
	sts?: string[];
	/** TXT at `_smtp._tls.<domain>`. */
	tlsrpt?: string[];
	/** MX at `<domain>`. */
	mx?: string[];
	/** Policy body served at the well-known URL. `null` = HTTP 404. */
	policy?: string | null;
	/** Serve the policy as a 301 redirect instead of a body. */
	redirect?: boolean;
	/** Advertise a Content-Length above the RFC 8461 64 KB ceiling. */
	oversized?: boolean;
	domain?: string;
}

async function run(scenario: Scenario): Promise<CheckResult> {
	const domain = scenario.domain ?? DOMAIN;
	const sts = scenario.sts ?? STS_TXT;
	const tlsrpt = scenario.tlsrpt ?? TLSRPT;
	const mx = scenario.mx ?? MX;
	const policy = scenario.policy === undefined ? POLICY_VALID_ENFORCE : scenario.policy;

	const queryDNS = (async (name: string, type: string) => {
		if (type === 'MX' && name === domain) return mx;
		if (type === 'TXT' && name === `_mta-sts.${domain}`) return sts;
		if (type === 'TXT' && name === `_smtp._tls.${domain}`) return tlsrpt;
		return [];
	}) as DNSQueryFunction;

	const fetchFn = (async () => {
		if (scenario.redirect) {
			return { ok: false, status: 301, headers: { get: () => null }, body: { cancel: async () => {} }, text: async () => '' };
		}
		if (policy === null) {
			return { ok: false, status: 404, headers: { get: () => null }, body: { cancel: async () => {} }, text: async () => '' };
		}
		if (scenario.oversized) {
			return { ok: true, status: 200, headers: { get: () => '70000' }, body: { cancel: async () => {} }, text: async () => policy };
		}
		return { ok: true, status: 200, headers: { get: () => String(policy.length) }, body: { cancel: async () => {} }, text: async () => policy };
	}) as never;

	return checkMTASTS(domain, queryDNS, { fetchFn });
}

/** The score plus the two booleans the defect moved. */
async function measure(scenario: Scenario): Promise<{ score: number; passed: boolean; zeroed: boolean }> {
	const result = await run(scenario);
	return {
		score: result.score,
		passed: result.passed,
		zeroed: scoreIndicatesMissingControl(result.findings),
	};
}

// ---------------------------------------------------------------------------
// The seven states, each as its own test.
// ---------------------------------------------------------------------------

describe('MTA-STS scoring ladder — the seven domain states', () => {
	it('valid enforcing policy covering its own MX scores a clean 100', async () => {
		expect(await measure({})).toEqual({ score: 100, passed: true, zeroed: false });
	});

	it('policy omitting max_age is GRADED, not zeroed — strictly better than no policy', async () => {
		// RFC 8461 §3.2 requires max_age, so conforming senders reject the whole policy.
		// But the operator deployed the DNS record AND the HTTPS policy host: that is
		// strictly better posture than never having tried, and must never score 0.
		expect(await measure({ policy: 'version: STSv1\nmode: enforce\nmx: mail.example.com' })).toEqual({
			score: 88,
			passed: true,
			zeroed: false,
		});
	});

	it('policy not covering its own MX is GRADED, not zeroed', async () => {
		// The control is live and enforcing; one MX host sits outside its coverage.
		expect(
			await measure({ policy: 'version: STSv1\nmode: enforce\nmx: other.example.net\nmax_age: 604800' }),
		).toEqual({ score: 90, passed: true, zeroed: false });
	});

	it('mode: none (protection switched off) is a graded medium, tied with silence', async () => {
		expect(await measure({ policy: 'version: STSv1\nmode: none\nmx: mail.example.com\nmax_age: 604800' })).toEqual({
			score: 85,
			passed: true,
			zeroed: false,
		});
	});

	it('mode: testing is a light deduction — report-only protection still beats a broken policy', async () => {
		expect(
			await measure({ policy: 'version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800' }),
		).toEqual({ score: 95, passed: true, zeroed: false });
	});

	it('no MTA-STS record on a mail-receiving domain is a graded absence, never zeroed', async () => {
		expect(await measure({ sts: [], policy: null })).toEqual({ score: 85, passed: true, zeroed: false });
	});

	it('no MTA-STS record on a domain with NO MX is barely penalised (applicability fork)', async () => {
		// A domain that accepts no inbound mail cannot be penalised for an absent
		// inbound-mail control. Both records missing + no MX → the "not applicable" low.
		expect(await measure({ sts: [], mx: [], tlsrpt: [], policy: null })).toEqual({
			score: 95,
			passed: true,
			zeroed: false,
		});
	});
});

// ---------------------------------------------------------------------------
// The ordering invariant — the thing that actually has to hold.
// ---------------------------------------------------------------------------

describe('MTA-STS scoring ladder — relative ordering is the invariant', () => {
	it('enforcing valid > partial/misconfigured > mode:none >= no MTA-STS at all', async () => {
		const validEnforce = (await measure({})).score;
		const noMaxAge = (await measure({ policy: 'version: STSv1\nmode: enforce\nmx: mail.example.com' })).score;
		const uncoveredMx = (await measure({ policy: 'version: STSv1\nmode: enforce\nmx: other.example.net\nmax_age: 604800' }))
			.score;
		const modeNone = (await measure({ policy: 'version: STSv1\nmode: none\nmx: mail.example.com\nmax_age: 604800' })).score;
		const noPolicy = (await measure({ sts: [], policy: null })).score;

		const worstMisconfigured = Math.min(noMaxAge, uncoveredMx);

		expect(validEnforce).toBeGreaterThan(worstMisconfigured);
		expect(worstMisconfigured).toBeGreaterThan(modeNone);
		expect(modeNone).toBeGreaterThanOrEqual(noPolicy);
	});

	it('EVERY single-defect misconfigured policy scores STRICTLY BETTER than no policy', async () => {
		const noPolicy = (await measure({ sts: [], policy: null })).score;

		const misconfigured = {
			'invalid version': 'version: STSv2\nmode: enforce\nmx: mail.example.com\nmax_age: 604800',
			'no mode directive': 'version: STSv1\nmx: mail.example.com\nmax_age: 604800',
			'no mx: entries': 'version: STSv1\nmode: enforce\nmax_age: 604800',
			'no max_age': 'version: STSv1\nmode: enforce\nmx: mail.example.com',
			'MX not covered': 'version: STSv1\nmode: enforce\nmx: other.example.net\nmax_age: 604800',
		};

		const scores: Record<string, number> = {};
		for (const [name, policy] of Object.entries(misconfigured)) {
			scores[name] = (await measure({ policy })).score;
		}

		for (const [name, score] of Object.entries(scores)) {
			expect(score, `${name} must beat the no-policy baseline of ${noPolicy}`).toBeGreaterThan(noPolicy);
		}
	});

	it('a wholly invalid policy body stacks its deductions BELOW the absence baseline — intentional', async () => {
		// A body carrying none of version/mode/mx/max_age is not a policy at all: the domain
		// advertises MTA-STS in DNS and serves something else. That is misleading rather than
		// merely incomplete, so the four deductions are allowed to stack past the graded
		// absence baseline. Pinned so the behaviour is a decision, not an accident — and it
		// is still GRADED, never zeroed, and still `passed`.
		const noPolicy = (await measure({ sts: [], policy: null })).score;
		const garbage = await measure({ policy: 'garbage' });

		expect(garbage).toEqual({ score: 52, passed: true, zeroed: false });
		expect(garbage.score).toBeLessThan(noPolicy);
	});

	it('no misconfigured-policy state is ever ZEROED or failed', async () => {
		const policies = [
			'version: STSv2\nmode: enforce\nmx: mail.example.com\nmax_age: 604800',
			'version: STSv1\nmx: mail.example.com\nmax_age: 604800',
			'version: STSv1\nmode: enforce\nmax_age: 604800',
			'version: STSv1\nmode: enforce\nmx: mail.example.com',
			'version: STSv1\nmode: enforce\nmx: other.example.net\nmax_age: 604800',
		];

		for (const policy of policies) {
			const m = await measure({ policy });
			expect(m.zeroed, `policy "${policy.replace(/\n/g, ' | ')}" must not trip scoreIndicatesMissingControl`).toBe(false);
			expect(m.score, `policy "${policy.replace(/\n/g, ' | ')}" must not be zeroed`).toBeGreaterThan(0);
			expect(m.passed).toBe(true);
		}
	});
});

// ---------------------------------------------------------------------------
// The zeroing must be disarmed at the FINDING level, not just in aggregate.
// ---------------------------------------------------------------------------

describe('MTA-STS findings never assert a missing control', () => {
	const scenarios: Array<[string, Scenario]> = [
		['valid enforcing policy', {}],
		['policy omitting max_age', { policy: 'version: STSv1\nmode: enforce\nmx: mail.example.com' }],
		['policy with invalid version', { policy: 'version: STSv2\nmode: enforce\nmx: mail.example.com\nmax_age: 604800' }],
		['policy with no mode directive', { policy: 'version: STSv1\nmx: mail.example.com\nmax_age: 604800' }],
		['policy with no mx: entries', { policy: 'version: STSv1\nmode: enforce\nmax_age: 604800' }],
		['policy not covering its own MX', { policy: 'version: STSv1\nmode: enforce\nmx: other.example.net\nmax_age: 604800' }],
		['mode: none', { policy: 'version: STSv1\nmode: none\nmx: mail.example.com\nmax_age: 604800' }],
		['mode: testing', { policy: 'version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800' }],
		['no MTA-STS record (MX present)', { sts: [], policy: null }],
		['no MTA-STS record, no MX', { sts: [], mx: [], tlsrpt: [], policy: null }],
		['policy file returns 404', { policy: null }],
		['policy file redirects', { redirect: true }],
		['policy file oversized', { oversized: true }],
	];

	for (const [name, scenario] of scenarios) {
		it(`"${name}" — every finding fails scoreIndicatesMissingControl individually`, async () => {
			const result = await run(scenario);
			expect(result.findings.length).toBeGreaterThan(0);
			for (const finding of result.findings) {
				expect(
					scoreIndicatesMissingControl([finding]),
					`finding "${finding.title}" (${finding.severity}) must not assert a missing control`,
				).toBe(false);
			}
		});
	}

	it('POSITIVE CONTROL — the guard still fires on a genuinely missing control', async () => {
		// Per the diagnostic-harness rule: prove the assertion above DISCRIMINATES.
		// Same prose the MTA-STS findings carry, at the severity that arms the regex.
		expect(
			scoreIndicatesMissingControl([
				{ category: 'mta_sts', title: 'MTA-STS policy missing max_age', severity: 'high', detail: 'x' },
			]),
		).toBe(true);
		expect(
			scoreIndicatesMissingControl([
				{ category: 'mta_sts', title: 'MTA-STS policy missing max_age', severity: 'medium', detail: 'x' },
			]),
		).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// The interpolation hazard: a domain's own NAME must not move its score.
// ---------------------------------------------------------------------------

describe('MTA-STS scoring is independent of the scanned domain NAME', () => {
	// `MISSING_CONTROL_REGEX` matches "missing"/"required"/"not found" anywhere in a
	// finding's title OR detail — including a domain name interpolated into it. Every
	// mta_sts finding that interpolates the domain must therefore sit below the
	// arming severity. Measured live 2026-08-20 on the dnssec category: github.com
	// scored 60 and missingkids.org scored 0 on byte-identical findings.
	const names = ['example.com', 'missingkids.org', 'requiredfields.co.nz', 'notfound.example'];

	it('an unfetchable policy scores the same for every domain name', async () => {
		const scores = await Promise.all(
			names.map(async (domain) => (await measure({ domain, policy: null })).score),
		);
		expect(new Set(scores).size, `scores diverged by domain name: ${JSON.stringify(scores)}`).toBe(1);
	});

	it('a policy omitting max_age scores the same for every domain name', async () => {
		const scores = await Promise.all(
			names.map(
				async (domain) => (await measure({ domain, policy: 'version: STSv1\nmode: enforce\nmx: mail.example.com' })).score,
			),
		);
		expect(new Set(scores).size, `scores diverged by domain name: ${JSON.stringify(scores)}`).toBe(1);
	});

	it('an absent MTA-STS record scores the same for every domain name', async () => {
		const scores = await Promise.all(
			names.map(async (domain) => (await measure({ domain, sts: [], policy: null })).score),
		);
		expect(new Set(scores).size, `scores diverged by domain name: ${JSON.stringify(scores)}`).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// Deployed-but-unfetchable policy: the fifth branch the false comment named.
// ---------------------------------------------------------------------------

describe('MTA-STS deployed-but-unfetchable policy is graded, not zeroed', () => {
	it('policy file 404 is a graded deduction above the no-policy baseline', async () => {
		expect(await measure({ policy: null })).toEqual({ score: 88, passed: true, zeroed: false });
	});

	it('policy file redirect is a graded deduction above the no-policy baseline', async () => {
		expect(await measure({ redirect: true })).toEqual({ score: 88, passed: true, zeroed: false });
	});

	it('policy file oversized is a graded deduction above the no-policy baseline', async () => {
		expect(await measure({ oversized: true })).toEqual({ score: 88, passed: true, zeroed: false });
	});
});
