// SPDX-License-Identifier: BUSL-1.1

/**
 * `CheckResult.recordPresent` — "was a record published at all", as distinct from
 * `controlPresent`'s "is the control active/enforcing".
 *
 * WHY THIS EXISTS. `controlPresent` deliberately conflates ABSENT with INACTIVE, because its
 * only consumer (`detectDomainContext`) cares solely whether a control is doing work. That is
 * correct for profile detection and WRONG for anything rendering per-check UI, and a downstream
 * consumer (bv-web-prod PR #1964) discovered it the hard way: it wanted "is this control
 * configured?" and had nothing to read, so it inferred absence from
 *
 *   (a) `controlPresent === false`  → a PUBLISHED `p=none` DMARC reads false, so a real,
 *       medium-severity weakness would have rendered as "Optional — not set"; and
 *   (b) "pass-band score + a non-info finding" → which cannot separate an absent TLS-RPT
 *       (95, `low`) from a PRESENT-but-duplicated one (95, `low`).
 *
 * Both heuristics are unsound because the information genuinely was not in the payload. This
 * signal puts it there. The pairs below are the ones that are otherwise INDISTINGUISHABLE — each
 * pair holds score and severity fixed so the only thing separating them is `recordPresent`.
 *
 * Score-neutrality is asserted alongside: nothing in the scoring path reads this field, so every
 * score here must match what the same input produced before it existed.
 */
import { describe, it, expect } from 'vitest';
import {
	checkTLSRPT,
	checkSVCBHTTPS,
	checkCAA,
	checkMTASTS,
	checkBIMI,
	checkDMARC,
} from '../../index.js';
import type { DNSQueryFunction } from '../../types.js';

const D = 'x.test';

/** Resolver that answers only what a case explicitly publishes; apex resolves so nothing abstains. */
function resolver(map: Record<string, string[]> = {}): DNSQueryFunction {
	return async (name: string, type: string) =>
		map[`${type}:${name}`] ??
		(type === 'NS' && name === D ? ['ns1.x', 'ns2.x'] : type === 'A' && name === D ? ['192.0.2.1'] : []);
}
const noFetch = async (): Promise<never> => {
	throw new Error('fetch not available in this test');
};
const opts = { timeout: 3000 };

describe('recordPresent — published-but-weak is not absent', () => {
	it('separates a PUBLISHED p=none DMARC from a domain with no DMARC at all', async () => {
		const published = await checkDMARC(
			D,
			resolver({ [`TXT:_dmarc.${D}`]: ['v=DMARC1; p=none; rua=mailto:a@x.test; adkim=s; aspf=s'] }),
			opts,
		);
		const absent = await checkDMARC(D, resolver(), opts);

		// Both are non-enforcing, so `controlPresent` cannot tell them apart — that is by design.
		expect(published.controlPresent).toBe(false);
		expect(absent.controlPresent).toBe(false);

		// `recordPresent` is the discriminator.
		expect(published.recordPresent).toBe(true);
		expect(absent.recordPresent).toBe(false);
	});

	it('reports an enforcing DMARC as both published and active', async () => {
		const r = await checkDMARC(
			D,
			resolver({ [`TXT:_dmarc.${D}`]: ['v=DMARC1; p=reject; rua=mailto:a@x.test'] }),
			opts,
		);
		expect(r.recordPresent).toBe(true);
		expect(r.controlPresent).toBe(true);
	});
});

describe('recordPresent — absent vs present-but-imperfect at an IDENTICAL score', () => {
	it('separates absent TLS-RPT from a duplicated (published) one', async () => {
		const absent = await checkTLSRPT(D, resolver(), opts);
		const duplicated = await checkTLSRPT(
			D,
			resolver({
				[`TXT:_smtp._tls.${D}`]: [
					'v=TLSRPTv1; rua=mailto:a@x.test',
					'v=TLSRPTv1; rua=mailto:b@x.test',
				],
			}),
			opts,
		);

		// The trap: identical score, identical top severity. Nothing else distinguishes them.
		expect(absent.score).toBe(duplicated.score);
		expect(absent.findings.some((f) => f.severity === 'low')).toBe(true);
		expect(duplicated.findings.some((f) => f.severity === 'low')).toBe(true);

		expect(absent.recordPresent).toBe(false);
		expect(duplicated.recordPresent).toBe(true);
	});

	it('separates an absent HTTPS/SVCB record from a published one missing ALPN', async () => {
		const absent = await checkSVCBHTTPS(D, resolver(), opts);
		const present = await checkSVCBHTTPS(
			D,
			resolver({ [`HTTPS:${D}`]: ['1 . ipv4hint=192.0.2.1'] }),
			opts,
		);
		// Both land in the pass band carrying non-info findings.
		expect(absent.score).toBeGreaterThanOrEqual(85);
		expect(present.score).toBeGreaterThanOrEqual(85);

		expect(absent.recordPresent).toBe(false);
		expect(present.recordPresent).toBe(true);
	});

	it('reports a BIMI record that exists while DMARC is not enforcing as PUBLISHED', async () => {
		const r = await checkBIMI(
			D,
			resolver({ [`TXT:default._bimi.${D}`]: ['v=BIMI1; l=https://x.test/logo.svg'] }),
			{ ...opts, fetchFn: noFetch },
		);
		expect(r.controlPresent).toBe(false); // not enforcing ⇒ not an active control
		expect(r.recordPresent).toBe(true); // ...but the record IS published
	});
});

describe('recordPresent — genuine absence', () => {
	it('reports false for controls that published nothing', async () => {
		expect((await checkTLSRPT(D, resolver(), opts)).recordPresent).toBe(false);
		expect((await checkCAA(D, resolver(), opts)).recordPresent).toBe(false);
		expect((await checkMTASTS(D, resolver(), { ...opts, fetchFn: noFetch })).recordPresent).toBe(
			false,
		);
		expect((await checkBIMI(D, resolver(), { ...opts, fetchFn: noFetch })).recordPresent).toBe(
			false,
		);
	});

	it('reports true for a published CAA RRset', async () => {
		const r = await checkCAA(D, resolver({ [`CAA:${D}`]: ['0 issue "letsencrypt.org"'] }), opts);
		expect(r.recordPresent).toBe(true);
	});
});

describe('recordPresent is never inferred from an unmeasured state', () => {
	it('leaves recordPresent undefined when the query itself failed', async () => {
		// A throwing resolver means absence was never OBSERVED. `false` here would be a
		// fabricated measurement — the same class of error as scoring a timed-out check 0.
		const throwing: DNSQueryFunction = async (name: string, type: string) => {
			if (type === 'NS' && name === D) return ['ns1.x'];
			if (type === 'A' && name === D) return ['192.0.2.1'];
			throw new Error('SERVFAIL');
		};
		const svcb = await checkSVCBHTTPS(D, throwing, opts);
		expect(svcb.recordPresent).toBeUndefined();
	});
});

describe('recordPresent is score-neutral', () => {
	it('does not alter any category score or passed flag', async () => {
		// Pinned literals captured from the package BEFORE the field existed (1.14.0).
		expect((await checkTLSRPT(D, resolver(), opts)).score).toBe(95);
		expect((await checkCAA(D, resolver(), opts)).score).toBe(85);
		expect((await checkMTASTS(D, resolver(), { ...opts, fetchFn: noFetch })).score).toBe(95);
		expect((await checkBIMI(D, resolver(), { ...opts, fetchFn: noFetch })).score).toBe(95);
		expect((await checkSVCBHTTPS(D, resolver(), opts)).score).toBe(95);

		const pnone = await checkDMARC(
			D,
			resolver({ [`TXT:_dmarc.${D}`]: ['v=DMARC1; p=none; rua=mailto:a@x.test; adkim=s; aspf=s'] }),
			opts,
		);
		expect(pnone.score).toBe(80);
		expect(pnone.passed).toBe(true);
	});
});
