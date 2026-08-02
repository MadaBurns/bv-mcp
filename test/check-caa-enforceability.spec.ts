// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

/**
 * CAA *enforceability* signals — distinct from the tag-completeness findings
 * covered by `check-caa.spec.ts`:
 *
 *  1. TTL. CA/Browser Forum TLS Baseline Requirements v2.2.8 §4.2.2.1: a CA may
 *     issue within the TTL of the CAA record "or 8 hours, whichever is greater".
 *     The window is a FLOOR, so a long TTL EXTENDS the period a CA may keep
 *     acting on a withdrawn policy.
 *  2. DNSSEC. BR §4.2.2.1.3 (CABF Ballot SC-085, in force 2026-03-15) requires
 *     DNSSEC validation of CAA lookups, but permits treating a lookup failure as
 *     permission to issue once the domain is confirmed "Insecure" per RFC 4035
 *     §4.3 — so over an unsigned zone the policy is strippable and advisory.
 */

/** Answer CAA for `domain` with a given TTL, and set the DoH AD flag. */
function mockCaa(records: string[], opts: { ttl: number; ad: boolean; domain?: string }) {
	const domain = opts.domain ?? 'example.com';
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const typeMatch = url.match(/[?&]type=([^&]+)/);
		const type = typeMatch ? typeMatch[1] : '';
		if (type === 'CAA') {
			const answers = records.map((data) => ({ name: domain, type: RecordType.CAA, TTL: opts.ttl, data }));
			return Promise.resolve(createDohResponse([{ name: domain, type: RecordType.CAA }], answers, { ad: opts.ad }));
		}
		return Promise.resolve(createDohResponse([{ name: domain, type: RecordType.NS }], []));
	});
}

const ALL_TAGS = ['0 issue "letsencrypt.org"', '0 issuewild "letsencrypt.org"', '0 iodef "mailto:admin@example.com"'];

async function run(domain = 'example.com') {
	const { checkCaa } = await import('../src/tools/check-caa');
	return checkCaa(domain);
}

describe('checkCaa — CAA reuse-window (TTL) staleness', () => {
	// Threshold is the 8-hour BR reuse-window FLOOR itself (28800s), and the comparison is
	// STRICT: at or below the floor the floor dominates and the TTL widens nothing. An earlier
	// revision used an arbitrary 24h; a 1,000-domain corpus (2026-08-03) observed a MAXIMUM CAA
	// TTL of 21600s (6h) across 135 RRsets, so that threshold could never fire.
	it('does not fire below the 8-hour BR floor (TTL is irrelevant there)', async () => {
		mockCaa(ALL_TAGS, { ttl: 21600, ad: false });
		const r = await run();
		expect(r.findings.some((f) => /reuse window/i.test(f.title))).toBe(false);
	});

	it('does not fire exactly AT the 8-hour floor (boundary is inclusive-safe)', async () => {
		mockCaa(ALL_TAGS, { ttl: 28800, ad: false });
		const r = await run();
		expect(r.findings.some((f) => /reuse window/i.test(f.title))).toBe(false);
	});

	it('fires low just above the 8-hour floor, where the TTL starts to govern', async () => {
		mockCaa(ALL_TAGS, { ttl: 28801, ad: false });
		const r = await run();
		const f = r.findings.find((x) => /reuse window/i.test(x.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
		// window === the TTL itself, never the floor, once the TTL is strictly greater.
		expect(f!.metadata).toMatchObject({ caaTtlSeconds: 28801, caaReuseWindowSeconds: 28801, caaReuseWindowFloorSeconds: 28800 });
	});

	it('fires low at 12 hours (previously silent under the arbitrary 24-hour threshold)', async () => {
		mockCaa(ALL_TAGS, { ttl: 43200, ad: false });
		const r = await run();
		const f = r.findings.find((x) => /reuse window/i.test(x.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
		expect(f!.detail).toMatch(/43200s \(12 hours\)/);
	});

	it('fires low above 24 hours and reports the resulting window', async () => {
		mockCaa(ALL_TAGS, { ttl: 604800, ad: false });
		const r = await run();
		const f = r.findings.find((x) => /reuse window/i.test(x.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
		expect(f!.detail).toMatch(/604800s \(7 days\)/);
		expect(f!.detail).toMatch(/whichever is greater/i);
		expect(f!.metadata).toMatchObject({ caaTtlSeconds: 604800, caaReuseWindowSeconds: 604800 });
	});

	it('uses the MINIMUM TTL across the RRset', async () => {
		const domain = 'example.com';
		globalThis.fetch = vi.fn().mockImplementation((url: string) => {
			const type = url.match(/[?&]type=([^&]+)/)?.[1] ?? '';
			if (type !== 'CAA') return Promise.resolve(createDohResponse([{ name: domain, type: RecordType.NS }], []));
			return Promise.resolve(
				createDohResponse(
					[{ name: domain, type: RecordType.CAA }],
					[
						{ name: domain, type: RecordType.CAA, TTL: 604800, data: ALL_TAGS[0] },
						{ name: domain, type: RecordType.CAA, TTL: 3600, data: ALL_TAGS[1] },
						{ name: domain, type: RecordType.CAA, TTL: 3600, data: ALL_TAGS[2] },
					],
				),
			);
		});
		const r = await run(domain);
		expect(r.findings.some((f) => /reuse window/i.test(f.title))).toBe(false);
	});

	it('never fires when there are no CAA records at all', async () => {
		mockCaa([], { ttl: 604800, ad: false });
		const r = await run();
		expect(r.findings.some((f) => f.title === 'No CAA records')).toBe(true);
		expect(r.findings.some((f) => /reuse window/i.test(f.title))).toBe(false);
	});
});

describe('checkCaa — CAA × DNSSEC enforceability pairing', () => {
	it('reports the policy as NOT DNSSEC-protected on an unsigned zone', async () => {
		mockCaa(ALL_TAGS, { ttl: 3600, ad: false });
		const r = await run();
		const f = r.findings.find((x) => x.title === 'CAA policy is not DNSSEC-protected');
		expect(f).toBeDefined();
		expect(f!.severity).toBe('info');
		expect(f!.detail).toMatch(/strip/i);
		expect(f!.detail).toMatch(/RFC 4035/);
		expect(f!.metadata).toMatchObject({ caaDnssecAuthenticated: false, caaEnforceable: false });
	});

	it('records positive evidence when the CAA answer is DNSSEC-authenticated', async () => {
		mockCaa(ALL_TAGS, { ttl: 3600, ad: true });
		const r = await run();
		const f = r.findings.find((x) => x.title === 'CAA policy is DNSSEC-protected');
		expect(f).toBeDefined();
		expect(f!.severity).toBe('info');
		expect(f!.metadata).toMatchObject({ caaDnssecAuthenticated: true, caaEnforceable: true });
		expect(r.findings.some((x) => x.title === 'CAA policy is not DNSSEC-protected')).toBe(false);
	});

	it('emits no pairing finding when there is no CAA policy to enforce', async () => {
		mockCaa([], { ttl: 300, ad: false });
		const r = await run();
		expect(r.findings.some((f) => /DNSSEC-protected/.test(f.title))).toBe(false);
	});
});

describe('checkCaa — enforceability is scoring-neutral where it must be', () => {
	it('an unsigned zone with complete tags still scores 100 and keeps controlPresent', async () => {
		// The pairing finding is `info` (0 penalty) precisely so it does not
		// double-penalize the `dnssec` category, which already scores signing.
		mockCaa(ALL_TAGS, { ttl: 3600, ad: false });
		const r = await run();
		expect(r.score).toBe(100);
		expect(r.passed).toBe(true);
		expect(r.controlPresent).toBe(true);
	});

	it('CAA absence remains a graded medium, never a category-zeroing missing control', async () => {
		mockCaa([], { ttl: 300, ad: false });
		const r = await run();
		expect(r.score).toBe(85);
		expect(r.passed).toBe(true);
		expect(r.findings.every((f) => f.metadata?.missingControl !== true)).toBe(true);
	});

	it('still emits the tag-completeness "properly configured" note alongside enforceability', async () => {
		mockCaa(ALL_TAGS, { ttl: 3600, ad: true });
		const r = await run();
		expect(r.findings.some((f) => f.title === 'CAA properly configured')).toBe(true);
	});
});

describe('checkCaa — inherited (non-apex) CAA attributes enforceability to the ancestor', () => {
	/** NS only at `ii.inc`; CAA only at `ii.inc` — so `mg.ii.inc` inherits by RFC 8659 climb. */
	function mockInherited(opts: { ttl: number; ad: boolean }) {
		globalThis.fetch = vi.fn().mockImplementation((url: string) => {
			const name = decodeURIComponent(url.match(/[?&]name=([^&]+)/)?.[1] ?? '').replace(/\.$/, '');
			const type = url.match(/[?&]type=([^&]+)/)?.[1] ?? '';
			if (type === 'NS' && name === 'ii.inc') {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: RecordType.NS }],
						[{ name, type: RecordType.NS, TTL: 86400, data: 'ns1.cloudflare.com.' }],
					),
				);
			}
			if (type === 'CAA' && name === 'ii.inc') {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: RecordType.CAA }],
						ALL_TAGS.map((data) => ({ name, type: RecordType.CAA, TTL: opts.ttl, data })),
						{ ad: opts.ad },
					),
				);
			}
			return Promise.resolve(createDohResponse([{ name, type: RecordType.NS }], []));
		});
	}

	it('names the ancestor (not the scanned label) in both enforceability findings', async () => {
		mockInherited({ ttl: 604800, ad: false });
		const r = await run('mg.ii.inc');
		const ttlFinding = r.findings.find((f) => /reuse window/i.test(f.title));
		const pairing = r.findings.find((f) => /DNSSEC-protected/.test(f.title));
		expect(ttlFinding?.detail).toMatch(/RRset at ii\.inc/);
		expect(pairing?.detail).toMatch(/RRset at ii\.inc/);
		expect(ttlFinding?.detail).not.toMatch(/mg\.ii\.inc/);
	});

	it('carries the ancestor AD flag through as positive evidence', async () => {
		mockInherited({ ttl: 300, ad: true });
		const r = await run('mg.ii.inc');
		expect(r.findings.some((f) => f.title === 'CAA policy is DNSSEC-protected')).toBe(true);
		expect(r.findings.some((f) => /inherited from ii\.inc/i.test(f.detail))).toBe(true);
	});
});
