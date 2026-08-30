// SPDX-License-Identifier: BUSL-1.1

/**
 * Attribution honesty under degraded lookups (#832) and registered-but-dark
 * visibility (#831) for `check_lookalikes`.
 *
 * #832 (measured 2026-08-29, jcpenney.com): a throttled run — the SEED's own
 * NS lookup failed — published `third_party` ("no ownership signal links it…")
 * plus an impersonation-shaped finding for a candidate that near-complete runs
 * prove is `owned_by_seed` on a full 8/8 NS match. The signals were not
 * absent; they were UNFETCHED. A definitive `third_party` requires the same
 * completeness bar `owned_by_seed` already implies, so a degraded comparison
 * must yield `unmeasured` and suppress the impersonation-shaped finding.
 *
 * #831 (measured 2026-08-29, febreeze.com): a candidate that resolves NS but
 * has no A and no MX was silently dropped by the capability gate, so "held
 * and dark" (a defensive Azure-DNS registration) rendered identically to
 * "unregistered".
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

function nsResponse(name: string, hosts: string[]) {
	return createDohResponse(
		[{ name, type: 2 }],
		hosts.map((data) => ({ name, type: 2, TTL: 300, data })),
	);
}

function aResponse(name: string) {
	return createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]);
}

function mxResponse(name: string) {
	return createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: `10 mail.${name}.` }]);
}

function empty() {
	return createDohResponse([], []);
}

async function run(domain = 'test.com') {
	const { checkLookalikes } = await import('../src/tools/check-lookalikes');
	return checkLookalikes(domain);
}

const isNs = (type: string) => type === 'NS' || type === '2';
const isA = (type: string) => type === 'A' || type === '1';
const isMx = (type: string) => type === 'MX' || type === '15';

describe('checkLookalikes - degraded ownership comparison (#832)', () => {
	/**
	 * Fixture: the seed's own NS lookup FAILS (throttled), while the candidate
	 * `tst.com` resolves cleanly with NS + A + MX. In a healthy run the same
	 * candidate would be compared against the seed's NS set; in this run there
	 * is nothing to compare against, so no definitive attribution is possible.
	 */
	function mockSeedNsFailure(): void {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'test.com' && isNs(type)) {
				return Promise.reject(new Error('DNS timeout'));
			}
			if (name === 'tst.com') {
				if (isNs(type)) return Promise.resolve(nsResponse(name, ['ns1-05.azure-dns.com.', 'ns2-05.azure-dns.net.']));
				if (isA(type)) return Promise.resolve(aResponse(name));
				if (isMx(type)) return Promise.resolve(mxResponse(name));
			}
			return Promise.resolve(empty());
		});
	}

	it('emits an unmeasured ownership verdict, never third_party, when the seed NS lookup failed', async () => {
		mockSeedNsFailure();
		const result = await run('test.com');

		const attribution = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'tst.com' && f.metadata?.findingAxis === 'attribution');
		expect(attribution.length).toBeGreaterThan(0);
		for (const f of attribution) {
			expect(f.metadata?.ownershipVerdict).toBe('unmeasured');
			expect(f.severity).toBe('info');
		}
		// The definitive negative must not appear anywhere in the run: the
		// signals were unfetched, not absent.
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(false);
		expect(JSON.stringify(result.findings)).not.toContain('no ownership signal links it');
	});

	it('suppresses the impersonation-shaped finding for candidates whose ownership comparison was degraded', async () => {
		mockSeedNsFailure();
		const result = await run('test.com');

		expect(result.findings.some((f) => /Impersonation-shaped/i.test(f.title))).toBe(false);
		expect(result.findings.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(false);
		// The run-level scan_status notice tells the consumer WHY attribution is
		// absent, so the non-answer is visible rather than silent.
		const notice = result.findings.find((f) => f.metadata?.findingAxis === 'scan_status' && /ownership/i.test(f.title));
		expect(notice).toBeDefined();
		expect(notice!.severity).toBe('info');
	});

	it('control: a healthy seed NS lookup still yields third_party and the threat observation (no over-suppression)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'test.com' && isNs(type)) {
				return Promise.resolve(nsResponse(name, ['ns1.cloudflare.com.', 'ns2.cloudflare.com.']));
			}
			if (name === 'tst.com') {
				if (isNs(type)) return Promise.resolve(nsResponse(name, ['ns1.attacker-dns.com.']));
				if (isA(type)) return Promise.resolve(aResponse(name));
				if (isMx(type)) return Promise.resolve(mxResponse(name));
			}
			return Promise.resolve(empty());
		});
		const result = await run('test.com');

		const tst = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'tst.com');
		expect(tst.some((f) => f.metadata?.findingAxis === 'attribution' && f.metadata?.ownershipVerdict === 'third_party')).toBe(true);
		expect(tst.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(true);
	});
});
