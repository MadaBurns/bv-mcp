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

describe('checkLookalikes - registered-but-dark candidates (#831)', () => {
	it('emits an info finding for an NS-resolved candidate with no A and no MX instead of dropping it silently', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'test.com' && isNs(type)) {
				return Promise.resolve(nsResponse(name, ['ns1.cloudflare.com.', 'ns2.cloudflare.com.']));
			}
			if (name === 'tst.com' && isNs(type)) {
				// Registered on Azure DNS, deliberately dark: A and MX both resolve
				// EMPTY (NOERROR, no answers) — the febreeze.com shape.
				return Promise.resolve(nsResponse(name, ['ns1-05.azure-dns.com.', 'ns2-05.azure-dns.net.', 'ns3-05.azure-dns.org.']));
			}
			return Promise.resolve(empty());
		});
		const result = await run('test.com');

		const dark = result.findings.find((f) => f.title === 'Registered, no active infrastructure: tst.com');
		expect(dark).toBeDefined();
		expect(dark!.severity).toBe('info');
		expect(dark!.metadata?.findingAxis).toBe('attribution');
		expect(dark!.metadata?.lookalikeDomain).toBe('tst.com');
		// Ownership-attribution lane applies the same as for active candidates.
		expect(dark!.metadata?.ownershipVerdict).toBe('third_party');
		// Not scored as impersonation-capable: no threat observation, nothing above info.
		expect(result.findings.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(false);
		expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
	});

	it('applies owned_by_seed attribution to an NS-only candidate sharing the seed nameserver set (defensive registration)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if ((name === 'test.com' || name === 'tst.com') && isNs(type)) {
				// Identical dedicated 2/2 NS set → owned_by_seed under classifyOwnership.
				return Promise.resolve(nsResponse(name, ['ns1.cloudflare.com.', 'ns2.cloudflare.com.']));
			}
			return Promise.resolve(empty());
		});
		const result = await run('test.com');

		const owned = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'tst.com');
		expect(owned.length).toBeGreaterThan(0);
		expect(owned.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(true);
		expect(owned.every((f) => f.severity === 'info')).toBe(true);
	});

	it('does NOT report registered-but-dark when the A/MX probe itself was degraded (absence unfetched, not measured)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'test.com' && isNs(type)) {
				return Promise.resolve(nsResponse(name, ['ns1.cloudflare.com.', 'ns2.cloudflare.com.']));
			}
			if (name === 'tst.com') {
				if (isNs(type)) return Promise.resolve(nsResponse(name, ['ns1-05.azure-dns.com.']));
				// The detail probe is throttled: A and MX lookups both REJECT.
				if (isA(type) || isMx(type)) return Promise.reject(new Error('DNS timeout'));
			}
			return Promise.resolve(empty());
		});
		const result = await run('test.com');

		// No dark claim from an absence never measured…
		expect(result.findings.some((f) => /Registered, no active infrastructure/.test(f.title))).toBe(false);
		// …but the candidate does not vanish silently either: the run reports
		// itself incomplete.
		const incomplete = result.findings.find((f) => /enumeration was incomplete/i.test(f.title));
		expect(incomplete).toBeDefined();
	});

	it('a dark candidate under a degraded seed NS lookup carries the unmeasured verdict (interplay with #832)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'test.com' && isNs(type)) {
				return Promise.reject(new Error('DNS timeout'));
			}
			if (name === 'tst.com' && isNs(type)) {
				return Promise.resolve(nsResponse(name, ['ns1-05.azure-dns.com.']));
			}
			return Promise.resolve(empty());
		});
		const result = await run('test.com');

		const dark = result.findings.find((f) => f.title === 'Registered, no active infrastructure: tst.com');
		expect(dark).toBeDefined();
		expect(dark!.metadata?.ownershipVerdict).toBe('unmeasured');
		expect(dark!.severity).toBe('info');
	});
});

describe('checkLookalikes - review follow-ups on the degraded-run contract (#847)', () => {
	/**
	 * A candidate whose A lookup RESOLVES while its MX lookup REJECTS is
	 * `probeDegraded`, but only half-measured: its mail capability was never
	 * observed. The enumeration contract ("complete: false means this set is a
	 * SAMPLE") must reflect that, or a partial run reads as a census.
	 */
	it('counts a half-degraded detail probe as unresolved, so the run is not reported complete', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'test.com' && isNs(type)) return Promise.resolve(nsResponse(name, ['ns1.test.com.']));
			if (name === 'tst.com') {
				if (isNs(type)) return Promise.resolve(nsResponse(name, ['ns1.other.com.']));
				if (isA(type)) return Promise.resolve(aResponse(name));
				// Mail capability never measured.
				if (isMx(type)) return Promise.reject(new Error('DNS timeout'));
			}
			return Promise.resolve(empty());
		});

		const result = await run('test.com');

		const withEnum = result.findings.find((f) => f.metadata?.enumeration !== undefined);
		expect(withEnum).toBeDefined();
		const enumeration = withEnum!.metadata!.enumeration as { complete: boolean; unresolvedCount: number };
		expect(enumeration.complete).toBe(false);
		expect(enumeration.unresolvedCount).toBeGreaterThan(0);
	});

	/**
	 * `classifyOwnership()` deliberately preserves `owned_by_seed` for an
	 * in-bailiwick candidate NS even when the seed NS lookup failed, so in a
	 * mixed batch NOT every registered candidate is unmeasured. The status
	 * finding must count the actual unmeasured verdicts, not the batch size.
	 */
	it('reports the true unmeasured count in a mixed batch, not every registered candidate', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'test.com' && isNs(type)) return Promise.reject(new Error('DNS timeout'));
			// In-bailiwick candidate: its NS sits under the seed domain, so ownership
			// is concluded from the candidate's own evidence despite the seed failure.
			if (name === 'tes.com') {
				if (isNs(type)) return Promise.resolve(nsResponse(name, ['ns1.test.com.']));
				if (isA(type)) return Promise.resolve(aResponse(name));
				if (isMx(type)) return Promise.resolve(mxResponse(name));
			}
			// Unrelated third-party NS: genuinely unmeasurable without the seed set.
			if (name === 'tst.com') {
				if (isNs(type)) return Promise.resolve(nsResponse(name, ['ns1.elsewhere.net.']));
				if (isA(type)) return Promise.resolve(aResponse(name));
				if (isMx(type)) return Promise.resolve(mxResponse(name));
			}
			return Promise.resolve(empty());
		});

		const result = await run('test.com');

		const notice = result.findings.find((f) => f.metadata?.unmeasuredCandidateCount !== undefined);
		expect(notice).toBeDefined();
		const claimed = notice!.metadata!.unmeasuredCandidateCount as number;
		const actualUnmeasured = result.findings.filter(
			(f) => f.metadata?.findingAxis === 'attribution' && f.metadata?.ownershipVerdict === 'unmeasured',
		).length;
		// The owned_by_seed candidate must not be counted as unmeasured.
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(true);
		expect(claimed).toBe(actualUnmeasured);
	});

	/**
	 * The degraded outcome is TRANSIENT. `check_lookalikes` is cached for an hour
	 * and the dispatcher skips cache writes only for `partial` results, so an
	 * unmeasured run must be marked partial — otherwise withheld verdicts are
	 * served for the full TTL after DNS recovers. Same contract the timeout path
	 * already honours.
	 */
	it('marks a degraded run partial so the non-answer is not cached for the TTL', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const { name, type } = parseDohQuery(input);
			if (name === 'test.com' && isNs(type)) return Promise.reject(new Error('DNS timeout'));
			if (name === 'tst.com') {
				if (isNs(type)) return Promise.resolve(nsResponse(name, ['ns1.elsewhere.net.']));
				if (isA(type)) return Promise.resolve(aResponse(name));
				if (isMx(type)) return Promise.resolve(mxResponse(name));
			}
			return Promise.resolve(empty());
		});

		const result = await run('test.com');
		expect(result.partial).toBe(true);
	});
});
