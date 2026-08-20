// SPDX-License-Identifier: BUSL-1.1

/**
 * Lame delegation ("Sitting Ducks") detection in the NS check.
 *
 * A lame delegation is a parent zone pointing at nameservers that do not answer for
 * the zone. The exploitable shape is the PARTIAL one: the domain still resolves via
 * its healthy nameservers, so nothing looks broken, while an attacker who claims the
 * non-responsive nameserver at its DNS provider becomes authoritative for the zone
 * without touching the registrar.
 *
 * Workers cannot open a UDP socket to an individual nameserver, so reachability is
 * established through the recursive-resolver seam the rest of this codebase uses: a
 * delegated nameserver whose hostname has no address cannot be queried by anyone.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

const DOMAIN = 'example.com';
const SOA_DATA = 'ns1.provider-a.com. admin.example.com. 2024010101 3600 900 604800 86400';

interface MockOptions {
	/** Nameserver hostnames delegated in the parent zone. */
	nsRecords: string[];
	/** Subset of `nsRecords` that resolve to an address. Everything else answers empty. */
	reachable: string[];
	/** Nameserver hostnames whose address lookup THROWS (resolver flake, not evidence). */
	throwing?: string[];
	/** Nameserver hostnames reachable over IPv6 only (A empty, AAAA answers). */
	ipv6Only?: string[];
}

/**
 * Fetch mock that answers NS for the scanned domain and routes A/AAAA per-name so the
 * reachability of each individual nameserver can be controlled.
 */
function mockDelegation(opts: MockOptions) {
	const calls: Array<{ name: string; type: string }> = [];
	const nsAnswers = opts.nsRecords.map((data) => ({ name: DOMAIN, type: RecordType.NS, TTL: 86400, data }));

	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const nameMatch = url.match(/[?&]name=([^&]+)/);
		const typeMatch = url.match(/[?&]type=([^&]+)/);
		const name = nameMatch ? decodeURIComponent(nameMatch[1]).replace(/\.$/, '').toLowerCase() : '';
		const type = typeMatch ? typeMatch[1] : '';
		calls.push({ name, type });

		if (type === 'NS') {
			return Promise.resolve(createDohResponse([{ name: DOMAIN, type: RecordType.NS }], nsAnswers));
		}
		if (type === 'SOA') {
			return Promise.resolve(
				createDohResponse([{ name: DOMAIN, type: RecordType.SOA }], [{ name: DOMAIN, type: RecordType.SOA, TTL: 3600, data: SOA_DATA }]),
			);
		}
		if (type === 'A' || type === 'AAAA') {
			if ((opts.throwing ?? []).includes(name)) {
				return Promise.reject(new Error('Network error'));
			}
			if (type === 'A' && opts.reachable.includes(name)) {
				return Promise.resolve(
					createDohResponse([{ name, type: RecordType.A }], [{ name, type: RecordType.A, TTL: 300, data: '192.0.2.53' }]),
				);
			}
			if (type === 'AAAA' && (opts.ipv6Only ?? []).includes(name)) {
				return Promise.resolve(
					createDohResponse([{ name, type: RecordType.AAAA }], [{ name, type: RecordType.AAAA, TTL: 300, data: '2001:db8::53' }]),
				);
			}
			return Promise.resolve(createDohResponse([{ name, type: RecordType.A }], []));
		}
		return Promise.resolve(createDohResponse([], []));
	});

	return calls;
}

async function run(domain = DOMAIN) {
	const { checkNs } = await import('../src/tools/check-ns');
	return checkNs(domain);
}

describe('checkNs — lame delegation (Sitting Ducks)', () => {
	it('emits a CRITICAL finding when SOME delegated nameservers do not answer for the zone', async () => {
		mockDelegation({
			nsRecords: ['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			reachable: ['ns1.provider-a.com'],
		});
		const r = await run();

		const f = r.findings.find((finding) => finding.title.match(/lame delegation/i));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('critical');
		expect(f!.detail).toContain('ns2.provider-b.net');
		expect(f!.metadata?.lameDelegation).toBe('partial');
		expect(f!.metadata?.nonResolvingNameservers).toEqual(['ns2.provider-b.net']);
		expect(f!.metadata?.resolvingNameservers).toEqual(['ns1.provider-a.com']);
	});

	it('the partial case stays SCORED — it is a posture finding, not a measurement failure', async () => {
		mockDelegation({
			nsRecords: ['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			reachable: ['ns1.provider-a.com'],
		});
		const r = await run();

		// The zone still answers, so the category WAS measured: it must be graded, not excluded.
		expect(r.checkStatus).not.toBe('error');
		expect(r.partial).not.toBe(true);
		// The `critical` carries a real deduction (−40) rather than passing silently. It does
		// NOT zero the category — deliberately no `missingControl`, so the NS weight is
		// unchanged, and the finding's prose is guarded against MISSING_CONTROL_REGEX.
		expect(r.score).toBe(60);
	});

	it('routes the ALL-fail case to the inconclusive path instead of scoring it 0', async () => {
		mockDelegation({
			nsRecords: ['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			reachable: [],
		});
		const r = await run();

		// A whole-delegation resolution failure is not a posture reading — the category is
		// EXCLUDED from scoring (checkStatus 'error' + partial) rather than zeroed as a deficiency.
		expect(r.checkStatus).toBe('error');
		expect(r.partial).toBe(true);
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('low');
		expect(r.findings[0].title).toContain('not assessed');
		expect(r.findings[0].metadata?.errorKind).toBe('dns_error');
		expect(r.findings[0].metadata?.inconclusive).toBe(true);
	});

	it('the ALL-fail finding never claims the domain does not resolve', async () => {
		// `domainResolves: false` is the package's non-resolving guard key. This probe only
		// proves the nameserver HOSTS have no address, which cannot distinguish a dead zone
		// from a resolver-side outage — asserting it here would fabricate an NXDOMAIN verdict.
		mockDelegation({ nsRecords: ['ns1.provider-a.com.', 'ns2.provider-b.net.'], reachable: [] });
		const r = await run();
		expect(r.findings[0].metadata?.domainResolves).toBeUndefined();
	});

	it('stays silent when every delegated nameserver resolves', async () => {
		mockDelegation({
			nsRecords: ['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			reachable: ['ns1.provider-a.com', 'ns2.provider-b.net'],
		});
		const r = await run();

		expect(r.findings.some((f) => f.title.match(/lame delegation/i))).toBe(false);
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].title).toContain('properly configured');
		expect(r.passed).toBe(true);
	});

	it('does not flag an IPv6-only nameserver (AAAA fallback)', async () => {
		mockDelegation({
			nsRecords: ['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			reachable: ['ns1.provider-a.com'],
			ipv6Only: ['ns2.provider-b.net'],
		});
		const r = await run();

		expect(r.findings.some((f) => f.title.match(/lame delegation/i))).toBe(false);
		expect(r.checkStatus).not.toBe('error');
	});

	it('a THROWN probe is never reported as a lame nameserver (fail-soft, not evidence)', async () => {
		mockDelegation({
			nsRecords: ['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			reachable: ['ns1.provider-a.com'],
			throwing: ['ns2.provider-b.net'],
		});
		const r = await run();

		expect(r.findings.some((f) => f.title.match(/lame delegation/i))).toBe(false);
		expect(r.checkStatus).not.toBe('error');
	});

	it('every probe throwing leaves the rest of the NS result intact (indeterminate, not inconclusive)', async () => {
		mockDelegation({
			nsRecords: ['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			reachable: [],
			throwing: ['ns1.provider-a.com', 'ns2.provider-b.net'],
		});
		const r = await run();

		// No determinate outcome at all → emit nothing rather than manufacture a `total`
		// verdict from a flaky resolver.
		expect(r.findings.some((f) => f.title.match(/lame delegation|not assessed/i))).toBe(false);
		expect(r.checkStatus).not.toBe('error');
		expect(r.findings[0].title).toContain('properly configured');
	});

	it('probes at most 4 nameservers (bounded subrequest budget)', async () => {
		// 4 == MAX_LAME_DELEGATION_PROBES; the constant's own value is pinned in
		// packages/dns-checks/src/__tests__/checks/ns-lame-delegation.test.ts.
		const nsRecords = ['ns1.p.com.', 'ns2.p.com.', 'ns3.p.com.', 'ns4.p.com.', 'ns5.p.com.', 'ns6.p.com.'];
		const calls = mockDelegation({
			nsRecords,
			reachable: nsRecords.map((n) => n.replace(/\.$/, '')),
		});
		await run();

		const probed = new Set(calls.filter((c) => c.type === 'A' && c.name.startsWith('ns')).map((c) => c.name));
		expect(probed.size).toBe(4);
		// Healthy zone → exactly one query per probed nameserver, no AAAA fallback spent.
		expect(calls.filter((c) => c.type === 'AAAA' && c.name.startsWith('ns'))).toHaveLength(0);
	});

	it('does not probe when no NS records were returned (no wasted subrequests)', async () => {
		const calls = mockDelegation({ nsRecords: [], reachable: [] });
		const r = await run();

		expect(r.findings[0].title).toMatch(/No NS records/i);
		expect(calls.filter((c) => c.type === 'AAAA')).toHaveLength(0);
	});
});
