// SPDX-License-Identifier: BUSL-1.1

/**
 * `probeAuthoritativeDns` with NO `recursiveQuery` dependency, so the production `defaultRecursiveQuery`
 * runs. It is reached through the DoH transport with `globalThis.fetch` mocked (dns-mock), never a live
 * network: this workstation intercepts TCP/53 and a live probe abstains by design.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { probeAuthoritativeDns } from '../src/lib/authoritative-dns-infra/authoritative-probe';
import { RecordType } from '../src/lib/dns-types';
import { createDohResponse, setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

const TYPE_CODES: Record<string, number> = { A: 1, NS: 2, AAAA: 28 };

function mockDoh(answersFor: (name: string, type: string) => Array<{ type: number; data: string }>): { urls: URL[] } {
	const urls: URL[] = [];
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		urls.push(u);
		const name = u.searchParams.get('name') ?? '';
		const type = u.searchParams.get('type') ?? '';
		const answers = answersFor(name, type).map((answer) => ({ name, TTL: 300, ...answer }));
		return Promise.resolve(createDohResponse([{ name, type: TYPE_CODES[type] ?? -1 }], answers));
	});
	return { urls };
}

describe('probeAuthoritativeDns default recursive query', () => {
	it('resolves the zone NS set over DoH, keeping only NS answers, lowercased without the trailing dot', async () => {
		const { urls } = mockDoh((name, type) =>
			name === 'example.com' && type === 'NS'
				? [
						{ type: RecordType.NS, data: 'NS1.Example.COM.' },
						{ type: RecordType.NS, data: 'ns2.example.com.' },
						// A non-NS answer in the same response (a CNAME chain) must be filtered out.
						{ type: RecordType.CNAME, data: 'alias.example.com.' },
					]
				: [],
		);
		const resolveAddresses = vi.fn(async () => []);

		const evidence = await probeAuthoritativeDns('example.com', { resolveAddresses }, { activeProbes: false });

		expect(urls[0]!.searchParams.get('name')).toBe('example.com');
		expect(urls[0]!.searchParams.get('type')).toBe('NS');
		// Looked up once per address family (A and AAAA), hence the de-duplication.
		expect([...new Set(resolveAddresses.mock.calls.map((call) => (call as unknown[])[0]))].sort()).toEqual(['ns1.example.com', 'ns2.example.com']);
		// The nameservers resolved but exposed no address, so the lane records no contact rather than a verdict.
		expect(evidence.errors).toBeDefined();
	});

	it('falls through to the host address lookup when the DoH NS query returns nothing', async () => {
		const { urls } = mockDoh((name, type) => (name === 'host.example.com' && type === 'A' ? [{ type: RecordType.A, data: '192.0.2.10' }] : []));
		const resolveAddresses = vi.fn(async () => []);

		await probeAuthoritativeDns('host.example.com', { resolveAddresses }, { activeProbes: false });

		const asked = urls.map((u) => `${u.searchParams.get('name')}/${u.searchParams.get('type')}`);
		expect(asked).toEqual(expect.arrayContaining(['host.example.com/NS', 'host.example.com/A', 'host.example.com/AAAA']));
		// A resolvable host with no NS set is probed as its own nameserver.
		expect([...new Set(resolveAddresses.mock.calls.map((call) => (call as unknown[])[0]))]).toEqual(['host.example.com']);
	});

	it('abstains with an explicit error, not a throw, when the DoH transport fails', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('network down'));

		const evidence = await probeAuthoritativeDns('example.com', {}, { activeProbes: false });

		expect(evidence.hostname).toBe('example.com');
		expect(evidence.errors).toBeDefined();
		expect(evidence.reachability).toBeUndefined();
	});
});
