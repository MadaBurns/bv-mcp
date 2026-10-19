// SPDX-License-Identifier: BUSL-1.1

/**
 * `probeDelegationConsistency` with NO `recursiveQuery` dependency, so the production
 * `defaultRecursiveQuery` runs. It is reached through the DoH transport with `globalThis.fetch` mocked
 * (dns-mock), never a live network; `directQuery` stays a fake so no TCP/53 is attempted.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { probeDelegationConsistency } from '../src/lib/authoritative-dns-infra/delegation-probe';
import type { DirectDnsResponse } from '../src/lib/authoritative-dns-infra/dns-tcp';
import { RecordType } from '../src/lib/dns-types';
import { createDohResponse, setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

const TYPE_CODES: Record<string, number> = { A: 1, NS: 2, AAAA: 28 };

function emptyResponse(): DirectDnsResponse {
	return { aa: false, rcode: 0, answers: [], authority: [], additional: [] };
}

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

describe('probeDelegationConsistency default recursive query', () => {
	it('resolves the parent zone NS set over DoH, keeping only NS answers, lowercased without the trailing dot', async () => {
		const { urls } = mockDoh((name, type) =>
			name === 'com' && type === 'NS'
				? [
						{ type: RecordType.NS, data: 'A.GTLD-SERVERS.NET.' },
						{ type: RecordType.NS, data: 'b.gtld-servers.net.' },
						{ type: RecordType.CNAME, data: 'ignored.gtld-servers.net.' },
					]
				: [],
		);
		const directQuery = vi.fn(async () => emptyResponse());

		const evidence = await probeDelegationConsistency('example.com', { directQuery });

		expect(urls[0]!.searchParams.get('name')).toBe('com');
		expect(urls[0]!.searchParams.get('type')).toBe('NS');
		expect(evidence.parentNameservers).toEqual(['a.gtld-servers.net', 'b.gtld-servers.net']);
		// The parents were then queried directly by exactly the normalized names, not over DoH.
		expect(directQuery.mock.calls.map((call) => (call as unknown[])[0]).sort()).toEqual(['a.gtld-servers.net', 'b.gtld-servers.net']);
	});

	it('records parent_ns_lookup_failed, not a throw, when the DoH transport fails', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('network down'));
		const directQuery = vi.fn(async () => emptyResponse());

		const evidence = await probeDelegationConsistency('example.com', { directQuery });

		expect(evidence.parentNameservers).toEqual([]);
		expect(evidence.errors).toContain('parent_ns_lookup_failed');
		expect(directQuery).not.toHaveBeenCalled();
	});
});
