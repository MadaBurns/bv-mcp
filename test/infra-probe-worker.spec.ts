// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import infraProbeWorker, { handleDelegationConsistencyProbe } from '../src/workers/infra-probe';
import { ROOT_HINTS, ROOT_SERVER_NAMES } from '../src/lib/authoritative-dns-infra/root-hints';

describe('infra probe worker', () => {
	it('returns official root-hint baseline evidence for known root server hostnames', async () => {
		const response = await infraProbeWorker.fetch(new Request('https://infra-probe.internal/probe/authoritative-dns', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ hostname: 'A.Root-Servers.NET.' }),
		}));

		expect(response.status).toBe(200);
		const body = await response.json() as Record<string, unknown>;
		expect(body).toMatchObject({
			hostname: 'a.root-servers.net',
			reachability: {
				ipv4: { addresses: ['198.41.0.4'] },
				ipv6: { addresses: ['2001:503:ba3e::2:30'] },
			},
			rootPriming: {
				nsNames: ROOT_SERVER_NAMES,
				matchesOfficialHints: true,
			},
			transportParity: {
				ipv4Ipv6Parity: true,
			},
			operationalExposure: {
				ptrRecords: ['a.root-servers.net'],
			},
		});
		expect(body.errors).toEqual(['live_raw_dns_probe_not_configured']);
		expect(typeof body.checkedAt).toBe('string');
	});

	it('returns embedded root-server-set evidence', async () => {
		const response = await infraProbeWorker.fetch(new Request('https://infra-probe.internal/probe/root-server-set', {
			method: 'POST',
		}));

		expect(response.status).toBe(200);
		const body = await response.json() as Record<string, unknown>;
		expect(body).toMatchObject({
			hostname: '.',
			rootHints: ROOT_HINTS,
			observedRootServers: ROOT_SERVER_NAMES,
			parentChildDelegationMatches: true,
			glueMatchesHints: true,
			errors: ['live_root_server_set_probe_not_configured'],
		});
		expect(typeof body.checkedAt).toBe('string');
	});

	it('returns ordinary-zone parent/child delegation evidence through the injected probe seam', async () => {
		const response = await handleDelegationConsistencyProbe(
			new Request('https://infra-probe.internal/probe/delegation-consistency', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ hostname: 'Example.COM.' }),
			}),
			{
				recursiveQuery: async (name, type) => (name === 'com' && type === 'NS' ? ['a.gtld-servers.net'] : []),
				directQuery: async (server) => server === 'a.gtld-servers.net'
					? {
						aa: false, rcode: 0, answers: [],
						authority: [{ name: 'example.com', type: 2, data: 'ns.provider.net' }],
						additional: [],
					}
					: {
						aa: true, rcode: 0,
						answers: [{ name: 'example.com', type: 2, data: 'ns.provider.net' }],
						authority: [], additional: [],
					},
				now: () => new Date('2026-08-07T00:00:00.000Z'),
			},
		);

		expect(response.status).toBe(200);
		await expect(response.json()).resolves.toMatchObject({
			hostname: 'example.com',
			parentZone: 'com',
			parentDelegationNs: ['ns.provider.net'],
			childObservations: [{ nameserver: 'ns.provider.net', aaFlag: true }],
		});
	});

	it('returns a fixed delegation failure without exposing exception details', async () => {
		const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
		try {
			const response = await handleDelegationConsistencyProbe(
				new Request('https://infra-probe.internal/probe/delegation-consistency', {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ hostname: 'example.com' }),
				}),
				{
					recursiveQuery: async () => [],
					now: () => { throw new Error('secret resolver endpoint and stack'); },
				},
			);

			expect(response.status).toBe(502);
			await expect(response.json()).resolves.toEqual({ error: 'delegation_probe_failed' });
			expect(consoleError).toHaveBeenCalledWith('Delegation consistency probe failed');
		} finally {
			consoleError.mockRestore();
		}
	});

	it('rejects invalid authoritative DNS probe payloads', async () => {
		const response = await infraProbeWorker.fetch(new Request('https://infra-probe.internal/probe/authoritative-dns', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ hostname: '' }),
		}));

		expect(response.status).toBe(400);
		const body = await response.json() as { error?: string };
		expect(body.error).toBe('invalid_hostname');
	});

	it('rejects an oversized chunked probe body before JSON parsing', async () => {
		const response = await infraProbeWorker.fetch(new Request('https://infra-probe.internal/probe/authoritative-dns', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ hostname: 'a'.repeat(2000) }),
		}));

		expect(response.status).toBe(413);
		await expect(response.json()).resolves.toEqual({ error: 'request_body_too_large' });
	});
});
