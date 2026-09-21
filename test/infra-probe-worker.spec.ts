// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import infraProbeWorker, { handleDelegationConsistencyProbe } from '../src/workers/infra-probe';
import { ROOT_HINTS } from '../src/lib/authoritative-dns-infra/root-hints';

describe('infra probe worker', () => {
	it('returns root-hint reference addresses for a root hostname, and nothing verdict-shaped', async () => {
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
		});
		expect(body.errors).toEqual(['live_raw_dns_probe_not_configured']);
		// The raw DNS lane issues no query. It once asserted `matchesOfficialHints: true`,
		// `ipv4Ipv6Parity: true` and `ptrRecords: [hostname]` (the input echoed back), which
		// check_authoritative_dns_infra published as 100 / passed. Reference data only.
		expect(Object.keys(body).sort()).toEqual(['checkedAt', 'errors', 'hostname', 'reachability']);
		expect(body.reachability).toEqual({
			ipv4: { addresses: ['198.41.0.4'] },
			ipv6: { addresses: ['2001:503:ba3e::2:30'] },
		});
		expect(typeof body.checkedAt).toBe('string');
	});

	it('returns embedded root hints for the root-server-set lane, and nothing verdict-shaped', async () => {
		const response = await infraProbeWorker.fetch(new Request('https://infra-probe.internal/probe/root-server-set', {
			method: 'POST',
		}));

		expect(response.status).toBe(200);
		const body = await response.json() as Record<string, unknown>;
		expect(body).toMatchObject({
			hostname: '.',
			rootHints: ROOT_HINTS,
			errors: ['live_root_server_set_probe_not_configured'],
		});
		// No query is issued, so nothing was "observed": the lane once returned
		// `observedRootServers` (a copy of the hints), `glueMatchesHints: true` and
		// `parentChildDelegationMatches: true`, which check_root_server_set published as 100.
		expect(Object.keys(body).sort()).toEqual(['checkedAt', 'errors', 'hostname', 'rootHints']);
		expect(typeof body.checkedAt).toBe('string');
	});

	// The seam, not the units: each side passed its own spec while the pair published
	// 100 / passed for lanes that query nothing. Drive the REAL worker through the REAL tools.
	it('makes both infra tools abstain end-to-end while its live lanes are unconfigured', async () => {
		const { checkAuthoritativeDnsInfra } = await import('../src/tools/check-authoritative-dns-infra');
		const { checkRootServerSet } = await import('../src/tools/check-root-server-set');
		const infraProbe = {
			fetch: ((input: RequestInfo | URL, init?: RequestInit) =>
				infraProbeWorker.fetch(new Request(input, init))) as typeof globalThis.fetch,
		};

		for (const result of [
			await checkAuthoritativeDnsInfra('a.root-servers.net', { infraProbe }),
			await checkAuthoritativeDnsInfra('example.com', { infraProbe }),
			await checkRootServerSet({ infraProbe }),
		]) {
			expect(result).toMatchObject({ passed: false, score: 0, checkStatus: 'error', partial: true });
			expect(result.metadata?.capabilitySummary).toMatchObject({ passed: [], failed: [] });
			expect(result.findings.every((finding) => finding.metadata?.unprovisioned === true)).toBe(true);
		}
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
