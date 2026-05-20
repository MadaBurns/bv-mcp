// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { checkAuthoritativeDnsInfra } from '../src/tools/check-authoritative-dns-infra';

describe('checkAuthoritativeDnsInfra', () => {
	it('returns a partial worker-only result when the infra probe binding is absent', async () => {
		const result = await checkAuthoritativeDnsInfra('A.Root-Servers.NET.');

		expect(result).toMatchObject({
			category: 'authoritative_dns_infra',
			passed: true,
			partial: true,
			metadata: {
				evidenceMode: 'worker_only',
				hostname: 'a.root-servers.net',
			},
		});
		expect(result.findings).toContainEqual(
			expect.objectContaining({
				title: 'Authoritative DNS infra probe not configured',
				severity: 'info',
			}),
		);
	});

	it('posts the normalized hostname to the infra probe binding', async () => {
		const fetch = vi.fn(async () => new Response(JSON.stringify({
			hostname: 'a.root-servers.net',
			checkedAt: '2026-05-21T00:00:00.000Z',
			reachability: {
				ipv4: { addresses: ['198.41.0.4'], reachable: true },
				ipv6: { addresses: ['2001:503:ba3e::2:30'], reachable: true },
			},
			authoritative: { aaFlag: true, recursionAvailable: false },
		})));

		const result = await checkAuthoritativeDnsInfra('A.Root-Servers.NET.', {
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(fetch).toHaveBeenCalledOnce();
		const [url, init] = fetch.mock.calls[0];
		expect(url).toBe('https://infra-probe.internal/probe/authoritative-dns');
		expect(init).toMatchObject({
			method: 'POST',
			headers: { 'content-type': 'application/json' },
		});
		expect(JSON.parse(String(init?.body))).toEqual({ hostname: 'a.root-servers.net' });
		expect(result).toMatchObject({
			category: 'authoritative_dns_infra',
			passed: true,
			metadata: {
				evidenceMode: 'infra_probe',
				hostname: 'a.root-servers.net',
				checkedAt: '2026-05-21T00:00:00.000Z',
			},
		});
		expect(result.findings).toContainEqual(
			expect.objectContaining({
				title: 'Authoritative DNS infra probe evidence received',
				severity: 'info',
			}),
		);
	});
});
