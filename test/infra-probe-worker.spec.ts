// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import infraProbeWorker from '../src/workers/infra-probe';
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
});
