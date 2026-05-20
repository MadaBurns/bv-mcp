// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import infraProbeWorker from '../src/workers/infra-probe';
import { ROOT_HINTS, ROOT_SERVER_NAMES } from '../src/lib/authoritative-dns-infra/root-hints';

describe('infra probe worker skeleton', () => {
	it('returns deterministic authoritative DNS probe evidence', async () => {
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
				ipv4: { addresses: [] },
				ipv6: { addresses: [] },
			},
			errors: ['raw_authoritative_dns_probe_not_implemented'],
		});
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
			errors: ['raw_root_server_set_probe_not_implemented'],
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
