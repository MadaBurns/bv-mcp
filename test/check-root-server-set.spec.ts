// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { ROOT_HINTS, ROOT_SERVER_NAMES } from '../src/lib/authoritative-dns-infra/root-hints';
import { checkRootServerSet } from '../src/tools/check-root-server-set';

describe('checkRootServerSet', () => {
	it('returns embedded official root hints when the infra probe binding is absent', async () => {
		const result = await checkRootServerSet();

		expect(result).toMatchObject({
			category: 'authoritative_dns_infra',
			passed: true,
			partial: true,
			metadata: {
				evidenceMode: 'worker_only',
				rootServers: ROOT_SERVER_NAMES,
			},
		});
		expect(result.findings).toContainEqual(
			expect.objectContaining({
				title: 'Official root hints embedded',
				severity: 'info',
			}),
		);
	});

	it('posts to the root-server-set probe and fails mismatched root infrastructure evidence', async () => {
		const fetch = vi.fn(async () => new Response(JSON.stringify({
			hostname: '.',
			checkedAt: '2026-05-21T00:00:00.000Z',
			rootHints: ROOT_HINTS,
			observedRootServers: ROOT_SERVER_NAMES.slice(0, -1),
			parentChildDelegationMatches: false,
			glueMatchesHints: false,
			serialsByRoot: {
				'a.root-servers.net': 2026052101,
				'b.root-servers.net': 2026052102,
			},
			dnskeyDigestsByRoot: {
				'a.root-servers.net': 'sha256:a',
				'b.root-servers.net': 'sha256:b',
			},
		})));

		const result = await checkRootServerSet({
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(fetch).toHaveBeenCalledOnce();
		const [url, init] = fetch.mock.calls[0];
		expect(url).toBe('https://infra-probe.internal/probe/root-server-set');
		expect(init).toMatchObject({
			method: 'POST',
			headers: { 'content-type': 'application/json' },
		});
		expect(JSON.parse(String(init?.body))).toEqual({});
		expect(result.passed).toBe(false);
		expect(result.score).toBe(0);
		expect(result.metadata?.capabilitySummary).toMatchObject({
			failed: expect.arrayContaining([
				'root_priming_ns_set',
				'root_glue_records',
				'root_servers_parent_child_delegation',
				'root_server_ns_soa_dnskey_cross_compare',
				'stale_root_zone_serial_detection',
			]),
		});
		expect(result.findings.map((finding) => finding.title)).toEqual(expect.arrayContaining([
			'Root server set mismatch',
			'Root glue does not match official hints',
			'Root parent/child delegation mismatch',
			'Root DNSKEY digests differ across roots',
			'Root zone serials differ across roots',
		]));
	});
});
