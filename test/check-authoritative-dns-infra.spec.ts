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

	it('passes healthy infra probe evidence with a capability summary', async () => {
		const fetch = vi.fn(async () => new Response(JSON.stringify({
			hostname: 'a.root-servers.net',
			checkedAt: '2026-05-21T00:00:00.000Z',
			reachability: {
				ipv4: { addresses: ['198.41.0.4'], reachable: true },
				ipv6: { addresses: ['2001:503:ba3e::2:30'], reachable: true },
				udp53Reachable: true,
				tcp53Reachable: true,
			},
			authoritative: { aaFlag: true, recursionAvailable: false, recursionRefused: true },
			soaSerial: { serialsByNameserver: { 'a.root-servers.net': 2026052101 }, consistent: true },
			dnssec: { dnskeyPresent: true, dsPresent: true, rrsigPresent: true, validates: true },
			largeResponse: {
				edns0Supported: true,
				largeUdpResponseOk: true,
				truncatesWhenNeeded: true,
				tcpFallbackOk: true,
			},
			zoneTransfer: { axfrRefused: true, ixfrRefused: true },
			amplification: { maxAmplificationRatio: 4, risky: false },
			abuseResistance: { dnsCookiesSupported: true, responseRateLimited: false },
			transportParity: { ipv4Ipv6Parity: true },
			routing: {
				originAsns: [19836],
				expectedOriginAsns: [19836],
				rpkiStatus: 'valid',
				anycastPaths: ['iad', 'sfo', 'ams'],
				routeLeakOrHijackSignals: [],
			},
			vantage: { vantageCount: 3, latencyMsP50: 22, latencyMsP95: 88, jitterMs: 4, packetLossPct: 0 },
			operationalExposure: {
				rir: 'ARIN',
				ptrRecords: ['a.root-servers.net'],
				unsupportedQueriesRefused: true,
			},
		})));

		const result = await checkAuthoritativeDnsInfra('a.root-servers.net', {
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(result.passed).toBe(true);
		expect(result.score).toBe(100);
		expect(result.metadata?.capabilitySummary).toMatchObject({
			failed: [],
			passed: expect.arrayContaining([
				'dns53_udp_reachability',
				'authoritative_aa_flag',
				'rpki_roa_validity',
				'route_leak_hijack_alerts',
			]),
		});
		expect(result.findings).toContainEqual(
			expect.objectContaining({
				title: 'Authoritative DNS infrastructure checks passed',
				severity: 'info',
			}),
		);
	});

	it('fails risky infra probe evidence with capability-specific findings', async () => {
		const fetch = vi.fn(async () => new Response(JSON.stringify({
			hostname: 'a.root-servers.net',
			checkedAt: '2026-05-21T00:00:00.000Z',
			reachability: {
				ipv4: { addresses: ['198.41.0.4'], reachable: true },
				ipv6: { addresses: ['2001:503:ba3e::2:30'], reachable: false },
				udp53Reachable: false,
				tcp53Reachable: true,
			},
			authoritative: { aaFlag: false, recursionAvailable: true, recursionRefused: false },
			zoneTransfer: { axfrRefused: false, ixfrRefused: true },
			amplification: { maxAmplificationRatio: 64, risky: true },
			abuseResistance: { dnsCookiesSupported: false, responseRateLimited: false },
			transportParity: { ipv4Ipv6Parity: false },
			routing: {
				originAsns: [64496],
				expectedOriginAsns: [19836],
				rpkiStatus: 'invalid',
				anycastPaths: ['iad'],
				routeLeakOrHijackSignals: ['origin-asn-mismatch'],
			},
			vantage: { vantageCount: 2, latencyMsP95: 900, packetLossPct: 2.5 },
			operationalExposure: { ptrRecords: [], unsupportedQueriesRefused: false },
		})));

		const result = await checkAuthoritativeDnsInfra('a.root-servers.net', {
			infraProbe: { fetch: fetch as unknown as typeof globalThis.fetch },
		});

		expect(result.passed).toBe(false);
		expect(result.score).toBe(0);
		expect(result.metadata?.capabilitySummary).toMatchObject({
			failed: expect.arrayContaining([
				'dns53_udp_reachability',
				'authoritative_aa_flag',
				'recursion_ra_refused',
				'zone_transfer_refusal',
				'rpki_roa_validity',
				'route_leak_hijack_alerts',
			]),
		});
		expect(result.findings.map((finding) => finding.title)).toEqual(expect.arrayContaining([
			'UDP/53 is not reachable',
			'Authoritative AA flag missing',
			'Recursive service exposed',
			'Zone transfer is not refused',
			'RPKI origin validation failed',
			'Route leak or hijack signal observed',
		]));
	});
});
