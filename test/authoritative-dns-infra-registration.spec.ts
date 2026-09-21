// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { TOOLS } from '../src/schemas/tool-definitions';
import { TOOL_SCHEMA_MAP } from '../src/schemas/tool-args';
import { handleToolsCall, handleToolsList } from '../src/handlers/tools';
import { scanDomain } from '../src/tools/scan-domain';
import { ROOT_HINTS } from '../src/lib/authoritative-dns-infra/root-hints';

/** Fake infra-probe binding: the root-server-set request carries no domain (body `{}`), the
 * authoritative request's `activeProbes` flag decides whether zone-transfer evidence (the
 * AXFR-refusal capability) is present — mirroring what the sidecar does once wired live. */
function fakeInfraProbeFetch(): typeof globalThis.fetch {
	return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		if (String(input).includes('/probe/root-server-set')) {
			return new Response(JSON.stringify({ hostname: '.', checkedAt: '2026-09-22T00:00:00.000Z', rootHints: ROOT_HINTS }));
		}
		const body = JSON.parse(String(init?.body ?? '{}')) as { hostname?: string; activeProbes?: boolean };
		return new Response(JSON.stringify({
			hostname: body.hostname,
			checkedAt: '2026-09-22T00:00:00.000Z',
			reachability: { ipv4: { addresses: ['198.41.0.4'], reachable: true } },
			authoritative: { aaFlag: true, recursionAvailable: false, recursionRefused: true },
			...(body.activeProbes === true ? { zoneTransfer: { axfrRefused: true } } : {}),
		}));
	}) as unknown as typeof globalThis.fetch;
}

describe('authoritative DNS infra registration', () => {
	it('registers direct MCP tools and schemas for authoritative infra checks', () => {
		const names = TOOLS.map((tool) => tool.name);

		expect(names).toContain('check_authoritative_dns_infra');
		expect(names).toContain('check_root_server_set');
		expect(Object.keys(TOOL_SCHEMA_MAP)).toEqual(expect.arrayContaining([
			'check_authoritative_dns_infra',
			'check_root_server_set',
		]));

		const rootSet = TOOLS.find((tool) => tool.name === 'check_root_server_set');
		expect(rootSet).toMatchObject({
			group: 'infrastructure',
			tier: 'core',
			scanIncluded: false,
		});
		expect(rootSet?.inputSchema.required ?? []).toEqual([]);

		const listedNames = handleToolsList().tools.map((tool) => tool.name);
		expect(listedNames).toEqual(expect.arrayContaining([
			'check_authoritative_dns_infra',
			'check_root_server_set',
		]));
	});

	it('dispatches the root server set tool without requiring a domain argument', async () => {
		const result = await handleToolsCall({ name: 'check_root_server_set', arguments: {} });

		expect(result.isError).toBeUndefined();
		expect(result.content[0].text).toContain('Official root hints embedded');
	});

	it('runs only authoritative infrastructure checks for the authoritative_dns_infra profile', async () => {
		globalThis.fetch = vi.fn(async () => {
			throw new Error('scan_domain should not run default DoH or HTTPS checks for this profile');
		}) as unknown as typeof globalThis.fetch;

		const result = await scanDomain('a.root-servers.net', undefined, {
			profile: 'authoritative_dns_infra',
			forceRefresh: true,
		});

		expect(result.context.profile).toBe('authoritative_dns_infra');
		expect(result.checks).toHaveLength(1);
		expect(result.checks[0]).toMatchObject({
			category: 'authoritative_dns_infra',
			partial: true,
			metadata: {
				evidenceMode: 'worker_only',
			},
		});
		expect(result.checks[0].findings.map((finding) => finding.title)).toEqual(expect.arrayContaining([
			'Authoritative DNS infra probe not configured',
			'Official root hints embedded',
		]));
	});

	it('gates AXFR/CHAOS active probes on the caller tier for the authoritative_dns_infra profile (US-4 contract #5)', async () => {
		const anon = await scanDomain('infra-tier-anon.example', undefined, {
			profile: 'authoritative_dns_infra',
			forceRefresh: true,
			infraProbe: { fetch: fakeInfraProbeFetch() },
		});
		const anonSummary = anon.checks[0].metadata?.capabilitySummary as { passed: string[] };
		expect(anonSummary.passed).not.toContain('zone_transfer_refusal');

		const authed = await scanDomain('infra-tier-authed.example', undefined, {
			profile: 'authoritative_dns_infra',
			forceRefresh: true,
			infraProbe: { fetch: fakeInfraProbeFetch() },
			authTier: 'developer',
		});
		const authedSummary = authed.checks[0].metadata?.capabilitySummary as { passed: string[] };
		expect(authedSummary.passed).toContain('zone_transfer_refusal');
	});

	// US-4 contract addendum: the whole-scan
	// cache key for this profile must partition on the active-probe gate, or an authenticated
	// scan's AXFR/CHAOS-bearing result gets served to a later anonymous caller for the same
	// domain inside the 5-minute TTL (and the reverse hides measured capabilities from a
	// paying caller).
	it('keeps authenticated-scan AXFR evidence out of a later anonymous scan of the same domain', async () => {
		const domain = 'infra-cache-partition.example';
		const fetch = fakeInfraProbeFetch();

		const authed = await scanDomain(domain, undefined, {
			profile: 'authoritative_dns_infra',
			forceRefresh: true,
			infraProbe: { fetch },
			authTier: 'developer',
		});
		const authedSummary = authed.checks[0].metadata?.capabilitySummary as { passed: string[] };
		expect(authedSummary.passed).toContain('zone_transfer_refusal');
		const callsAfterAuthed = (fetch as ReturnType<typeof vi.fn>).mock.calls.length;

		// Deliberately NOT force_refresh — this is exactly the case a shared cache key would
		// serve stale AXFR/CHAOS evidence to an anonymous caller.
		const anon = await scanDomain(domain, undefined, {
			profile: 'authoritative_dns_infra',
			infraProbe: { fetch },
		});
		expect((fetch as ReturnType<typeof vi.fn>).mock.calls.length).toBeGreaterThan(callsAfterAuthed);
		const anonSummary = anon.checks[0].metadata?.capabilitySummary as { passed: string[] };
		expect(anonSummary.passed).not.toContain('zone_transfer_refusal');
	});
});
