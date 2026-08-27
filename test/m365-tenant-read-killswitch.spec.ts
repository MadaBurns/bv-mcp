// SPDX-License-Identifier: BUSL-1.1

/**
 * M365 client-tenant read kill switch.
 *
 * The three active `identity_secops` tools are the only surface whose data path
 * requires authenticating into a CUSTOMER's Microsoft 365 / Entra tenant.
 * bv-mcp holds no tenant credential itself: it forwards over the `BV_WEB`
 * service binding carrying the trusted internal bearer, and bv-web-prod
 * exchanges an owner-consented OAuth token for a Graph read. Deprecated
 * `query_ual` is a local tombstone and never reaches this binding.
 *
 * The capability is withdrawn by never WIRING that binding, so no tenant read
 * is possible on any path (public `/mcp`, `/internal/tools/*`, service
 * binding). These tests pin the two properties that make that safe:
 *
 *   1. fail-closed — absent/garbage/`'false'` config ⇒ disabled;
 *   2. all-or-nothing — the binding and its bearer are dropped TOGETHER
 *      (wiring a bearer without a proxy, or vice versa, is the dangerous
 *      half-state this helper exists to make unrepresentable).
 */

import { describe, expect, it } from 'vitest';
import { isM365TenantReadEnabled, m365ProxyBindings } from '../src/lib/config';

const FAKE_BINDING = { fetch: async () => new Response('{}') } as unknown as Fetcher;

describe('isM365TenantReadEnabled — fail-closed', () => {
	it('is disabled when the var is absent (the production default)', () => {
		expect(isM365TenantReadEnabled({})).toBe(false);
	});

	it.each(['false', 'FALSE', 'True', '1', 'yes', 'on', '', ' true', 'true ', 'enabled'])(
		'is disabled for the non-canonical value %o',
		(value) => {
			expect(isM365TenantReadEnabled({ M365_TENANT_READS_ENABLED: value })).toBe(false);
		},
	);

	it('is enabled ONLY for the exact string "true"', () => {
		expect(isM365TenantReadEnabled({ M365_TENANT_READS_ENABLED: 'true' })).toBe(true);
	});
});

describe('m365ProxyBindings — the capability is withdrawn by not wiring it', () => {
	it('wires NEITHER the proxy nor the internal bearer when disabled', () => {
		const wired = m365ProxyBindings({ BV_WEB: FAKE_BINDING, BV_MCP_M365_KEY: 'm'.repeat(32) });
		expect(wired.m365Proxy).toBeUndefined();
		expect(wired.m365ProxyAuthToken).toBeUndefined();
	});

	it('does not leak the internal bearer even when the binding is present', () => {
		// The bearer is the credential bv-web-prod trusts. Dropping the proxy but
		// forwarding the token would hand a trusted secret to a disabled path.
		const wired = m365ProxyBindings({
			BV_WEB: FAKE_BINDING,
			BV_MCP_M365_KEY: 'm'.repeat(32),
			M365_TENANT_READS_ENABLED: 'false',
		});
		expect(Object.values(wired)).not.toContain('m'.repeat(32));
		expect(Object.keys(wired)).toHaveLength(0);
	});

	it('wires BOTH the proxy and the bearer when explicitly enabled', () => {
		const wired = m365ProxyBindings({
			BV_WEB: FAKE_BINDING,
			BV_MCP_M365_KEY: 'm'.repeat(32),
			M365_TENANT_READS_ENABLED: 'true',
		});
		expect(wired.m365Proxy).toBe(FAKE_BINDING);
		expect(wired.m365ProxyAuthToken).toBe('m'.repeat(32));
	});

	it('stays unwired when enabled but the dedicated M365 capability is absent or weak', () => {
		expect(m365ProxyBindings({ BV_WEB: FAKE_BINDING, M365_TENANT_READS_ENABLED: 'true' })).toEqual({});
		expect(m365ProxyBindings({ BV_WEB: FAKE_BINDING, BV_MCP_M365_KEY: 'too-short', M365_TENANT_READS_ENABLED: 'true' })).toEqual({});
	});

	it.each(['BV_API_KEY', 'OAUTH_SIGNING_SECRET', 'KV_ENVELOPE_KEY'] as const)(
		'stays unwired when the M365 capability aliases %s',
		(peerKey) => {
			const shared = 'm365-peer-alias-capability-32-bytes-minimum';
			expect(
				m365ProxyBindings({
					BV_WEB: FAKE_BINDING,
					BV_MCP_M365_KEY: shared,
					[peerKey]: shared,
					M365_TENANT_READS_ENABLED: 'true',
				}),
			).toEqual({});
		},
	);

	it('stays unwired when enabled on a self-host that has no BV_WEB binding', () => {
		const wired = m365ProxyBindings({ M365_TENANT_READS_ENABLED: 'true' });
		expect(wired.m365Proxy).toBeUndefined();
	});
});
