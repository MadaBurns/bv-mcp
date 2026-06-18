import { describe, expect, it, vi } from 'vitest';

describe('paid OAuth entitlement service binding', () => {
	it('validates developer entitlement responses from bv-web', async () => {
		const { fetchPaidOAuthEntitlement } = await import('../../src/oauth/entitlements');
		const fetcher = {
			fetch: vi.fn(
				async () =>
					new Response(
						JSON.stringify({
							subject: 'user_123',
							emailHash: 'a'.repeat(64),
							tier: 'developer',
							stripeCustomerId: 'cus_123',
							stripeSubscriptionId: 'sub_123',
							subscriptionStatus: 'active',
							scopes: ['mcp'],
							entitlementExpiresAt: 1893456000,
						}),
						{ status: 200, headers: { 'Content-Type': 'application/json' } },
					),
			),
		} as unknown as Fetcher;

		const entitlement = await fetchPaidOAuthEntitlement(
			{ BV_WEB: fetcher, BV_WEB_INTERNAL_KEY: 'internal-key' },
			{
				clientId: 'client_123',
				redirectUri: 'https://claude.ai/cb',
				codeChallenge: 'x'.repeat(43),
				scope: 'mcp',
			},
		);

		expect(entitlement?.tier).toBe('developer');
		expect(fetcher.fetch).toHaveBeenCalledOnce();
		const req = vi.mocked(fetcher.fetch).mock.calls[0][0] as Request;
		expect(req.url).toBe('https://internal/api/internal/mcp/oauth/authorize');
		expect(req.headers.get('authorization')).toBe('Bearer internal-key');
		expect(await req.json()).toEqual({
			clientId: 'client_123',
			redirectUri: 'https://claude.ai/cb',
			codeChallenge: 'x'.repeat(43),
			scope: 'mcp',
		});
	});

	it('rejects invalid or escalated bv-web entitlement responses', async () => {
		const { fetchPaidOAuthEntitlement } = await import('../../src/oauth/entitlements');
		const fetcher = {
			fetch: vi.fn(
				async () =>
					new Response(
						JSON.stringify({
							subject: 'user_123',
							tier: 'owner',
							stripeCustomerId: 'cus_123',
							stripeSubscriptionId: 'sub_123',
							subscriptionStatus: 'active',
							scopes: ['mcp'],
						}),
						{ status: 200, headers: { 'Content-Type': 'application/json' } },
					),
			),
		} as unknown as Fetcher;

		await expect(
			fetchPaidOAuthEntitlement(
				{ BV_WEB: fetcher, BV_WEB_INTERNAL_KEY: 'internal-key' },
				{
					clientId: 'client_123',
					redirectUri: 'https://claude.ai/cb',
					codeChallenge: 'x'.repeat(43),
					scope: 'mcp',
				},
			),
		).rejects.toThrow('Invalid OAuth entitlement response');
	});

	it('builds customer code records without copying raw billing metadata into JWT claims', async () => {
		const { buildCodeRecordFromEntitlement } = await import('../../src/oauth/entitlements');
		const codeRecord = buildCodeRecordFromEntitlement({
			clientId: 'client_123',
			redirectUri: 'https://claude.ai/cb',
			codeChallenge: 'x'.repeat(43),
			scope: 'mcp',
			entitlement: {
				subject: 'user_123',
				emailHash: 'a'.repeat(64),
				tier: 'developer',
				stripeCustomerId: 'cus_123',
				stripeSubscriptionId: 'sub_123',
				subscriptionStatus: 'active',
				scopes: ['mcp'],
				entitlementExpiresAt: 1893456000,
			},
		});

		expect(codeRecord).toMatchObject({
			client_id: 'client_123',
			redirect_uri: 'https://claude.ai/cb',
			code_challenge: 'x'.repeat(43),
			scope: 'mcp',
			subject: 'user_123',
			tier: 'developer',
			stripeCustomerId: 'cus_123',
			stripeSubscriptionId: 'sub_123',
		});
	});

	it('omits Stripe IDs from the code record when the entitlement has none', async () => {
		const { buildCodeRecordFromEntitlement } = await import('../../src/oauth/entitlements');
		const rec = buildCodeRecordFromEntitlement({
			clientId: 'client-1',
			redirectUri: 'https://claude.ai/api/mcp/auth_callback',
			codeChallenge: 'a'.repeat(43),
			entitlement: {
				subject: 'tenant_abc',
				tier: 'developer',
				subscriptionStatus: 'active',
				scopes: ['mcp'],
			},
		});
		expect(rec.subject).toBe('tenant_abc');
		expect(rec.tier).toBe('developer');
		expect('stripeCustomerId' in rec).toBe(false);
		expect('stripeSubscriptionId' in rec).toBe(false);
	});
});
