import { describe, expect, it } from 'vitest';

describe('oauth schemas', () => {
	it('RegisterRequestSchema accepts minimal valid body', async () => {
		const { RegisterRequestSchema } = await import('../../src/schemas/oauth');
		const parsed = RegisterRequestSchema.parse({
			redirect_uris: ['https://claude.ai/cb'],
			client_name: 'Claude',
		});
		expect(parsed.token_endpoint_auth_method).toBe('none');
	});

	it('RegisterRequestSchema rejects missing redirect_uris', async () => {
		const { RegisterRequestSchema } = await import('../../src/schemas/oauth');
		expect(() => RegisterRequestSchema.parse({ client_name: 'x' })).toThrow();
	});

	it('AuthorizeQuerySchema rejects missing PKCE', async () => {
		const { AuthorizeQuerySchema } = await import('../../src/schemas/oauth');
		expect(() =>
			AuthorizeQuerySchema.parse({
				client_id: 'c',
				redirect_uri: 'https://claude.ai/cb',
				response_type: 'code',
				state: 's',
			}),
		).toThrow(/code_challenge/);
	});

	it('AuthorizeQuerySchema rejects plain PKCE method', async () => {
		const { AuthorizeQuerySchema } = await import('../../src/schemas/oauth');
		expect(() =>
			AuthorizeQuerySchema.parse({
				client_id: 'c',
				redirect_uri: 'https://claude.ai/cb',
				response_type: 'code',
				state: 's',
				code_challenge: 'x',
				code_challenge_method: 'plain',
			}),
		).toThrow();
	});

	it('TokenRequestSchema accepts authorization_code grant', async () => {
		const { TokenRequestSchema } = await import('../../src/schemas/oauth');
		const parsed = TokenRequestSchema.parse({
			grant_type: 'authorization_code',
			code: 'abc',
			redirect_uri: 'https://claude.ai/cb',
			client_id: 'c',
			code_verifier: 'v'.repeat(43),
		});
		expect(parsed.grant_type).toBe('authorization_code');
	});

	it('PaidOAuthEntitlementResponseSchema accepts active developer entitlement metadata', async () => {
		const { PaidOAuthEntitlementResponseSchema } = await import('../../src/schemas/oauth');
		const parsed = PaidOAuthEntitlementResponseSchema.parse({
			subject: 'user_123',
			emailHash: 'a'.repeat(64),
			tier: 'developer',
			stripeCustomerId: 'cus_123',
			stripeSubscriptionId: 'sub_123',
			subscriptionStatus: 'active',
			scopes: ['mcp'],
			entitlementExpiresAt: 1893456000,
		});
		expect(parsed.tier).toBe('developer');
		expect(parsed.subscriptionStatus).toBe('active');
	});

	it('PaidOAuthEntitlementResponseSchema rejects owner escalation from Stripe-backed entitlements', async () => {
		const { PaidOAuthEntitlementResponseSchema } = await import('../../src/schemas/oauth');
		expect(() =>
			PaidOAuthEntitlementResponseSchema.parse({
				subject: 'user_123',
				tier: 'owner',
				stripeCustomerId: 'cus_123',
				stripeSubscriptionId: 'sub_123',
				subscriptionStatus: 'active',
				scopes: ['mcp'],
			}),
		).toThrow();
	});

	it('CodeRecordSchema accepts customer OAuth tier metadata', async () => {
		const { CodeRecordSchema } = await import('../../src/schemas/oauth');
		const parsed = CodeRecordSchema.parse({
			client_id: 'client_123',
			redirect_uri: 'https://claude.ai/cb',
			code_challenge: 'x'.repeat(43),
			issued_at: 1,
			scope: 'mcp',
			subject: 'user_123',
			tier: 'developer',
			stripeCustomerId: 'cus_123',
			stripeSubscriptionId: 'sub_123',
			subscriptionStatus: 'active',
			entitlementExpiresAt: 1893456000,
		});
		expect(parsed.subject).toBe('user_123');
		expect(parsed.tier).toBe('developer');
	});

	it('accepts an entitlement with no Stripe IDs (comped partner)', async () => {
		const { PaidOAuthEntitlementResponseSchema } = await import('../../src/schemas/oauth');
		const parsed = PaidOAuthEntitlementResponseSchema.parse({
			subject: 'tenant_abc',
			tier: 'developer',
			subscriptionStatus: 'active',
			scopes: ['mcp'],
		});
		expect(parsed.stripeCustomerId).toBeUndefined();
		expect(parsed.stripeSubscriptionId).toBeUndefined();
		expect(parsed.tier).toBe('developer');
	});
});
