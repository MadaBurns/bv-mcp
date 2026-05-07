// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: bv-web → bv-mcp OAuth entitlement tier surface.
 *
 * CLAUDE.md "Paid OAuth Tiers" is the source of truth: only `developer` and
 * `enterprise` tiers reach bv-mcp via OAuth. The `agent` tier is reserved for
 * static API-key authentication, not OAuth, so the entitlement schema must not
 * accept it. This contract test guards the bv-web ↔ bv-mcp Zod payload from
 * silently accepting an `agent` claim that downstream code (rate limiter, quota
 * coordinator) never expects from an OAuth principal.
 */
import { describe, expect, it } from 'vitest';

describe('CustomerOAuthTierSchema contract', () => {
	it('accepts developer (paid Pro/Business/MCP-Developer plan)', async () => {
		const { CustomerOAuthTierSchema } = await import('../../src/schemas/oauth');
		expect(CustomerOAuthTierSchema.safeParse('developer').success).toBe(true);
	});

	it('accepts enterprise (paid Enterprise/MCP-Enterprise plan)', async () => {
		const { CustomerOAuthTierSchema } = await import('../../src/schemas/oauth');
		expect(CustomerOAuthTierSchema.safeParse('enterprise').success).toBe(true);
	});

	it('rejects agent (static-API-key-only tier, never reachable via OAuth)', async () => {
		const { CustomerOAuthTierSchema } = await import('../../src/schemas/oauth');
		expect(CustomerOAuthTierSchema.safeParse('agent').success).toBe(false);
	});

	it('rejects owner (privileged tier, never minted by bv-web Stripe entitlements)', async () => {
		const { CustomerOAuthTierSchema } = await import('../../src/schemas/oauth');
		expect(CustomerOAuthTierSchema.safeParse('owner').success).toBe(false);
	});

	it('rejects free / unauthenticated tiers', async () => {
		const { CustomerOAuthTierSchema } = await import('../../src/schemas/oauth');
		expect(CustomerOAuthTierSchema.safeParse('free').success).toBe(false);
		expect(CustomerOAuthTierSchema.safeParse('partner').success).toBe(false);
	});

	it('PaidOAuthEntitlementResponseSchema rejects agent tier from bv-web', async () => {
		const { PaidOAuthEntitlementResponseSchema } = await import('../../src/schemas/oauth');
		const result = PaidOAuthEntitlementResponseSchema.safeParse({
			subject: 'user_123',
			tier: 'agent',
			stripeCustomerId: 'cus_123',
			stripeSubscriptionId: 'sub_123',
			subscriptionStatus: 'active',
			scopes: ['mcp'],
		});
		expect(result.success).toBe(false);
	});
});
