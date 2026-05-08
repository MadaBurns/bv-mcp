// L1 regression: pre-fix the JWT branch in tier-auth.ts validated the `tier` claim
// against the full 6-tier TierSchema (free/agent/developer/enterprise/partner/owner).
// Today only owner/developer/enterprise are minted, so widening the verifier beyond
// what minters can produce is a defense-in-depth gap. Tightening the enum makes any
// future regression in putCode that quietly stores tier=agent or tier=partner a
// schema failure rather than a silent privilege grant.

import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { signJwt, newJti } from '../src/oauth/jwt';
import { resolveTier } from '../src/lib/tier-auth';
import { OAUTH_JWT_TTL_SECONDS } from '../src/lib/config';

const SECRET = 'a'.repeat(32);
const ISSUER = 'https://example.com';
const AUDIENCE = `${ISSUER}/mcp`;

async function mintWithTier(tier: string): Promise<string> {
	return signJwt(
		{ sub: 'subject', jti: newJti(), tier },
		{ secret: SECRET, ttlSeconds: OAUTH_JWT_TTL_SECONDS, issuer: ISSUER, audience: AUDIENCE },
	);
}

describe('resolveTier — JWT tier enum is restricted to owner/developer/enterprise', () => {
	const baseEnv = {
		// Intentionally NO BV_API_KEY so a non-matching JWT cleanly falls through to unauthenticated.
		OAUTH_SIGNING_SECRET: SECRET,
		OAUTH_ISSUER: ISSUER,
		SESSION_STORE: env.SESSION_STORE,
	};

	for (const allowed of ['owner', 'developer', 'enterprise'] as const) {
		it(`accepts tier=${allowed}`, async () => {
			const token = await mintWithTier(allowed);
			const result = await resolveTier(token, baseEnv, '203.0.113.1', `${ISSUER}/mcp`);
			expect(result.authenticated).toBe(true);
			expect(result.tier).toBe(allowed);
		});
	}

	for (const blocked of ['free', 'agent', 'partner'] as const) {
		it(`rejects tier=${blocked}`, async () => {
			const token = await mintWithTier(blocked);
			const result = await resolveTier(token, baseEnv, '203.0.113.1', `${ISSUER}/mcp`);
			expect(result.authenticated).toBe(false);
		});
	}

	it('rejects nonsense tier values', async () => {
		const token = await mintWithTier('superuser');
		const result = await resolveTier(token, baseEnv, '203.0.113.1', `${ISSUER}/mcp`);
		expect(result.authenticated).toBe(false);
	});
});
