// M1 regression: pre-fix the JWT branch in resolveTier accepted any owner-tier
// JWT for its full 90-day TTL without re-checking OWNER_ALLOW_IPS. The IP gate
// was only enforced once at /oauth/authorize consent, so anyone briefly on an
// allowlisted IP (compromised dev box, shared VPN, ephemeral cloud instance)
// could mint a token usable from any IP for 90 days, with no revocation route.
//
// Fix: re-evaluate OWNER_ALLOW_IPS in the JWT branch when claims.tier === 'owner',
// downgrading to 'partner' when the request's clientIp isn't in the allowlist —
// mirroring the BV_API_KEY path.

import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { signJwt, newJti } from '../src/oauth/jwt';
import { resolveTier } from '../src/lib/tier-auth';
import { OAUTH_JWT_TTL_SECONDS } from '../src/lib/config';

const SECRET = 'a'.repeat(32);
const ISSUER = 'https://example.com';
const AUDIENCE = `${ISSUER}/mcp`;

async function mintOwnerJwt(): Promise<string> {
	return signJwt(
		{ sub: 'owner', jti: newJti(), tier: 'owner' },
		{ secret: SECRET, ttlSeconds: OAUTH_JWT_TTL_SECONDS, issuer: ISSUER, audience: AUDIENCE },
	);
}

const baseEnv = {
	OAUTH_SIGNING_SECRET: SECRET,
	OAUTH_ISSUER: ISSUER,
	SESSION_STORE: env.SESSION_STORE,
};

describe('resolveTier — owner-tier JWT IP rebind', () => {
	it('owner JWT from allowlisted IP → owner tier', async () => {
		const token = await mintOwnerJwt();
		const result = await resolveTier(
			token,
			{ ...baseEnv, OWNER_ALLOW_IPS: '203.0.113.1, 198.51.100.5' },
			'203.0.113.1',
			`${ISSUER}/mcp`,
		);
		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('owner');
	});

	it('owner JWT from non-allowlisted IP → downgraded to partner', async () => {
		const token = await mintOwnerJwt();
		const result = await resolveTier(
			token,
			{ ...baseEnv, OWNER_ALLOW_IPS: '203.0.113.1' },
			'10.20.30.40',
			`${ISSUER}/mcp`,
		);
		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('partner');
	});

	it('owner JWT with missing clientIp and configured allowlist → partner', async () => {
		const token = await mintOwnerJwt();
		const result = await resolveTier(
			token,
			{ ...baseEnv, OWNER_ALLOW_IPS: '203.0.113.1' },
			undefined,
			`${ISSUER}/mcp`,
		);
		expect(result.tier).toBe('partner');
	});

	it('owner JWT with empty/unset allowlist → owner (backward-compat for self-hosted)', async () => {
		const token = await mintOwnerJwt();
		const result = await resolveTier(
			token,
			{ ...baseEnv, OWNER_ALLOW_IPS: '' },
			'10.20.30.40',
			`${ISSUER}/mcp`,
		);
		expect(result.tier).toBe('owner');
	});
});
