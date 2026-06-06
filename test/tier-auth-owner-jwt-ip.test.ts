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

async function mintDeveloperJwt(): Promise<string> {
	return signJwt(
		{ sub: 'dev-user', jti: newJti(), tier: 'developer' },
		{ secret: SECRET, ttlSeconds: OAUTH_JWT_TTL_SECONDS, issuer: ISSUER, audience: AUDIENCE },
	);
}

/** Mirror tier-auth's keyHash derivation: hex(SHA-256(rawBearerToken)). */
async function expectedKeyHash(token: string): Promise<string> {
	const raw = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
	return Array.from(raw)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
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

describe('resolveTier — JWT path returns a per-credential keyHash (BUG #5)', () => {
	// Quota/concurrency principal selection is `tierAuthResult.keyHash ?? options.ip`
	// (mcp/execute.ts). If the JWT branch omits keyHash, paid (developer/enterprise)
	// callers fall back to client IP — a JWT reused across IPs multiplies the daily
	// quota, and NAT users share one bucket. The JWT branch must return a stable
	// keyHash derived the SAME way as the static path: hex(SHA-256(rawBearerToken)).
	it('developer JWT → defined 64-hex keyHash matching hex(SHA-256(token))', async () => {
		const token = await mintDeveloperJwt();
		const result = await resolveTier(token, { ...baseEnv }, '203.0.113.9', `${ISSUER}/mcp`);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('developer');
		expect(result.keyHash).toBeDefined();
		expect(result.keyHash).toMatch(/^[0-9a-f]{64}$/);
		expect(result.keyHash).toBe(await expectedKeyHash(token));
	});
});
