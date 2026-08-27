// M1 regression: pre-fix the JWT branch in resolveTier accepted any owner-tier
// JWT for its full bearer lifetime without re-checking OWNER_ALLOW_IPS. The IP gate
// was only enforced once at /oauth/authorize consent, so anyone briefly on an
// allowlisted IP (compromised dev box, shared VPN, ephemeral cloud instance)
// could mint a token usable from any IP until expiry, with no revocation route.
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

async function mintDeveloperJwt(sub = 'dev-user', issuer = ISSUER, ttlSeconds = OAUTH_JWT_TTL_SECONDS): Promise<string> {
	return signJwt(
		{ sub, jti: newJti(), tier: 'developer' },
		{ secret: SECRET, ttlSeconds, issuer, audience: `${issuer}/mcp` },
	);
}

/** Mirror tier-auth's domain-separated OAuth principal derivation. */
async function expectedOAuthPrincipalHash(issuer: string, sub: string, kind: 'tenant' | 'owner' = 'tenant'): Promise<string> {
	const raw = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`oauth-${kind}\0${issuer}\0${sub}`)));
	return Array.from(raw)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

const baseEnv = {
	OAUTH_SIGNING_SECRET: SECRET,
	OAUTH_ISSUER: ISSUER,
	SESSION_STORE: env.SESSION_STORE,
	QUOTA_COORDINATOR: env.QUOTA_COORDINATOR,
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
		expect(result.keyHash).toBe(await expectedOAuthPrincipalHash(ISSUER, 'owner', 'owner'));
		expect(result.oauthTenantId).toBeUndefined();
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

describe('resolveTier — JWT path returns a stable OAuth-subject keyHash', () => {
	// Quota/concurrency principal selection is `tierAuthResult.keyHash ?? options.ip`
	// (mcp/execute.ts). If the JWT branch omits keyHash, paid (developer/enterprise)
	// callers fall back to client IP — a JWT reused across IPs multiplies the daily
	// quota, and NAT users share one bucket. The principal must also survive token
	// rotation: hashing the raw bearer/jti would let a subscriber multiply quotas
	// and lose ownership continuity by obtaining another hourly access token.
	it('two rotated JWTs for one issuer + subject resolve to the same 256-bit principal', async () => {
		const tokenA = await mintDeveloperJwt();
		const tokenB = await mintDeveloperJwt();
		expect(tokenA).not.toBe(tokenB);

		const resultA = await resolveTier(tokenA, { ...baseEnv }, '203.0.113.9', `${ISSUER}/mcp`);
		const resultB = await resolveTier(tokenB, { ...baseEnv }, '198.51.100.9', `${ISSUER}/mcp`);

		expect(resultA.authenticated).toBe(true);
		expect(resultA.tier).toBe('developer');
		expect(resultA.keyHash).toMatch(/^[0-9a-f]{64}$/);
		expect(resultA.keyHash).toBe(await expectedOAuthPrincipalHash(ISSUER, 'dev-user'));
		expect(resultB.keyHash).toBe(resultA.keyHash);
	});

	it('different subjects and issuers cannot share an OAuth principal', async () => {
		const otherIssuer = 'https://other.example.com';
		const sameIssuerA = await resolveTier(
			await mintDeveloperJwt('dev-a'),
			{ ...baseEnv },
			'203.0.113.9',
			`${ISSUER}/mcp`,
		);
		const sameIssuerB = await resolveTier(
			await mintDeveloperJwt('dev-b'),
			{ ...baseEnv },
			'203.0.113.9',
			`${ISSUER}/mcp`,
		);
		const otherIssuerResult = await resolveTier(
			await mintDeveloperJwt('dev-a', otherIssuer),
			{ ...baseEnv, OAUTH_ISSUER: otherIssuer },
			'203.0.113.9',
			`${otherIssuer}/mcp`,
		);

		expect(sameIssuerA.keyHash).not.toBe(sameIssuerB.keyHash);
		expect(otherIssuerResult.keyHash).not.toBe(sameIssuerA.keyHash);
	});

	it('namespaces owner OAuth away from a paid tenant whose id is literally owner', async () => {
		const ownerResult = await resolveTier(await mintOwnerJwt(), { ...baseEnv }, '203.0.113.1', `${ISSUER}/mcp`);
		const tenantResult = await resolveTier(await mintDeveloperJwt('owner'), { ...baseEnv }, '203.0.113.1', `${ISSUER}/mcp`);

		expect(ownerResult.keyHash).toBe(await expectedOAuthPrincipalHash(ISSUER, 'owner', 'owner'));
		expect(tenantResult.keyHash).toBe(await expectedOAuthPrincipalHash(ISSUER, 'owner', 'tenant'));
		expect(ownerResult.keyHash).not.toBe(tenantResult.keyHash);
	});

	it('rejects still-unexpired access tokens minted under the retired 90-day lifetime', async () => {
		const legacyToken = await mintDeveloperJwt('dev-user', ISSUER, 90 * 24 * 60 * 60);
		const result = await resolveTier(legacyToken, { ...baseEnv }, '203.0.113.9', `${ISSUER}/mcp`);

		expect(result).toEqual({ authenticated: false });
	});
});
