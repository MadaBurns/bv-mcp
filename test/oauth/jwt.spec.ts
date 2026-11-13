import { afterEach, describe, expect, it, vi } from 'vitest';

const SECRET = 'x'.repeat(32);
const NOW = 1_700_000_000; // fixed epoch seconds for determinism

describe('oauth/jwt', () => {
	it('signJwt produces a three-segment token', async () => {
		const { signJwt } = await import('../../src/oauth/jwt');
		const token = await signJwt({ sub: 'owner', jti: 'j1' }, { secret: SECRET, ttlSeconds: 60, issuer: 'https://x', audience: 'https://y', now: NOW });
		expect(token.split('.')).toHaveLength(3);
	});

	it('verifyJwt accepts a freshly signed token', async () => {
		const { signJwt, verifyJwt } = await import('../../src/oauth/jwt');
		const token = await signJwt({ sub: 'owner', jti: 'j1' }, { secret: SECRET, ttlSeconds: 60, issuer: 'https://x', audience: 'https://y', now: NOW });
		const claims = await verifyJwt(token, { secret: SECRET, issuer: 'https://x', audience: 'https://y', now: NOW });
		expect(claims.sub).toBe('owner');
		expect(claims.jti).toBe('j1');
	});

	it('verifyJwt rejects expired token', async () => {
		const { signJwt, verifyJwt } = await import('../../src/oauth/jwt');
		const token = await signJwt({ sub: 'owner', jti: 'j1' }, { secret: SECRET, ttlSeconds: 10, issuer: 'https://x', audience: 'https://y', now: NOW });
		await expect(
			verifyJwt(token, { secret: SECRET, issuer: 'https://x', audience: 'https://y', now: NOW + 100 }),
		).rejects.toThrow(/expired/i);
	});

	it('verifyJwt rejects wrong signature (different secret)', async () => {
		const { signJwt, verifyJwt } = await import('../../src/oauth/jwt');
		const token = await signJwt({ sub: 'owner', jti: 'j1' }, { secret: SECRET, ttlSeconds: 60, issuer: 'https://x', audience: 'https://y', now: NOW });
		await expect(
			verifyJwt(token, { secret: 'y'.repeat(32), issuer: 'https://x', audience: 'https://y', now: NOW }),
		).rejects.toThrow(/signature/i);
	});

	it('verifyJwt rejects wrong issuer', async () => {
		const { signJwt, verifyJwt } = await import('../../src/oauth/jwt');
		const token = await signJwt({ sub: 'owner', jti: 'j1' }, { secret: SECRET, ttlSeconds: 60, issuer: 'https://x', audience: 'https://y', now: NOW });
		await expect(
			verifyJwt(token, { secret: SECRET, issuer: 'https://evil', audience: 'https://y', now: NOW }),
		).rejects.toThrow(/issuer/i);
	});

	it('verifyJwt rejects malformed token', async () => {
		const { verifyJwt } = await import('../../src/oauth/jwt');
		await expect(
			verifyJwt('not-a-jwt', { secret: SECRET, issuer: 'https://x', audience: 'https://y', now: NOW }),
		).rejects.toThrow(/malformed/i);
	});

	it('rejects a correctly signed legacy token whose minted lifetime exceeds the verifier maximum', async () => {
		const { signJwt, verifyJwt } = await import('../../src/oauth/jwt');
		const token = await signJwt(
			{ sub: 'tenant-1', jti: 'legacy-90-day' },
			{ secret: SECRET, ttlSeconds: 90 * 24 * 60 * 60, issuer: 'https://x', audience: 'https://y', now: NOW },
		);

		await expect(
			verifyJwt(token, {
				secret: SECRET,
				issuer: 'https://x',
				audience: 'https://y',
				now: NOW,
				maxLifetimeSeconds: 60 * 60,
			}),
		).rejects.toThrow('token lifetime exceeds maximum');
	});

	it('accepts a token exactly at the configured maximum lifetime', async () => {
		const { signJwt, verifyJwt } = await import('../../src/oauth/jwt');
		const token = await signJwt(
			{ sub: 'tenant-1', jti: 'one-hour' },
			{ secret: SECRET, ttlSeconds: 60 * 60, issuer: 'https://x', audience: 'https://y', now: NOW },
		);

		await expect(
			verifyJwt(token, {
				secret: SECRET,
				issuer: 'https://x',
				audience: 'https://y',
				now: NOW,
				maxLifetimeSeconds: 60 * 60,
			}),
		).resolves.toMatchObject({ sub: 'tenant-1', iat: NOW, exp: NOW + 60 * 60 });
	});

	it('rejects a token issued beyond the allowed clock skew', async () => {
		const { signJwt, verifyJwt } = await import('../../src/oauth/jwt');
		const token = await signJwt(
			{ sub: 'tenant-1', jti: 'future-token' },
			{ secret: SECRET, ttlSeconds: 60 * 60, issuer: 'https://x', audience: 'https://y', now: NOW + 31 },
		);

		await expect(
			verifyJwt(token, {
				secret: SECRET,
				issuer: 'https://x',
				audience: 'https://y',
				now: NOW,
				clockSkewSeconds: 30,
				maxLifetimeSeconds: 60 * 60,
			}),
		).rejects.toThrow('token issued in the future');
	});

	it('signJwt ignores attempts to override iss/aud via payload', async () => {
		const { signJwt, verifyJwt } = await import('../../src/oauth/jwt');
		const token = await signJwt(
			{ sub: 'owner', jti: 'j1', iss: 'evil', aud: 'evil', exp: 9999999999 } as never,
			{ secret: SECRET, ttlSeconds: 60, issuer: 'https://x', audience: 'https://y', now: NOW },
		);
		const claims = await verifyJwt(token, { secret: SECRET, issuer: 'https://x', audience: 'https://y', now: NOW });
		expect(claims.iss).toBe('https://x');
		expect(claims.aud).toBe('https://y');
		expect(claims.exp).toBe(NOW + 60);
	});

	it('verifyJwt rejects a token whose header alg is not HS256, even with a valid HS256 HMAC', async () => {
		// Forge a token: header says alg=none, body is normal claims, signature is the
		// correct HS256 HMAC over header.body. RFC 8725 §3.1 requires verifiers to pin
		// the expected alg to defend against algorithm-confusion / downgrade attacks.
		const b64url = (s: string) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
		const header = b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }));
		const payload = b64url(
			JSON.stringify({ iss: 'https://x', aud: 'https://y', sub: 'owner', jti: 'j1', iat: NOW, exp: NOW + 60 }),
		);
		const unsigned = `${header}.${payload}`;
		const key = await crypto.subtle.importKey(
			'raw',
			new TextEncoder().encode(SECRET),
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign'],
		);
		const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(unsigned)));
		let s = '';
		for (const x of sig) s += String.fromCharCode(x);
		const token = `${unsigned}.${btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')}`;

		const { verifyJwt } = await import('../../src/oauth/jwt');
		await expect(
			verifyJwt(token, { secret: SECRET, issuer: 'https://x', audience: 'https://y', now: NOW }),
		).rejects.toThrow(/alg|algorithm/i);
	});
});

// SQ-586: OAUTH_SIGNING_SECRET_PREVIOUS is accepted on VERIFY only, so rotating the signing
// secret does not invalidate every outstanding access token at once.

const CURRENT = 'c'.repeat(32);
const PREVIOUS = 'p'.repeat(32);
const THIRD = 't'.repeat(32);
const BASE = { issuer: 'https://x', audience: 'https://y', now: NOW } as const;

async function mint(secret: string, ttlSeconds = 60): Promise<string> {
	const { signJwt } = await import('../../src/oauth/jwt');
	return signJwt({ sub: 'owner', jti: 'j1' }, { secret, ttlSeconds, ...BASE });
}

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('oauth/jwt previous signing secret (verify only)', () => {
	it('a token signed with the current secret verifies with and without a previous secret', async () => {
		const { verifyJwt } = await import('../../src/oauth/jwt');
		const token = await mint(CURRENT);
		await expect(verifyJwt(token, { secret: CURRENT, ...BASE })).resolves.toMatchObject({ sub: 'owner' });
		await expect(verifyJwt(token, { secret: CURRENT, previousSecret: PREVIOUS, ...BASE })).resolves.toMatchObject({ sub: 'owner' });
	});

	it('a token signed with the previous secret verifies ONLY when the previous secret is configured', async () => {
		const { verifyJwt } = await import('../../src/oauth/jwt');
		const token = await mint(PREVIOUS);
		await expect(verifyJwt(token, { secret: CURRENT, previousSecret: PREVIOUS, ...BASE })).resolves.toMatchObject({ jti: 'j1' });
		await expect(verifyJwt(token, { secret: CURRENT, ...BASE })).rejects.toThrow(/signature/i);
		await expect(verifyJwt(token, { secret: CURRENT, previousSecret: undefined, ...BASE })).rejects.toThrow(/signature/i);
	});

	it('a token signed with a third secret is rejected whether or not a previous secret is configured', async () => {
		const { verifyJwt } = await import('../../src/oauth/jwt');
		const token = await mint(THIRD);
		await expect(verifyJwt(token, { secret: CURRENT, ...BASE })).rejects.toThrow(/signature/i);
		await expect(verifyJwt(token, { secret: CURRENT, previousSecret: PREVIOUS, ...BASE })).rejects.toThrow(/signature/i);
	});

	it('every other validation still runs on a previous-secret token (expired, wrong issuer, lifetime ceiling)', async () => {
		const { verifyJwt } = await import('../../src/oauth/jwt');
		const opts = { secret: CURRENT, previousSecret: PREVIOUS } as const;
		const expired = await mint(PREVIOUS, 10);
		await expect(verifyJwt(expired, { ...opts, ...BASE, now: NOW + 100 })).rejects.toThrow(/expired/i);
		const token = await mint(PREVIOUS);
		await expect(verifyJwt(token, { ...opts, ...BASE, issuer: 'https://evil' })).rejects.toThrow(/issuer/i);
		await expect(verifyJwt(token, { ...opts, ...BASE, audience: 'https://evil' })).rejects.toThrow(/audience/i);
		await expect(verifyJwt(token, { ...opts, ...BASE, maxLifetimeSeconds: 30 })).rejects.toThrow(/lifetime/i);
	});

	it('the ownership-proof verifier also honours the previous secret', async () => {
		const { verifyJwtOwnershipProof } = await import('../../src/oauth/jwt');
		const token = await mint(PREVIOUS);
		await expect(
			verifyJwtOwnershipProof(token, { secret: CURRENT, previousSecret: PREVIOUS, maxLifetimeSeconds: 3600, ...BASE }),
		).resolves.toMatchObject({ sub: 'owner' });
		await expect(verifyJwtOwnershipProof(token, { secret: CURRENT, maxLifetimeSeconds: 3600, ...BASE })).rejects.toThrow(/signature/i);
	});

	it.each([
		['empty', ''],
		['whitespace-only', '   \t '],
	])('an %s previous secret is treated as unset: previous-signed tokens fail and nothing is logged', async (_label, blank) => {
		const log = vi.spyOn(console, 'log').mockImplementation(() => {});
		const { verifyJwt } = await import('../../src/oauth/jwt');
		const token = await mint(PREVIOUS);
		await expect(verifyJwt(token, { secret: CURRENT, previousSecret: blank, ...BASE })).rejects.toThrow(/signature/i);
		expect(log).not.toHaveBeenCalled();
	});

	it('a previous secret below the strength floor is ignored, even though it signed the token', async () => {
		const { verifyJwt } = await import('../../src/oauth/jwt');
		const weak = 'w'.repeat(31);
		const token = await mint(weak);
		vi.spyOn(console, 'log').mockImplementation(() => {});
		await expect(verifyJwt(token, { secret: CURRENT, previousSecret: weak, ...BASE })).rejects.toThrow(/signature/i);
	});

	it('a previous secret equal to the current secret is ignored without affecting current-secret tokens', async () => {
		const { verifyJwt } = await import('../../src/oauth/jwt');
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const token = await mint(CURRENT);
		await expect(verifyJwt(token, { secret: CURRENT, previousSecret: CURRENT, ...BASE })).resolves.toMatchObject({ sub: 'owner' });
		await expect(verifyJwt(await mint(THIRD), { secret: CURRENT, previousSecret: CURRENT, ...BASE })).rejects.toThrow(/signature/i);
	});

	it('an ignored previous secret logs one fixed-token warning per isolate and never the secret value', async () => {
		const log = vi.spyOn(console, 'log').mockImplementation(() => {});
		const { verifyJwt } = await import('../../src/oauth/jwt');
		const weak = 'weak-previous-secret-value';
		const token = await mint(THIRD);
		for (let i = 0; i < 3; i += 1) {
			await expect(verifyJwt(token, { secret: CURRENT, previousSecret: weak, ...BASE })).rejects.toThrow(/signature/i);
		}
		await expect(verifyJwt(token, { secret: CURRENT, previousSecret: CURRENT, ...BASE })).rejects.toThrow(/signature/i);
		expect(log).toHaveBeenCalledTimes(1);
		const line = String(log.mock.calls[0][0]);
		expect(line).toContain('oauth_previous_signing_secret_ignored');
		expect(line).toContain('"severity":"warn"');
		expect(line).not.toContain(weak);
		expect(line).not.toContain(CURRENT);
	});

	it('signJwt signs with the given secret only: the verify-side previous secret never reaches signing', async () => {
		const { signJwt, verifyJwt } = await import('../../src/oauth/jwt');
		// signJwt has no previous-secret input; a token it mints under CURRENT must not verify under PREVIOUS alone.
		const token = await signJwt({ sub: 'owner', jti: 'j1' }, { secret: CURRENT, ttlSeconds: 60, ...BASE });
		await expect(verifyJwt(token, { secret: PREVIOUS, ...BASE })).rejects.toThrow(/signature/i);
		await expect(verifyJwt(token, { secret: THIRD, previousSecret: PREVIOUS, ...BASE })).rejects.toThrow(/signature/i);
	});
});

describe('securityConfigurationCollision with OAUTH_SIGNING_SECRET_PREVIOUS', () => {
	it('tolerates previous === current (same authority named twice) but not an alias of another capability', async () => {
		const { securityConfigurationCollision } = await import('../../src/lib/security-capabilities');
		expect(securityConfigurationCollision({ OAUTH_SIGNING_SECRET: CURRENT, OAUTH_SIGNING_SECRET_PREVIOUS: CURRENT })).toBeNull();
		expect(securityConfigurationCollision({ OAUTH_SIGNING_SECRET: CURRENT, OAUTH_SIGNING_SECRET_PREVIOUS: PREVIOUS })).toBeNull();
		expect(securityConfigurationCollision({ BV_API_KEY: PREVIOUS, OAUTH_SIGNING_SECRET_PREVIOUS: PREVIOUS })).toEqual({
			left: 'BV_API_KEY',
			right: 'OAUTH_SIGNING_SECRET_PREVIOUS',
		});
		// Equal to the current signing secret AND to another capability: the other alias still collides.
		expect(
			securityConfigurationCollision({ BV_API_KEY: CURRENT, OAUTH_SIGNING_SECRET: CURRENT, OAUTH_SIGNING_SECRET_PREVIOUS: CURRENT }),
		).toEqual({ left: 'BV_API_KEY', right: 'OAUTH_SIGNING_SECRET' });
	});
});
