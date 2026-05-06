import { describe, expect, it } from 'vitest';

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
