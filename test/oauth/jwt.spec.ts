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
});
