// SPDX-License-Identifier: BUSL-1.1
/**
 * Minimal HS256 JWT sign/verify for the OAuth access token path.
 * Uses Web Crypto — no Node dependencies.
 */

export interface JwtSignOptions {
	secret: string;
	ttlSeconds: number;
	issuer: string;
	audience: string;
	now?: number; // epoch seconds; injected for tests
}

export interface JwtVerifyOptions {
	secret: string;
	issuer: string;
	audience: string;
	clockSkewSeconds?: number;
	now?: number;
}

export interface JwtClaims {
	iss: string;
	aud: string;
	sub: string;
	jti: string;
	iat: number;
	exp: number;
	tier?: string;
	[k: string]: unknown;
}

const textEncoder = new TextEncoder();

function base64UrlEncode(buf: ArrayBuffer | Uint8Array): string {
	const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
	let str = '';
	for (const b of bytes) str += String.fromCharCode(b);
	return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlEncodeString(s: string): string {
	return base64UrlEncode(textEncoder.encode(s));
}

function base64UrlDecode(s: string): Uint8Array {
	const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
	const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
	const bytes = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
	return bytes;
}

async function hmacKey(secret: string): Promise<CryptoKey> {
	return crypto.subtle.importKey('raw', textEncoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.byteLength !== b.byteLength) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
	return diff === 0;
}

export async function signJwt(payload: Partial<JwtClaims> & { sub: string; jti: string }, opts: JwtSignOptions): Promise<string> {
	const now = opts.now ?? Math.floor(Date.now() / 1000);
	const claims: JwtClaims = {
		...payload,
		iss: opts.issuer,
		aud: opts.audience,
		sub: payload.sub,
		jti: payload.jti,
		iat: now,
		exp: now + opts.ttlSeconds,
	};
	const header = { alg: 'HS256', typ: 'JWT' };
	const h = base64UrlEncodeString(JSON.stringify(header));
	const p = base64UrlEncodeString(JSON.stringify(claims));
	const unsigned = `${h}.${p}`;
	const key = await hmacKey(opts.secret);
	const sig = await crypto.subtle.sign('HMAC', key, textEncoder.encode(unsigned));
	return `${unsigned}.${base64UrlEncode(sig)}`;
}

export async function verifyJwt(token: string, opts: JwtVerifyOptions): Promise<JwtClaims> {
	const parts = token.split('.');
	if (parts.length !== 3) throw new Error('malformed token');
	const [h, p, s] = parts;

	// Verify signature FIRST, before trusting any payload bytes
	const key = await hmacKey(opts.secret);
	const expected = new Uint8Array(await crypto.subtle.sign('HMAC', key, textEncoder.encode(`${h}.${p}`)));
	let given: Uint8Array;
	try {
		given = base64UrlDecode(s);
	} catch {
		throw new Error('malformed token');
	}
	if (!constantTimeEqual(expected, given)) throw new Error('invalid signature');

	// Signature verified — safe to parse claims
	let claims: JwtClaims;
	try {
		claims = JSON.parse(new TextDecoder().decode(base64UrlDecode(p))) as JwtClaims;
	} catch {
		throw new Error('malformed token payload');
	}

	const now = opts.now ?? Math.floor(Date.now() / 1000);
	const skew = opts.clockSkewSeconds ?? 30;
	if (claims.exp <= now - skew) throw new Error('token expired');
	if (claims.iss !== opts.issuer) throw new Error('invalid issuer');
	if (claims.aud !== opts.audience) throw new Error('invalid audience');
	return claims;
}

export function newJti(): string {
	return crypto.randomUUID();
}
