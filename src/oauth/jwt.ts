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
	/** Reject even correctly signed tokens minted with a longer lifetime. */
	maxLifetimeSeconds?: number;
	now?: number;
}

/**
 * Historical-token verification is deliberately separate from ordinary bearer
 * authentication. It may ignore expiry only so a caller who is already
 * authenticated as the same canonical OAuth principal can prove a legacy
 * Brand Audit owner hash. Callers MUST NOT use this result to grant access.
 */
export interface JwtOwnershipProofOptions extends JwtVerifyOptions {
	/** Upper bound for the retired access-token lifetime accepted as migration evidence. */
	maxLifetimeSeconds: number;
}

export interface JwtClaims {
	iss: string;
	aud: string;
	sub: string;
	jti: string;
	iat: number;
	exp: number;
	tier?: string;
	/** Token-version claim (FIND-13). Absent on old tokens — treated as 1 by verifiers. */
	ver?: number;
	/** Billing entitlement generation authorized by bv-web; absent legacy tokens are generation 1. */
	entitlementGeneration?: number;
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

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
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

async function verifyJwtWithPolicy(token: string, opts: JwtVerifyOptions, allowExpired: boolean): Promise<JwtClaims> {
	const parts = token.split('.');
	if (parts.length !== 3) throw new Error('malformed token');
	const [h, p, s] = parts;

	// Pin alg=HS256 (RFC 8725 §3.1). Reject `none` and any other algorithm
	// before doing further work — defends against algorithm-confusion attacks
	// where a forged header tricks a verifier into the wrong code path.
	let header: { alg?: unknown; typ?: unknown };
	try {
		header = JSON.parse(new TextDecoder().decode(base64UrlDecode(h))) as { alg?: unknown };
	} catch {
		throw new Error('malformed token');
	}
	if (header.alg !== 'HS256') throw new Error('unsupported alg');

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

	// Defense-in-depth: validate claim types BEFORE comparisons. Signature already proved the
	// token wasn't forged externally, but a future signing-path bug that omitted `exp` would
	// otherwise produce never-expiring tokens (`undefined <= n - skew` is `false`). Same goes
	// for the string claims — comparing `undefined !== 'something'` is `true`, so missing iss
	// or aud already fails closed, but explicit typeof checks make the contract obvious.
	if (!Number.isSafeInteger(claims.exp) || claims.exp < 1) throw new Error('malformed token payload');
	if (!Number.isSafeInteger(claims.iat) || claims.iat < 1) throw new Error('malformed token payload');
	if (typeof claims.iss !== 'string') throw new Error('malformed token payload');
	if (typeof claims.aud !== 'string') throw new Error('malformed token payload');
	if (typeof claims.sub !== 'string') throw new Error('malformed token payload');
	if (typeof claims.jti !== 'string') throw new Error('malformed token payload');
	if (
		claims.entitlementGeneration !== undefined &&
		(!Number.isSafeInteger(claims.entitlementGeneration) || claims.entitlementGeneration < 1)
	) {
		throw new Error('malformed token payload');
	}

	const now = opts.now ?? Math.floor(Date.now() / 1000);
	const skew = opts.clockSkewSeconds ?? 30;
	if (!Number.isSafeInteger(now) || !Number.isSafeInteger(skew) || skew < 0) throw new Error('invalid verifier clock');
	if (claims.iat > now + skew) throw new Error('token issued in the future');
	if (claims.exp <= claims.iat) throw new Error('invalid token lifetime');
	if (
		opts.maxLifetimeSeconds !== undefined &&
		(!Number.isSafeInteger(opts.maxLifetimeSeconds) || opts.maxLifetimeSeconds < 1 || claims.exp - claims.iat > opts.maxLifetimeSeconds)
	) {
		throw new Error('token lifetime exceeds maximum');
	}
	if (!allowExpired && claims.exp <= now - skew) throw new Error('token expired');
	if (claims.iss !== opts.issuer) throw new Error('invalid issuer');
	if (claims.aud !== opts.audience) throw new Error('invalid audience');
	return claims;
}

export function verifyJwt(token: string, opts: JwtVerifyOptions): Promise<JwtClaims> {
	return verifyJwtWithPolicy(token, opts, false);
}

/**
 * Verify a historical OAuth JWT solely as cryptographic ownership evidence.
 * Expiry is ignored, but signature, algorithm, issuer, audience, claim types,
 * issue time, and the caller-supplied historical lifetime ceiling remain
 * enforced. The returned claims are not an authentication result.
 */
export function verifyJwtOwnershipProof(token: string, opts: JwtOwnershipProofOptions): Promise<JwtClaims> {
	return verifyJwtWithPolicy(token, opts, true);
}

export function newJti(): string {
	return crypto.randomUUID();
}
