// SPDX-License-Identifier: BUSL-1.1
/**
 * Bearer authentication for the query API. Fails closed: an unset or empty key matches nothing.
 *
 * Two kinds of key are accepted. CT_INDEX_ADMIN_KEY works alone. A read key works only for the caller it was
 * issued to: the request names its caller in X-BV-Caller, and the bearer must be that caller's key. Each caller's
 * key is its own secret, so one can be rotated or revoked without touching the others. An unknown caller, or a
 * caller whose secret is unset, is refused.
 */

const encoder = new TextEncoder();

async function digest(value: string): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
}

/**
 * Compares SHA-256 digests of both strings, so the loop runs over 32 bytes whatever the lengths are and a
 * timing difference cannot reveal where, or how long, the presented key is.
 */
export async function isAuthorized(authorization: string | null, expectedKey: string | undefined): Promise<boolean> {
	if (typeof expectedKey !== 'string' || expectedKey.length === 0) return false;
	const presented = /^Bearer (.+)$/i.exec(authorization ?? '')?.[1] ?? '';
	const [a, b] = await Promise.all([digest(presented), digest(expectedKey)]);
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
	// An absent presented key must not authenticate, whatever the digests say.
	return diff === 0 && presented.length > 0;
}

/** The callers that have their own read key: the X-BV-Caller value (the calling Worker's name), then its secret. */
export const READ_CALLERS = {
	'bv-mcp': 'CT_INDEX_KEY_BV_MCP',
	'bv-web-prod': 'CT_INDEX_KEY_BV_WEB_PROD',
	'bv2-ops': 'CT_INDEX_KEY_BV2_OPS',
	'bv2-recon': 'CT_INDEX_KEY_BV2_RECON',
	'bv2-certstream': 'CT_INDEX_KEY_BV2_CERTSTREAM',
} as const;

type ReadCaller = keyof typeof READ_CALLERS;
export type ReadKeySecret = (typeof READ_CALLERS)[ReadCaller];
export type ApiKeys = { CT_INDEX_ADMIN_KEY: string } & Partial<Record<ReadKeySecret, string>>;

function readCaller(header: string | null): ReadCaller | null {
	return header !== null && Object.hasOwn(READ_CALLERS, header) ? (header as ReadCaller) : null;
}

/** Who the request authenticates as: 'admin', a read caller's name, or null when it is refused. */
export async function authenticate(headers: Headers, keys: ApiKeys): Promise<string | null> {
	const authorization = headers.get('authorization');
	if (await isAuthorized(authorization, keys.CT_INDEX_ADMIN_KEY)) return 'admin';
	const caller = readCaller(headers.get('x-bv-caller'));
	if (caller === null) return null;
	return (await isAuthorized(authorization, keys[READ_CALLERS[caller]])) ? caller : null;
}
