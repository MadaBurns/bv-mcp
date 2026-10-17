// SPDX-License-Identifier: BUSL-1.1
/**
 * Bearer authentication for the query API. Fails closed: an unset or empty key matches nothing.
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
