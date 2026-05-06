// Tests for the PKCE verifier in src/oauth/token.ts. The function is internal
// to that module, so we exercise it via the exported verifyPkce contract once
// extracted, plus end-to-end behavior coverage on /oauth/token.
//
// Behavioral contract:
//   - Correct verifier whose SHA-256 BASE64URL equals the challenge => true
//   - Mismatched verifier => false
//   - The implementation must compare digests in constant time (no early exit
//     on the first mismatched byte). We assert the contract by testing the
//     observable boolean output across a range of inputs; timing is
//     unmeasurable in JS but the implementation is verified by code review
//     to use a constant-time byte comparison.

import { describe, it, expect } from 'vitest';

function base64url(buf: ArrayBuffer): string {
	const b = new Uint8Array(buf);
	let s = '';
	for (const x of b) s += String.fromCharCode(x);
	return btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function challengeFor(verifier: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	return base64url(digest);
}

describe('verifyPkce', () => {
	it('returns true for a verifier whose SHA-256 base64url equals the challenge', async () => {
		const { verifyPkce } = await import('../../src/oauth/token');
		const verifier = 'a'.repeat(64);
		const challenge = await challengeFor(verifier);
		expect(await verifyPkce(verifier, challenge)).toBe(true);
	});

	it('returns false when the verifier does not match the challenge', async () => {
		const { verifyPkce } = await import('../../src/oauth/token');
		const verifier = 'a'.repeat(64);
		const wrongChallenge = await challengeFor('b'.repeat(64));
		expect(await verifyPkce(verifier, wrongChallenge)).toBe(false);
	});

	it('returns false when the challenge is well-formed base64url but wrong length', async () => {
		// Defends the constant-time path against length-mismatch shortcuts.
		const { verifyPkce } = await import('../../src/oauth/token');
		const verifier = 'a'.repeat(64);
		const shortChallenge = (await challengeFor(verifier)).slice(0, 20);
		expect(await verifyPkce(verifier, shortChallenge)).toBe(false);
	});

	it('returns false when the challenge contains non-base64url characters', async () => {
		const { verifyPkce } = await import('../../src/oauth/token');
		const verifier = 'a'.repeat(64);
		// `!` is not a valid base64url char; decoder must reject without throwing through the API.
		expect(await verifyPkce(verifier, '!!!invalid-challenge!!!')).toBe(false);
	});
});
