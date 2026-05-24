// SPDX-License-Identifier: BUSL-1.1
//
// Regression/characterization audit — pins EXISTING security controls.
// No production code changes. Tests must pass against the current codebase.
//
// Covers FIND-08 (alg=none / JWT auth), FIND-09 (SSRF), FIND-10 (rate limits),
// FIND-11 (error info-disclosure).

import { describe, it, expect } from 'vitest';
import { verifyJwt } from '../../src/oauth/jwt';
import { resolveTier } from '../../src/lib/tier-auth';
import { safeFetch } from '../../src/lib/safe-fetch';
import { GLOBAL_DAILY_TOOL_LIMIT, FREE_TOOL_DAILY_LIMITS } from '../../src/lib/config';
import { sanitizeErrorMessage } from '../../src/lib/json-rpc';

// ---------------------------------------------------------------------------
// Helper: construct a JWT with the given alg field and no valid signature.
// Builds header.payload.signature where signature is intentionally empty,
// matching the alg=none "none" attack pattern.
// ---------------------------------------------------------------------------
function buildJwtWithAlg(alg: string): string {
	const now = Math.floor(Date.now() / 1000);
	const header = btoa(JSON.stringify({ alg, typ: 'JWT' }))
		.replace(/=/g, '')
		.replace(/\+/g, '-')
		.replace(/\//g, '_');
	const payload = btoa(
		JSON.stringify({
			iss: 'https://example.com',
			aud: 'https://example.com/mcp',
			sub: 'user-123',
			jti: 'jti-abc',
			iat: now,
			exp: now + 3600,
		}),
	)
		.replace(/=/g, '')
		.replace(/\+/g, '-')
		.replace(/\//g, '_');
	// Empty signature — the defining characteristic of the alg=none attack
	return `${header}.${payload}.`;
}

// ---------------------------------------------------------------------------
// FIND-08: JWT algorithm confusion / alg=none
// ---------------------------------------------------------------------------
describe('FIND-08: verifyJwt rejects alg=none and bogus tokens', () => {
	it('rejects a JWT with alg=none (throws "unsupported alg")', async () => {
		const token = buildJwtWithAlg('none');
		await expect(
			verifyJwt(token, {
				secret: 'a'.repeat(32),
				issuer: 'https://example.com',
				audience: 'https://example.com/mcp',
			}),
		).rejects.toThrow('unsupported alg');
	});

	it('rejects a JWT with alg=RS256 (not the supported HS256)', async () => {
		const token = buildJwtWithAlg('RS256');
		await expect(
			verifyJwt(token, {
				secret: 'a'.repeat(32),
				issuer: 'https://example.com',
				audience: 'https://example.com/mcp',
			}),
		).rejects.toThrow('unsupported alg');
	});

	it('resolveTier returns { authenticated: false } for a bogus non-JWT token with empty env', async () => {
		// A single-segment string can never be mistaken for a JWT (3 dot-separated segments),
		// so the OAuth path is skipped immediately. The static BV_API_KEY path also has
		// nothing to match against. Result: authenticated: false — tier never derived from input.
		const result = await resolveTier('not-a-jwt', {}, undefined, 'http://x/');
		expect(result.authenticated).toBe(false);
		expect(result.tier).toBeUndefined();
	});

	it('resolveTier returns { authenticated: false } for a null token', async () => {
		const result = await resolveTier(null, {}, undefined, 'http://x/');
		expect(result.authenticated).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// FIND-09: SSRF — safeFetch rejects internal/RFC1918 destinations
// ---------------------------------------------------------------------------
describe('FIND-09: safeFetch blocks SSRF targets', () => {
	it('throws TypeError when fetching the IMDS 169.254.169.254 endpoint', async () => {
		// 169.254.169.254 is the cloud metadata endpoint; its IP literal matches
		// BLOCKED_IP_PATTERNS in config.ts, triggering rejection in validateOutboundUrl.
		await expect(safeFetch('https://169.254.169.254/latest/meta-data/')).rejects.toThrow(TypeError);
	});

	it('throws TypeError with "Outbound fetch blocked" prefix for IMDS', async () => {
		await expect(safeFetch('https://169.254.169.254/latest/meta-data/')).rejects.toThrow('Outbound fetch blocked');
	});

	it('throws TypeError for http:// to an RFC1918 host (protocol gate fires first)', async () => {
		// validateOutboundUrl requires https: — http:// is rejected before any IP check.
		// Still proves the URL is blocked; the two-layer defence is intentional.
		await expect(safeFetch('http://10.0.0.1/')).rejects.toThrow(TypeError);
	});

	it('throws TypeError for https:// to an RFC1918 10.x address', async () => {
		// 10.0.0.1 matches /^10\./ in BLOCKED_IP_PATTERNS; validateDomain rejects it.
		await expect(safeFetch('https://10.0.0.1/')).rejects.toThrow(TypeError);
	});

	it('throws TypeError with "Outbound fetch blocked" prefix for RFC1918 https URL', async () => {
		await expect(safeFetch('https://10.0.0.1/')).rejects.toThrow('Outbound fetch blocked');
	});
});

// ---------------------------------------------------------------------------
// FIND-10: Rate-limit constants exist and are within expected bounds
// ---------------------------------------------------------------------------
describe('FIND-10: rate-limit constants are set and bounded', () => {
	it('GLOBAL_DAILY_TOOL_LIMIT is positive', () => {
		expect(GLOBAL_DAILY_TOOL_LIMIT).toBeGreaterThan(0);
	});

	it('GLOBAL_DAILY_TOOL_LIMIT is 500_000 (locked value)', () => {
		// Lock the exact value — a regression that sets this to 0 or Infinity would
		// open the service to abuse or lock it down entirely.
		expect(GLOBAL_DAILY_TOOL_LIMIT).toBe(500_000);
	});

	it('FREE_TOOL_DAILY_LIMITS.batch_scan is at most 1 (restrictive free-tier cap)', () => {
		// batch_scan is high-compute — the free cap must stay at or below 1.
		expect(FREE_TOOL_DAILY_LIMITS.batch_scan).toBeLessThanOrEqual(1);
	});

	it('FREE_TOOL_DAILY_LIMITS.scan_domain exists and is positive', () => {
		expect(FREE_TOOL_DAILY_LIMITS.scan_domain).toBeGreaterThan(0);
	});

	it('FREE_TOOL_DAILY_LIMITS.check_lookalikes is at most 5 (high-resource cap)', () => {
		// lookalikes and shadow_domains are resource-intensive; cap must stay low.
		expect(FREE_TOOL_DAILY_LIMITS.check_lookalikes).toBeLessThanOrEqual(5);
	});
});

// ---------------------------------------------------------------------------
// FIND-11: sanitizeErrorMessage — error information disclosure prevention
// ---------------------------------------------------------------------------
describe('FIND-11: sanitizeErrorMessage prevents info-disclosure', () => {
	const FALLBACK = 'An internal error occurred';

	it('passes through a message starting with an allowlisted prefix ("Invalid")', () => {
		const result = sanitizeErrorMessage(new Error('Invalid domain: foo'), FALLBACK);
		expect(result).toBe('Invalid domain: foo');
	});

	it('passes through a message starting with "Missing required"', () => {
		const result = sanitizeErrorMessage(new Error('Missing required parameter: domain'), FALLBACK);
		expect(result).toBe('Missing required parameter: domain');
	});

	it('passes through a message starting with "Domain "', () => {
		const result = sanitizeErrorMessage(new Error('Domain "evil.com" is blocked'), FALLBACK);
		expect(result).toBe('Domain "evil.com" is blocked');
	});

	it('returns the fallback for a TypeError leaking an internal file path', () => {
		// The exact "TypeError: secret at /src/x.ts:5" shape is the threat the control defends against.
		const result = sanitizeErrorMessage(new Error('TypeError: secret at /src/x.ts:5'), FALLBACK);
		expect(result).toBe(FALLBACK);
	});

	it('does NOT include the source path in the returned message (no-leak invariant)', () => {
		const result = sanitizeErrorMessage(new Error('TypeError: secret at /src/x.ts:5'), FALLBACK);
		expect(result).not.toContain('/src/');
		expect(result).not.toContain('secret');
	});

	it('returns the fallback for a generic runtime error without an allowlisted prefix', () => {
		const result = sanitizeErrorMessage(new Error('Connection refused by 192.168.1.1'), FALLBACK);
		expect(result).toBe(FALLBACK);
	});

	it('returns the fallback for a non-Error value (e.g. a raw string throw)', () => {
		// sanitizeErrorMessage checks `instanceof Error` before inspecting the message;
		// a raw string thrown from a catch block must not leak through.
		const result = sanitizeErrorMessage('Invalid domain: actually leaked', FALLBACK);
		expect(result).toBe(FALLBACK);
	});
});
