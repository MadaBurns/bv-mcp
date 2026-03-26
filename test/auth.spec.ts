// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { isAuthorizedRequest, unauthorizedResponse } from '../src/lib/auth';

describe('auth', () => {
	describe('isAuthorizedRequest', () => {
		const SECRET = 'my-secret-api-key-12345';

		it('returns true for matching bearer token', async () => {
			const result = await isAuthorizedRequest(`Bearer ${SECRET}`, SECRET);
			expect(result).toBe(true);
		});

		it('returns false for mismatched token', async () => {
			const result = await isAuthorizedRequest('Bearer wrong-token', SECRET);
			expect(result).toBe(false);
		});

		it('returns false for missing auth header', async () => {
			const result = await isAuthorizedRequest(undefined, SECRET);
			expect(result).toBe(false);
		});

		it('returns false for empty auth header', async () => {
			const result = await isAuthorizedRequest('', SECRET);
			expect(result).toBe(false);
		});

		it('returns false for non-Bearer scheme', async () => {
			const result = await isAuthorizedRequest(`Basic ${SECRET}`, SECRET);
			expect(result).toBe(false);
		});

		it('returns false for Bearer with empty token', async () => {
			const result = await isAuthorizedRequest('Bearer ', SECRET);
			expect(result).toBe(false);
		});

		it('returns false for Bearer with only whitespace', async () => {
			const result = await isAuthorizedRequest('Bearer    ', SECRET);
			expect(result).toBe(false);
		});

		it('handles different-length tokens without early exit', async () => {
			// Short token vs long expected — should still process both through SHA-256
			const result = await isAuthorizedRequest('Bearer a', 'a-very-long-expected-token-that-differs-in-length');
			expect(result).toBe(false);
		});

		it('handles very long tokens', async () => {
			const longToken = 'x'.repeat(10000);
			const result = await isAuthorizedRequest(`Bearer ${longToken}`, longToken);
			expect(result).toBe(true);
		});

		it('is case-sensitive for tokens', async () => {
			const result = await isAuthorizedRequest(`Bearer ${SECRET.toUpperCase()}`, SECRET);
			expect(result).toBe(false);
		});

		it('trims whitespace from token after Bearer prefix', async () => {
			// Token has trailing whitespace — .trim() should normalize it
			const result = await isAuthorizedRequest(`Bearer ${SECRET}  `, SECRET);
			expect(result).toBe(true);
		});

		it('rejects token with only the prefix "Bearer" (no space)', async () => {
			const result = await isAuthorizedRequest('BearerToken', SECRET);
			expect(result).toBe(false);
		});
	});

	describe('unauthorizedResponse', () => {
		it('returns a 401 response', () => {
			const response = unauthorizedResponse();
			expect(response.status).toBe(401);
		});

		it('returns JSON-RPC error body', async () => {
			const response = unauthorizedResponse();
			const body = await response.json();
			expect(body).toHaveProperty('error');
			expect(body.error.message).toContain('Unauthorized');
		});

		it('includes JSON-RPC 2.0 envelope', async () => {
			const response = unauthorizedResponse();
			const body = await response.json();
			expect(body.jsonrpc).toBe('2.0');
			expect(body.id).toBeNull();
		});
	});
});
