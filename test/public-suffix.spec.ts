// SPDX-License-Identifier: MIT
import { describe, it, expect } from 'vitest';

describe('public-suffix', () => {
	async function loadModule() {
		return import('../src/lib/public-suffix');
	}

	describe('extractBrandName', () => {
		it('should extract brand from NZ govt domain', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('tewhatuora.govt.nz')).toBe('tewhatuora');
		});

		it('should extract brand from NZ co domain', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('acc.co.nz')).toBe('acc');
		});

		it('should extract brand from simple .com', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('blackveilsecurity.com')).toBe('blackveilsecurity');
		});

		it('should extract brand from UK co domain', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('bbc.co.uk')).toBe('bbc');
		});

		it('should extract brand from simple .nz domain', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('blackveil.nz')).toBe('blackveil');
		});

		it('should strip subdomains and extract brand from co.nz', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('sub.example.co.nz')).toBe('example');
		});

		it('should extract brand from AU gov domain', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('services.gov.au')).toBe('services');
		});

		it('should extract brand from .io domain', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('linear.io')).toBe('linear');
		});

		it('should extract brand from .ai domain', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('perplexity.ai')).toBe('perplexity');
		});

		it('should extract brand from JP co domain', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('toyota.co.jp')).toBe('toyota');
		});

		it('should extract brand from ZA co domain', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('vodacom.co.za')).toBe('vodacom');
		});

		it('should extract brand from IDN/punycode domain', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('xn--nxasmq6b.org')).toBe('xn--nxasmq6b');
		});

		it('should return null for single-label input', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('com')).toBeNull();
		});

		it('should return null for empty string', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('')).toBeNull();
		});

		it('should return null for bare TLD suffix', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('co.nz')).toBeNull();
		});
	});

	describe('getEffectiveTld', () => {
		it('should return govt.nz for NZ govt domain', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('tewhatuora.govt.nz')).toBe('govt.nz');
		});

		it('should return co.nz for NZ co domain', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('acc.co.nz')).toBe('co.nz');
		});

		it('should return com for simple .com', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('blackveilsecurity.com')).toBe('com');
		});

		it('should return co.uk for UK co domain', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('bbc.co.uk')).toBe('co.uk');
		});

		it('should return nz for simple .nz domain', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('blackveil.nz')).toBe('nz');
		});

		it('should return co.nz for subdomain under co.nz', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('sub.example.co.nz')).toBe('co.nz');
		});

		it('should return gov.au for AU gov domain', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('services.gov.au')).toBe('gov.au');
		});

		it('should return io for .io domain', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('linear.io')).toBe('io');
		});

		it('should return ai for .ai domain', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('perplexity.ai')).toBe('ai');
		});

		it('should return co.jp for JP co domain', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('toyota.co.jp')).toBe('co.jp');
		});

		it('should return co.za for ZA co domain', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('vodacom.co.za')).toBe('co.za');
		});

		it('should return org for IDN/punycode domain', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('xn--nxasmq6b.org')).toBe('org');
		});

		it('should return null for single-label input', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('com')).toBeNull();
		});

		it('should return null for empty string', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('')).toBeNull();
		});

		it('should return null for bare TLD suffix', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('co.nz')).toBeNull();
		});

		it('should handle domain with trailing dot without crashing', async () => {
			const { getEffectiveTld } = await loadModule();
			// Trailing dot creates an empty label — function should not throw
			const result = getEffectiveTld('example.com.');
			// Returns something (not undefined), proving it handles edge case without crashing
			expect(() => getEffectiveTld('example.com.')).not.toThrow();
			expect(result).toBeDefined();
		});

		it('should normalize uppercase domain', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('EXAMPLE.COM')).toBe('com');
		});

		it('should extract correct TLD for deep subdomain under co.nz', async () => {
			const { getEffectiveTld } = await loadModule();
			expect(getEffectiveTld('a.b.c.example.co.nz')).toBe('co.nz');
		});
	});

	describe('extractBrandName — edge cases', () => {
		it('should normalize uppercase domain and extract brand', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('EXAMPLE.COM')).toBe('example');
		});

		it('should extract brand from deep subdomain under co.nz', async () => {
			const { extractBrandName } = await loadModule();
			expect(extractBrandName('a.b.c.example.co.nz')).toBe('example');
		});
	});
});
