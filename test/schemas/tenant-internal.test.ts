// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for src/schemas/tenant-internal.ts.
 *
 * The Tenant orchestrator endpoints sit behind the existing /internal network +
 * bearer guards but accept richer payloads than /tools/call. These schemas
 * encode the contract: (a) Zod gives us early "Invalid <field>" errors that
 * pass the SAFE_ERROR_PREFIXES gate; (b) `.passthrough()` is consistent with
 * project convention so we don't accidentally strip future fields.
 */

import { describe, it, expect } from 'vitest';
import {
	PortfolioRequestSchema,
	ScanRequestSchema,
	ReportParamsSchema,
	TENANT_ID_REGEX,
	MAX_PORTFOLIO_DOMAINS,
} from '../../src/schemas/tenant-internal';

describe('PortfolioRequestSchema', () => {
	it('accepts a non-empty array of domain strings', () => {
		const r = PortfolioRequestSchema.parse({ domains: ['example.com', 'foo.test'] });
		expect(r.domains).toEqual(['example.com', 'foo.test']);
	});

	it('rejects an empty domains array', () => {
		expect(() => PortfolioRequestSchema.parse({ domains: [] })).toThrow();
	});

	it('rejects payloads with no domains key', () => {
		expect(() => PortfolioRequestSchema.parse({})).toThrow();
	});

	it('caps the domains array at MAX_PORTFOLIO_DOMAINS', () => {
		const tooMany = Array.from({ length: MAX_PORTFOLIO_DOMAINS + 1 }, (_, i) => `d${i}.example`);
		expect(() => PortfolioRequestSchema.parse({ domains: tooMany })).toThrow();
	});

	it('passes through unknown extra fields (passthrough convention)', () => {
		const r = PortfolioRequestSchema.parse({ domains: ['a.test'], extra: 'ok' });
		expect((r as Record<string, unknown>).extra).toBe('ok');
	});

	it('rejects non-string entries inside domains array', () => {
		expect(() => PortfolioRequestSchema.parse({ domains: [123] })).toThrow();
	});
});

describe('ScanRequestSchema', () => {
	it('accepts an empty body (full-portfolio scan, server fills cycle_id)', () => {
		const r = ScanRequestSchema.parse({});
		expect(r.cycle_id).toBeUndefined();
		expect(r.domains).toBeUndefined();
		expect(r.domain_ids).toBeUndefined();
	});

	it('accepts an explicit cycle_id', () => {
		const r = ScanRequestSchema.parse({ cycle_id: 'abc-123' });
		expect(r.cycle_id).toBe('abc-123');
	});

	it('accepts an explicit domains list', () => {
		const r = ScanRequestSchema.parse({ domains: ['a.test', 'b.test'] });
		expect(r.domains).toEqual(['a.test', 'b.test']);
	});

	it('accepts a concurrency between 1 and 50', () => {
		expect(ScanRequestSchema.parse({ concurrency: 1 }).concurrency).toBe(1);
		expect(ScanRequestSchema.parse({ concurrency: 50 }).concurrency).toBe(50);
	});

	it('rejects concurrency above 50', () => {
		expect(() => ScanRequestSchema.parse({ concurrency: 51 })).toThrow();
	});

	it('rejects concurrency below 1', () => {
		expect(() => ScanRequestSchema.parse({ concurrency: 0 })).toThrow();
	});

	it('caps the inline domains list at MAX_PORTFOLIO_DOMAINS', () => {
		const tooMany = Array.from({ length: MAX_PORTFOLIO_DOMAINS + 1 }, (_, i) => `d${i}.example`);
		expect(() => ScanRequestSchema.parse({ domains: tooMany })).toThrow();
	});
});

describe('ReportParamsSchema', () => {
	it('accepts a UUID-shaped cycle_id', () => {
		const r = ReportParamsSchema.parse({ cycle_id: '550e8400-e29b-41d4-a716-446655440000' });
		expect(r.cycle_id).toBe('550e8400-e29b-41d4-a716-446655440000');
	});

	it('accepts an alphanumeric cycle_id', () => {
		const r = ReportParamsSchema.parse({ cycle_id: 'cycle_2026_05_09' });
		expect(r.cycle_id).toBe('cycle_2026_05_09');
	});

	it('rejects a cycle_id with shell metacharacters or spaces', () => {
		expect(() => ReportParamsSchema.parse({ cycle_id: 'a; rm -rf' })).toThrow();
		expect(() => ReportParamsSchema.parse({ cycle_id: 'with spaces' })).toThrow();
	});

	it('rejects an empty cycle_id', () => {
		expect(() => ReportParamsSchema.parse({ cycle_id: '' })).toThrow();
	});
});

describe('TENANT_ID_REGEX', () => {
	it('matches the same shape as the tenant-D1 adapter prefix rule (lowercase + dashes/underscores)', () => {
		expect(TENANT_ID_REGEX.test('tenant-1')).toBe(true);
		expect(TENANT_ID_REGEX.test('acme_co')).toBe(true);
		expect(TENANT_ID_REGEX.test('a')).toBe(true);
	});

	it('rejects uppercase, leading digits, and special chars (cross-tenant leak guard)', () => {
		expect(TENANT_ID_REGEX.test('Tenant')).toBe(false);
		expect(TENANT_ID_REGEX.test('1tenant')).toBe(false);
		expect(TENANT_ID_REGEX.test('tenant.acme')).toBe(false);
		expect(TENANT_ID_REGEX.test('tenant;DROP')).toBe(false);
		expect(TENANT_ID_REGEX.test('')).toBe(false);
	});

	it('caps tenant ID length at 64 characters', () => {
		expect(TENANT_ID_REGEX.test('a' + 'b'.repeat(63))).toBe(true);
		expect(TENANT_ID_REGEX.test('a' + 'b'.repeat(64))).toBe(false);
	});
});
