import { describe, it, expect } from 'vitest';
import { InternalToolCallSchema, BatchRequestSchema } from '../../src/schemas/internal';

describe('InternalToolCallSchema', () => {
	it('accepts valid call', () => {
		const result = InternalToolCallSchema.safeParse({ name: 'check_spf', arguments: { domain: 'example.com' } });
		expect(result.success).toBe(true);
	});
	it('accepts call without arguments', () => {
		const result = InternalToolCallSchema.safeParse({ name: 'check_spf' });
		expect(result.success).toBe(true);
	});
	it('rejects missing name', () => {
		const result = InternalToolCallSchema.safeParse({});
		expect(result.success).toBe(false);
	});
	it('rejects uppercase name', () => {
		const result = InternalToolCallSchema.safeParse({ name: 'Check_SPF' });
		expect(result.success).toBe(false);
	});
	it('rejects name over 30 chars', () => {
		const result = InternalToolCallSchema.safeParse({ name: 'a'.repeat(31) });
		expect(result.success).toBe(false);
	});
});

describe('BatchRequestSchema', () => {
	it('accepts valid batch', () => {
		const result = BatchRequestSchema.safeParse({ tool: 'scan_domain', domains: ['example.com'] });
		expect(result.success).toBe(true);
	});
	it('defaults tool to scan_domain', () => {
		const result = BatchRequestSchema.safeParse({ domains: ['example.com'] });
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.tool).toBe('scan_domain');
	});
	it('rejects empty domains', () => {
		const result = BatchRequestSchema.safeParse({ tool: 'check_spf', domains: [] });
		expect(result.success).toBe(false);
	});
	it('rejects > 500 domains', () => {
		const domains = Array.from({ length: 501 }, (_, i) => `d${i}.com`);
		const result = BatchRequestSchema.safeParse({ tool: 'check_spf', domains });
		expect(result.success).toBe(false);
	});
	it('rejects concurrency > 50', () => {
		const result = BatchRequestSchema.safeParse({ tool: 'check_spf', domains: ['example.com'], concurrency: 51 });
		expect(result.success).toBe(false);
	});
});
