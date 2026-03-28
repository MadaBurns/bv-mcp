import { describe, it, expect } from 'vitest';
import { DohResponseSchema, CaaRecordSchema, TlsaRecordSchema, MxRecordSchema, SrvRecordSchema } from '../../src/schemas/dns';

describe('DohResponseSchema', () => {
	it('accepts valid response', () => {
		const result = DohResponseSchema.safeParse({ Status: 0 });
		expect(result.success).toBe(true);
	});
	it('accepts response with answers', () => {
		const result = DohResponseSchema.safeParse({
			Status: 0,
			AD: true,
			Answer: [{ name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 -all"' }],
		});
		expect(result.success).toBe(true);
	});
	it('rejects non-finite Status', () => {
		const result = DohResponseSchema.safeParse({ Status: Infinity });
		expect(result.success).toBe(false);
	});
	it('rejects missing Status', () => {
		const result = DohResponseSchema.safeParse({});
		expect(result.success).toBe(false);
	});
	it('rejects non-object', () => {
		const result = DohResponseSchema.safeParse('not an object');
		expect(result.success).toBe(false);
	});
	it('rejects null', () => {
		const result = DohResponseSchema.safeParse(null);
		expect(result.success).toBe(false);
	});
});

describe('CaaRecordSchema', () => {
	it('accepts valid CAA record', () => {
		const result = CaaRecordSchema.safeParse({ flags: 0, tag: 'issue', value: 'letsencrypt.org' });
		expect(result.success).toBe(true);
	});
});

describe('TlsaRecordSchema', () => {
	it('accepts valid TLSA record', () => {
		const result = TlsaRecordSchema.safeParse({ usage: 3, selector: 1, matchingType: 1, certData: 'abcd' });
		expect(result.success).toBe(true);
	});
});

describe('MxRecordSchema', () => {
	it('accepts valid MX record', () => {
		const result = MxRecordSchema.safeParse({ priority: 10, exchange: 'mail.example.com' });
		expect(result.success).toBe(true);
	});
});

describe('SrvRecordSchema', () => {
	it('accepts valid SRV record', () => {
		const result = SrvRecordSchema.safeParse({ priority: 0, weight: 5, port: 443, target: 'sip.example.com' });
		expect(result.success).toBe(true);
	});
});
