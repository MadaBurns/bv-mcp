import { describe, it, expect } from 'vitest';
import { SessionRecordSchema } from '../../src/schemas/session';

describe('SessionRecordSchema', () => {
	it('accepts valid record', () => {
		const result = SessionRecordSchema.safeParse({ createdAt: 1000, lastAccessedAt: 2000 });
		expect(result.success).toBe(true);
	});
	it('rejects missing createdAt', () => {
		const result = SessionRecordSchema.safeParse({ lastAccessedAt: 2000 });
		expect(result.success).toBe(false);
	});
	it('rejects non-number lastAccessedAt', () => {
		const result = SessionRecordSchema.safeParse({ createdAt: 1000, lastAccessedAt: 'not a number' });
		expect(result.success).toBe(false);
	});
	it('rejects null', () => {
		const result = SessionRecordSchema.safeParse(null);
		expect(result.success).toBe(false);
	});
});
