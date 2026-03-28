import { describe, it, expect } from 'vitest';
import { TierCacheEntrySchema, ValidateKeyResponseSchema } from '../../src/schemas/auth';

describe('TierCacheEntrySchema', () => {
	it('accepts valid entry', () => {
		const result = TierCacheEntrySchema.safeParse({ tier: 'enterprise', revokedAt: null });
		expect(result.success).toBe(true);
	});
	it('accepts entry with numeric revokedAt', () => {
		const result = TierCacheEntrySchema.safeParse({ tier: 'free', revokedAt: 1234567890 });
		expect(result.success).toBe(true);
	});
	it('accepts entry without revokedAt', () => {
		const result = TierCacheEntrySchema.safeParse({ tier: 'agent' });
		expect(result.success).toBe(true);
	});
	it('rejects invalid tier', () => {
		const result = TierCacheEntrySchema.safeParse({ tier: 'admin' });
		expect(result.success).toBe(false);
	});
	it('rejects non-string tier', () => {
		const result = TierCacheEntrySchema.safeParse({ tier: 42 });
		expect(result.success).toBe(false);
	});
});

describe('ValidateKeyResponseSchema', () => {
	it('accepts valid response', () => {
		const result = ValidateKeyResponseSchema.safeParse({ tier: 'developer' });
		expect(result.success).toBe(true);
	});
	it('rejects null tier', () => {
		const result = ValidateKeyResponseSchema.safeParse({ tier: null });
		expect(result.success).toBe(false);
	});
});
