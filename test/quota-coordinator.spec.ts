import { describe, expect, it } from 'vitest';
import { validateQuotaPayload } from '../src/lib/quota-coordinator';

describe('quota-coordinator payload validation', () => {
	it('rejects a payload missing the kind field', () => {
		const result = validateQuotaPayload({ ip: '1.2.3.4' });
		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toContain('missing kind');
		}
	});

	it('rejects an unknown kind value', () => {
		const result = validateQuotaPayload({ kind: 'not-a-real-kind' });
		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.error).toContain('unknown kind');
		}
	});

	it('rejects a non-object payload', () => {
		const result = validateQuotaPayload('just a string');
		expect(result.valid).toBe(false);
	});

	it('rejects null', () => {
		const result = validateQuotaPayload(null);
		expect(result.valid).toBe(false);
	});

	it('rejects a numeric kind', () => {
		const result = validateQuotaPayload({ kind: 42 });
		expect(result.valid).toBe(false);
	});

	it('accepts a valid scoped-rate payload', () => {
		const result = validateQuotaPayload({
			kind: 'scoped-rate',
			scope: 'tools',
			ip: '203.0.113.1',
			minuteLimit: 30,
			hourLimit: 200,
		});
		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.payload.kind).toBe('scoped-rate');
		}
	});

	it('accepts a valid tool-daily payload', () => {
		const result = validateQuotaPayload({
			kind: 'tool-daily',
			principalId: 'ip:1.2.3.4',
			toolName: 'check_lookalikes',
			limit: 10,
		});
		expect(result.valid).toBe(true);
	});

	it('accepts a valid global-daily payload', () => {
		const result = validateQuotaPayload({ kind: 'global-daily', limit: 10000 });
		expect(result.valid).toBe(true);
	});

	it('accepts a valid session-create payload', () => {
		const result = validateQuotaPayload({ kind: 'session-create', ip: '1.2.3.4', limit: 30, windowMs: 60000 });
		expect(result.valid).toBe(true);
	});

	it('accepts a valid reset payload', () => {
		const result = validateQuotaPayload({ kind: 'reset' });
		expect(result.valid).toBe(true);
	});
});
