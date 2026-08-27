import { describe, expect, it } from 'vitest';
import { validateQuotaPayload } from '../src/lib/quota-coordinator';

describe('quota-coordinator payload validation', () => {
	it('rejects a payload missing the kind field', () => {
		const result = validateQuotaPayload({ ip: '192.0.2.1' });
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
			principalId: 'ip:192.0.2.1',
			toolName: 'check_lookalikes',
			limit: 10,
		});
		expect(result.valid).toBe(true);
	});

	it('accepts a valid distinct-domain-daily payload', () => {
		const result = validateQuotaPayload({
			kind: 'distinct-domain-daily',
			principalId: '203.0.113.1',
			domainFingerprint: 'd_12ab34cd',
			limit: 12,
		});
		expect(result.valid).toBe(true);
	});

	it('rejects an empty, control-bearing, or oversized domain fingerprint', () => {
		for (const domainFingerprint of ['', 'd_bad\nkey', 'x'.repeat(129)]) {
			const result = validateQuotaPayload({
				kind: 'distinct-domain-daily',
				principalId: '203.0.113.1',
				domainFingerprint,
				limit: 12,
			});
			expect(result.valid).toBe(false);
		}
	});

	it('accepts a valid global-daily payload', () => {
		const result = validateQuotaPayload({ kind: 'global-daily', limit: 10000 });
		expect(result.valid).toBe(true);
	});

	it('accepts a valid session-create payload', () => {
		const result = validateQuotaPayload({ kind: 'session-create', ip: '192.0.2.1', limit: 30, windowMs: 60000 });
		expect(result.valid).toBe(true);
	});

	it('accepts only bounded OAuth DCR write-budget payloads with hashed sources', () => {
		expect(
			validateQuotaPayload({
				kind: 'oauth-dcr-write',
				sourceFingerprint: 'a'.repeat(64),
				sourceDailyLimit: 20,
				globalHourlyLimit: 60,
				globalDailyLimit: 250,
			}).valid,
		).toBe(true);
		for (const sourceFingerprint of ['198.51.100.1', 'A'.repeat(64), 'a'.repeat(63)]) {
			expect(
				validateQuotaPayload({
					kind: 'oauth-dcr-write',
					sourceFingerprint,
					sourceDailyLimit: 20,
					globalHourlyLimit: 60,
					globalDailyLimit: 250,
				}).valid,
			).toBe(false);
		}
	});

	it('accepts a valid reset payload', () => {
		const result = validateQuotaPayload({ kind: 'reset' });
		expect(result.valid).toBe(true);
	});
});
