// SPDX-License-Identifier: BUSL-1.1

/**
 * Pins the exact error `validateQuotaPayload` returns for every per-field invariant, and which error a
 * multi-invalid payload gets. Field ORDER decides the latter, so this order is part of the contract:
 * ip, principalId, scope, toolName, domainFingerprint, sourceFingerprint, coordinationKey,
 * idempotencyCoordinationKey, the numeric fields (in the order below), expiresAt, requestHash, result.
 *
 * The fields are exercised through a `global-daily` payload (its only required field is `limit`), so the
 * field validator is reached with no kind-specific check in the way.
 */
import { describe, expect, it } from 'vitest';
import { validateQuotaPayload } from '../src/lib/quota-coordinator';

const HEX64 = 'a'.repeat(64);
const MAX_RESULT_BYTES = 64 * 1024;

interface FieldCase {
	field: string;
	bad: unknown;
	error: string;
}

const NON_NEGATIVE_INT_FIELDS = [
	'minuteLimit',
	'hourLimit',
	'limit',
	'windowMs',
	'amount',
	'defaultValue',
	'initialUsed',
	'value',
	'sourceDailyLimit',
	'globalHourlyLimit',
	'globalDailyLimit',
] as const;

/** One bad value per field, in validation order. */
const ORDERED_FIELD_CASES: FieldCase[] = [
	{ field: 'ip', bad: 'x'.repeat(51), error: 'Invalid ip: must be string <= 50 chars' },
	{ field: 'principalId', bad: 'x'.repeat(101), error: 'Invalid principalId: must be string <= 100 chars' },
	{ field: 'scope', bad: 's'.repeat(31), error: 'Invalid scope' },
	{ field: 'toolName', bad: 7, error: 'Invalid toolName: must be string <= 100 chars' },
	{
		field: 'domainFingerprint',
		bad: '',
		error: 'Invalid domainFingerprint: must be a non-empty printable string <= 128 chars',
	},
	{
		field: 'sourceFingerprint',
		bad: 'A'.repeat(64),
		error: 'Invalid sourceFingerprint: must be a lowercase SHA-256 hex digest',
	},
	{
		field: 'coordinationKey',
		bad: 'bad\u0000key',
		error: 'Invalid coordinationKey: must be a non-empty printable string <= 256 chars',
	},
	{
		field: 'idempotencyCoordinationKey',
		bad: '',
		error: 'Invalid idempotencyCoordinationKey: must be a non-empty printable string <= 256 chars',
	},
	...NON_NEGATIVE_INT_FIELDS.map((field) => ({
		field,
		bad: -1,
		error: `Invalid ${field}: must be a non-negative safe integer`,
	})),
	{ field: 'expiresAt', bad: 0, error: 'Invalid expiresAt: must be a positive safe integer' },
	{ field: 'requestHash', bad: 'nothex', error: 'Invalid requestHash: must be a lowercase SHA-256 hex digest' },
	{
		field: 'result',
		bad: 'x'.repeat(MAX_RESULT_BYTES + 1),
		error: `Invalid result: must be a UTF-8 string <= ${MAX_RESULT_BYTES} bytes`,
	},
];

/** Validate one global-daily payload carrying the given extra fields. */
function errorFor(extra: Record<string, unknown>): string | undefined {
	const result = validateQuotaPayload({ kind: 'global-daily', limit: 1, ...extra });
	return result.valid ? undefined : result.error;
}

describe('validateQuotaFields: exact error per invalid field', () => {
	for (const { field, bad, error } of ORDERED_FIELD_CASES) {
		it(`reports ${field}`, () => {
			expect(errorFor({ [field]: bad })).toBe(error);
		});
	}

	it('accepts a payload with no optional fields', () => {
		expect(errorFor({})).toBeUndefined();
	});

	it('accepts the boundary-valid value for every field at once', () => {
		expect(
			errorFor({
				ip: 'x'.repeat(50),
				principalId: 'x'.repeat(100),
				scope: 's'.repeat(30),
				toolName: 't'.repeat(100),
				domainFingerprint: 'd'.repeat(128),
				sourceFingerprint: HEX64,
				coordinationKey: 'k'.repeat(256),
				idempotencyCoordinationKey: 'i'.repeat(256),
				minuteLimit: 0,
				hourLimit: 0,
				windowMs: 0,
				amount: 0,
				defaultValue: 0,
				initialUsed: 0,
				value: 0,
				sourceDailyLimit: 0,
				globalHourlyLimit: 0,
				globalDailyLimit: 0,
				expiresAt: 1,
				requestHash: HEX64,
				result: 'r'.repeat(MAX_RESULT_BYTES),
			}),
		).toBeUndefined();
	});
});

describe('validateQuotaFields: per-field boundaries', () => {
	it('rejects non-strings for the bounded-string fields', () => {
		for (const field of ['ip', 'principalId', 'scope', 'toolName']) {
			expect(errorFor({ [field]: 123 })).toMatch(/^Invalid /);
			expect(errorFor({ [field]: null })).toMatch(/^Invalid /);
		}
	});

	it('enforces the string length cap exactly (cap passes, cap+1 fails)', () => {
		expect(errorFor({ ip: 'x'.repeat(50) })).toBeUndefined();
		expect(errorFor({ ip: 'x'.repeat(51) })).toBe('Invalid ip: must be string <= 50 chars');
		expect(errorFor({ principalId: 'x'.repeat(100) })).toBeUndefined();
		expect(errorFor({ principalId: 'x'.repeat(101) })).toBe('Invalid principalId: must be string <= 100 chars');
		expect(errorFor({ scope: 's'.repeat(30) })).toBeUndefined();
		expect(errorFor({ scope: 's'.repeat(31) })).toBe('Invalid scope');
		expect(errorFor({ toolName: 't'.repeat(100) })).toBeUndefined();
		expect(errorFor({ toolName: 't'.repeat(101) })).toBe('Invalid toolName: must be string <= 100 chars');
	});

	it('accepts an empty string for ip, principalId, scope and toolName (only the cap is enforced)', () => {
		expect(errorFor({ ip: '', principalId: '', scope: '', toolName: '' })).toBeUndefined();
	});

	it('rejects empty, oversized, non-string and control-character fingerprints and keys', () => {
		const cases: Array<[string, number, string]> = [
			['domainFingerprint', 128, 'Invalid domainFingerprint: must be a non-empty printable string <= 128 chars'],
			['coordinationKey', 256, 'Invalid coordinationKey: must be a non-empty printable string <= 256 chars'],
			['idempotencyCoordinationKey', 256, 'Invalid idempotencyCoordinationKey: must be a non-empty printable string <= 256 chars'],
		];
		for (const [field, max, error] of cases) {
			expect(errorFor({ [field]: '' })).toBe(error);
			expect(errorFor({ [field]: 5 })).toBe(error);
			expect(errorFor({ [field]: 'a'.repeat(max) })).toBeUndefined();
			expect(errorFor({ [field]: 'a'.repeat(max + 1) })).toBe(error);
			expect(errorFor({ [field]: 'a\u0000b' })).toBe(error);
			expect(errorFor({ [field]: 'a\u001fb' })).toBe(error);
			expect(errorFor({ [field]: 'a\u007fb' })).toBe(error);
			expect(errorFor({ [field]: 'a b~' })).toBeUndefined();
		}
	});

	it('requires a lowercase 64-char hex digest for sourceFingerprint and requestHash', () => {
		const cases: Array<[string, string]> = [
			['sourceFingerprint', 'Invalid sourceFingerprint: must be a lowercase SHA-256 hex digest'],
			['requestHash', 'Invalid requestHash: must be a lowercase SHA-256 hex digest'],
		];
		for (const [field, error] of cases) {
			expect(errorFor({ [field]: HEX64 })).toBeUndefined();
			expect(errorFor({ [field]: 'a'.repeat(63) })).toBe(error);
			expect(errorFor({ [field]: 'a'.repeat(65) })).toBe(error);
			expect(errorFor({ [field]: 'A'.repeat(64) })).toBe(error);
			expect(errorFor({ [field]: 'g'.repeat(64) })).toBe(error);
			expect(errorFor({ [field]: 12345 })).toBe(error);
		}
	});

	it('requires a non-negative safe integer for every numeric field', () => {
		for (const field of NON_NEGATIVE_INT_FIELDS) {
			const error = `Invalid ${field}: must be a non-negative safe integer`;
			// `limit` is the required field of this payload, so a valid value is already supplied for it.
			expect(errorFor({ [field]: 0 })).toBeUndefined();
			expect(errorFor({ [field]: Number.MAX_SAFE_INTEGER })).toBeUndefined();
			for (const bad of [-1, 1.5, '1', null, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
				expect(errorFor({ [field]: bad })).toBe(error);
			}
		}
	});

	it('requires a positive safe integer for expiresAt', () => {
		const error = 'Invalid expiresAt: must be a positive safe integer';
		expect(errorFor({ expiresAt: 1 })).toBeUndefined();
		expect(errorFor({ expiresAt: Number.MAX_SAFE_INTEGER })).toBeUndefined();
		for (const bad of [0, -1, 1.5, '5', null, Number.MAX_SAFE_INTEGER + 1]) {
			expect(errorFor({ expiresAt: bad })).toBe(error);
		}
	});

	it('bounds result by UTF-8 bytes, not by string length', () => {
		const error = `Invalid result: must be a UTF-8 string <= ${MAX_RESULT_BYTES} bytes`;
		expect(errorFor({ result: '' })).toBeUndefined();
		expect(errorFor({ result: 'r'.repeat(MAX_RESULT_BYTES) })).toBeUndefined();
		expect(errorFor({ result: 'r'.repeat(MAX_RESULT_BYTES + 1) })).toBe(error);
		expect(errorFor({ result: 42 })).toBe(error);
		// 21846 euro signs = 65538 UTF-8 bytes but only 21846 UTF-16 units: a length check would pass it.
		expect(errorFor({ result: '€'.repeat(21_846) })).toBe(error);
		expect(errorFor({ result: '€'.repeat(21_845) })).toBeUndefined();
	});
});

describe('validateQuotaFields: first error wins by field order, not key order', () => {
	it('returns the earlier field error for every pair of invalid fields, in either key order', () => {
		for (let i = 0; i < ORDERED_FIELD_CASES.length; i++) {
			for (let j = i + 1; j < ORDERED_FIELD_CASES.length; j++) {
				const earlier = ORDERED_FIELD_CASES[i];
				const later = ORDERED_FIELD_CASES[j];
				// The `limit` field is a required field of this payload; an invalid pair containing it
				// simply replaces the valid default, so only the ordering is under test.
				expect(errorFor({ [earlier.field]: earlier.bad, [later.field]: later.bad })).toBe(earlier.error);
				expect(errorFor({ [later.field]: later.bad, [earlier.field]: earlier.bad })).toBe(earlier.error);
			}
		}
	});

	it('reports the earliest error when every field is invalid at once', () => {
		const everything = Object.fromEntries(ORDERED_FIELD_CASES.map((c) => [c.field, c.bad]));
		expect(errorFor(everything)).toBe(ORDERED_FIELD_CASES[0].error);
		const withoutIp = { ...everything };
		delete withoutIp.ip;
		expect(errorFor(withoutIp)).toBe(ORDERED_FIELD_CASES[1].error);
	});

	it('puts string fields before numeric fields before expiresAt, requestHash, result', () => {
		expect(errorFor({ hourLimit: -1, minuteLimit: -1 })).toBe('Invalid minuteLimit: must be a non-negative safe integer');
		expect(errorFor({ globalDailyLimit: -1, sourceDailyLimit: -1 })).toBe('Invalid sourceDailyLimit: must be a non-negative safe integer');
		expect(errorFor({ expiresAt: 0, globalDailyLimit: -1 })).toBe('Invalid globalDailyLimit: must be a non-negative safe integer');
		expect(errorFor({ requestHash: 'x', expiresAt: 0 })).toBe('Invalid expiresAt: must be a positive safe integer');
		expect(errorFor({ result: 9, requestHash: 'x' })).toBe('Invalid requestHash: must be a lowercase SHA-256 hex digest');
	});
});

describe('validateQuotaFields through evaluate sub-checks', () => {
	const goodCheck = { kind: 'tool-daily', principalId: 'p', toolName: 't', limit: 1 };

	it('applies the same field errors to an evaluate check', () => {
		const result = validateQuotaPayload({
			kind: 'evaluate',
			shardKey: 'k',
			checks: [{ ...goodCheck, toolName: 't'.repeat(101) }],
		});
		expect(result).toEqual({ valid: false, error: 'Invalid toolName: must be string <= 100 chars' });
	});

	it('returns the first field error in order for a multi-invalid evaluate check', () => {
		const result = validateQuotaPayload({
			kind: 'evaluate',
			shardKey: 'k',
			checks: [{ kind: 'scoped-rate', scope: 'tools', ip: 'x'.repeat(51), minuteLimit: -1, hourLimit: 1 }],
		});
		expect(result).toEqual({ valid: false, error: 'Invalid ip: must be string <= 50 chars' });
	});

	it('rejects a scoped-rate evaluate check whose scope is a short but unknown string', () => {
		const result = validateQuotaPayload({
			kind: 'evaluate',
			shardKey: 'k',
			checks: [{ kind: 'scoped-rate', scope: 'bogus', ip: '1.2.3.4', minuteLimit: 1, hourLimit: 1 }],
		});
		expect(result).toEqual({ valid: false, error: 'Invalid scope' });
	});

	it('reports a field error before the scope allowlist error', () => {
		const result = validateQuotaPayload({
			kind: 'evaluate',
			shardKey: 'k',
			checks: [{ kind: 'scoped-rate', scope: 'bogus', ip: 'x'.repeat(51), minuteLimit: 1, hourLimit: 1 }],
		});
		expect(result).toEqual({ valid: false, error: 'Invalid ip: must be string <= 50 chars' });
	});

	it('reports the first failing check of a batch', () => {
		const result = validateQuotaPayload({
			kind: 'evaluate',
			shardKey: 'k',
			checks: [goodCheck, { ...goodCheck, limit: -1 }, { ...goodCheck, principalId: 'p'.repeat(101) }],
		});
		expect(result).toEqual({ valid: false, error: 'Invalid limit: must be a non-negative safe integer' });
	});
});

describe('validateQuotaPayload: field errors vs kind-specific errors on a top-level payload', () => {
	it('reports missing required fields before any field error', () => {
		const result = validateQuotaPayload({ kind: 'tool-daily', principalId: 'p'.repeat(101), toolName: 't' });
		expect(result).toEqual({ valid: false, error: 'Invalid tool-daily: missing limit' });
	});

	it('reports a field error before the scoped-rate scope allowlist error', () => {
		const result = validateQuotaPayload({ kind: 'scoped-rate', scope: 'bogus', ip: 'x'.repeat(51), minuteLimit: 1, hourLimit: 1 });
		expect(result).toEqual({ valid: false, error: 'Invalid ip: must be string <= 50 chars' });
	});

	it('reports the scope allowlist error for a short unknown scope', () => {
		const result = validateQuotaPayload({ kind: 'scoped-rate', scope: 'bogus', ip: '1.2.3.4', minuteLimit: 1, hourLimit: 1 });
		expect(result).toEqual({ valid: false, error: 'Invalid scope' });
	});
});
