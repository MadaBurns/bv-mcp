// SPDX-License-Identifier: BUSL-1.1

/**
 * Direct, table-driven coverage of `parseTlsaRecord` (packages/dns-checks/src/checks/dane-analysis.ts).
 *
 * `parseTlsaRecord` has no direct test anywhere in this suite today — root test/dane-analysis.spec.ts
 * exercises it only indirectly through `analyzeTlsaRecords` (which runs in the Workers pool and isn't
 * counted toward this package's own-suite coverage), using a handful of presentation-form strings
 * (`'3 1 1 aabbccdd'`, `'garbage'`, `'\\# 35 03 01 01 aa bb cc dd'`) plus severity-per-field cases.
 * This file uses different literal inputs throughout so it adds coverage rather than duplicate
 * assertions, and calls `parseTlsaRecord` directly.
 *
 * The function does NOT validate usage/selector/matchingType against their defined ranges, and does
 * NOT validate certData as hex or cross-check its length against matchingType — those checks belong to
 * higher-level callers (see the "Invalid TLSA usage/selector/matching type" findings in
 * `analyzeTlsaRecords`). Tests below that feed out-of-range or non-hex certData values assert the
 * actual pass-through behavior, not a validation the source doesn't perform.
 */

import { describe, it, expect } from 'vitest';
import { parseTlsaRecord } from '../../checks/dane-analysis';

describe('parseTlsaRecord — presentation format', () => {
	const usages = [0, 1, 2, 3];
	const selectors = [0, 1];
	const matchingTypes = [0, 1, 2];
	const combos: Array<{ usage: number; selector: number; matchingType: number }> = [];
	for (const usage of usages) {
		for (const selector of selectors) {
			for (const matchingType of matchingTypes) {
				combos.push({ usage, selector, matchingType });
			}
		}
	}

	it.each(combos)('parses valid usage=$usage selector=$selector matchingType=$matchingType', ({ usage, selector, matchingType }) => {
		const result = parseTlsaRecord(`${usage} ${selector} ${matchingType} aabbccdd`);
		expect(result).toEqual({ usage, selector, matchingType, certData: 'aabbccdd' });
	});

	it('collapses extra internal whitespace between fields', () => {
		const result = parseTlsaRecord('  1   0   1   aa bb cc dd  ');
		expect(result).toEqual({ usage: 1, selector: 0, matchingType: 1, certData: 'aabbccdd' });
	});

	it('preserves uppercase hex in certData as-is (no case normalization)', () => {
		const result = parseTlsaRecord('3 1 2 ABCDEF01');
		expect(result).toEqual({ usage: 3, selector: 1, matchingType: 2, certData: 'ABCDEF01' });
	});

	it('preserves mixed-case hex in certData as-is', () => {
		const result = parseTlsaRecord('3 1 2 aAbBcCdD');
		expect(result).toEqual({ usage: 3, selector: 1, matchingType: 2, certData: 'aAbBcCdD' });
	});

	it('does not validate certData as hex — a non-hex tail is passed through', () => {
		const result = parseTlsaRecord('3 1 1 not-hex-data');
		expect(result).toEqual({ usage: 3, selector: 1, matchingType: 1, certData: 'not-hex-data' });
	});

	it.each([
		{ desc: 'usage out of range (5)', input: '5 1 1 aabbccdd', expected: { usage: 5, selector: 1, matchingType: 1, certData: 'aabbccdd' } },
		{ desc: 'selector out of range (9)', input: '3 9 1 aabbccdd', expected: { usage: 3, selector: 9, matchingType: 1, certData: 'aabbccdd' } },
		{
			desc: 'matchingType out of range (7)',
			input: '3 1 7 aabbccdd',
			expected: { usage: 3, selector: 1, matchingType: 7, certData: 'aabbccdd' },
		},
	])('returns a flagged (non-validated) record for $desc — source performs no range check', ({ input, expected }) => {
		expect(parseTlsaRecord(input)).toEqual(expected);
	});

	it.each([
		{ desc: 'empty string', input: '' },
		{ desc: 'whitespace only', input: '   ' },
		{ desc: 'missing certData field (only 3 tokens)', input: '3 1 1' },
		{ desc: 'garbage / non-numeric fields', input: 'not a valid record' },
	])('returns null for $desc', ({ input }) => {
		expect(parseTlsaRecord(input)).toBeNull();
	});
});

describe('parseTlsaRecord — RFC 3597 generic/wire format', () => {
	it('parses the backslash-hash marker form, discarding the RDLENGTH token', () => {
		// '\# 35' — the stated RDLENGTH (0x35) is discarded outright and never cross-checked
		// against the actual byte count that follows it.
		const result = parseTlsaRecord('\\# 35 03 00 01 aa bb cc dd');
		expect(result).toEqual({ usage: 3, selector: 0, matchingType: 1, certData: 'aabbccdd' });
	});

	it('parses the bare "#" marker form identically to "\\#"', () => {
		const result = parseTlsaRecord('# 03 00 01 aa bb');
		expect(result).toEqual({ usage: 0, selector: 1, matchingType: 170, certData: 'bb' });
	});

	/**
	 * When the leading token is a bare "#" glued to more characters (e.g. produced upstream as
	 * "#5" rather than "# 5"), `parts[0] === '#'` is false, so `hexStart` takes its `: 1` branch
	 * instead of `: 2`. Unlike CAA's fixed DoH wire encoding (always a separate marker token), a
	 * TLSA source can legitimately hit this — this case exercises that branch directly.
	 */
	it('takes the hexStart=1 branch when the marker token is glued to trailing text', () => {
		const result = parseTlsaRecord('#5 00 01 aa bb');
		expect(result).toEqual({ usage: 0, selector: 1, matchingType: 170, certData: 'bb' });
	});

	it('accepts uppercase and mixed-case hex bytes', () => {
		const result = parseTlsaRecord('\\# 3 0F 01 AA BB CC');
		expect(result).toEqual({ usage: 15, selector: 1, matchingType: 170, certData: 'BBCC' });
	});

	it('ignores a stated RDLENGTH that does not match the actual byte count (no cross-check)', () => {
		// Declared length (0x99) is far larger than the 4 hex-byte tokens actually present;
		// the source never compares them, so parsing still succeeds.
		const result = parseTlsaRecord('\\# 99 00 01 aa bb');
		expect(result).toEqual({ usage: 0, selector: 1, matchingType: 170, certData: 'bb' });
	});

	it.each([
		{ desc: 'truncated to fewer than 4 hex-byte tokens after the marker', input: '\\# 3 00 01 aa' },
		{ desc: 'only the marker and length, no hex bytes at all', input: '\\#' },
		{ desc: 'bare "#" with nothing else', input: '#' },
		{ desc: 'bare "#" glued to trailing text with too few bytes', input: '#garbage' },
	])('returns null when $desc', ({ input }) => {
		expect(parseTlsaRecord(input)).toBeNull();
	});

	it('returns null when a leading field byte is not valid hex', () => {
		// 'zz' in the usage-byte position is not parseable as hex, so parseInt yields NaN.
		const result = parseTlsaRecord('\\# 3 zz 00 01 aa');
		expect(result).toBeNull();
	});
});
