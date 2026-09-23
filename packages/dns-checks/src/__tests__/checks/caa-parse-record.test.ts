// SPDX-License-Identifier: BUSL-1.1

/**
 * Direct, table-driven coverage of `parseCaaRecord` (packages/dns-checks/src/checks/caa-analysis.ts).
 *
 * `parseCaaRecord` itself has no direct test anywhere in this suite today — caa-analysis.test.ts
 * exercises `summarizeCaaTags`, `parseCaaParameters`, and the finding builders by constructing
 * `CaaRecord` objects by hand, and check-caa-rfc8657.test.ts drives the whole `checkCAA` pipeline.
 * Neither calls `parseCaaRecord` directly, so this file adds no duplicate assertions.
 */

import { describe, it, expect } from 'vitest';
import { parseCaaRecord } from '../../checks/caa-analysis';

/**
 * Build the Cloudflare DoH hex wire-format string for one CAA record.
 *
 * Both the `\#` and bare `#` marker forms the parser accepts carry the SAME shape — a marker
 * token followed by an RDLENGTH token (discarded) and then the flags/tagLen/tag/value hex
 * bytes — the parser's `hexStart` is `2` for either marker, never `1` in practice (the `: 1`
 * fallback is unreachable given the outer `startsWith('\\#') || startsWith('#')` guard already
 * requires `parts[0]` to be exactly one of those two tokens).
 */
function toWireFormat(flags: number, tag: string, value: string, options?: { plainHash?: boolean }): string {
	const toHexBytes = (s: string) =>
		Array.from(s)
			.map((ch) => ch.charCodeAt(0).toString(16).padStart(2, '0'))
			.join(' ');
	const flagsHex = flags.toString(16).padStart(2, '0');
	const tagLenHex = tag.length.toString(16).padStart(2, '0');
	const rdlength = 2 + tag.length + value.length;
	const marker = options?.plainHash ? '#' : '\\#';
	return `${marker} ${rdlength.toString(16).padStart(2, '0')} ${flagsHex} ${tagLenHex} ${toHexBytes(tag)} ${toHexBytes(value)}`.trim();
}

describe('parseCaaRecord — presentation format', () => {
	it.each([
		{ desc: 'flags 0, quoted value', input: '0 issue "letsencrypt.org"', expected: { flags: 0, tag: 'issue', value: 'letsencrypt.org' } },
		{
			desc: 'flags 128 (critical bit)',
			input: '128 issue "letsencrypt.org"',
			expected: { flags: 128, tag: 'issue', value: 'letsencrypt.org' },
		},
		{ desc: 'issuewild tag', input: '0 issuewild "letsencrypt.org"', expected: { flags: 0, tag: 'issuewild', value: 'letsencrypt.org' } },
		{
			desc: 'iodef tag with a mailto value',
			input: '0 iodef "mailto:security@example.com"',
			expected: { flags: 0, tag: 'iodef', value: 'mailto:security@example.com' },
		},
		{
			desc: 'case-insensitive tag is lowercased',
			input: '0 ISSUE "letsencrypt.org"',
			expected: { flags: 0, tag: 'issue', value: 'letsencrypt.org' },
		},
		{
			desc: 'mixed-case tag is lowercased',
			input: '0 IssueWild "letsencrypt.org"',
			expected: { flags: 0, tag: 'issuewild', value: 'letsencrypt.org' },
		},
		{
			desc: 'unquoted value is taken verbatim (no stripping needed)',
			input: '0 issue letsencrypt.org',
			expected: { flags: 0, tag: 'issue', value: 'letsencrypt.org' },
		},
		{
			desc: 'quoted value has exactly one layer of quotes stripped',
			input: '0 issue "letsencrypt.org"',
			expected: { flags: 0, tag: 'issue', value: 'letsencrypt.org' },
		},
		{
			desc: 'RFC 8659 §4.2 explicit no-issuance form: quoted ";"',
			input: '0 issue ";"',
			expected: { flags: 0, tag: 'issue', value: ';' },
		},
		{
			desc: 'RFC 8659 §4.2 explicit no-issuance form: unquoted ";"',
			input: '0 issue ;',
			expected: { flags: 0, tag: 'issue', value: ';' },
		},
		{
			desc: 'RFC 8657 accounturi parameter is preserved verbatim in the value',
			input: '0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/12345"',
			expected: { flags: 0, tag: 'issue', value: 'letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/12345' },
		},
		{
			desc: 'RFC 8657 validationmethods parameter is preserved verbatim in the value',
			input: '0 issuewild "letsencrypt.org; validationmethods=dns-01,http-01"',
			expected: { flags: 0, tag: 'issuewild', value: 'letsencrypt.org; validationmethods=dns-01,http-01' },
		},
		{
			desc: 'value with internal whitespace around the closing quote is trimmed first',
			input: '0 issue   "letsencrypt.org"  ',
			expected: { flags: 0, tag: 'issue', value: 'letsencrypt.org' },
		},
	])('$desc', ({ input, expected }) => {
		expect(parseCaaRecord(input)).toEqual(expected);
	});
});

describe('parseCaaRecord — malformed presentation-format input returns null, never throws', () => {
	it.each([
		{ desc: 'missing value entirely (no trailing separator)', input: '0 issue' },
		{ desc: 'non-numeric flags', input: 'abc issue "letsencrypt.org"' },
		{ desc: 'garbage with no flags/tag structure at all', input: 'not a caa record at all' },
		{ desc: 'empty string', input: '' },
	])('$desc', ({ input }) => {
		expect(parseCaaRecord(input)).toBeNull();
	});

	it('a bare flags+tag with a trailing separator and no value parses to an empty value, not null', () => {
		// The prefix regex only requires trailing whitespace after the tag — an absent value
		// after that separator is a distinct (still well-formed) shape from a missing separator.
		expect(parseCaaRecord('0 issue ')).toEqual({ flags: 0, tag: 'issue', value: '' });
	});
});

describe('parseCaaRecord — Cloudflare DoH hex wire format', () => {
	it('parses the "\\#" form identically to the presentation form', () => {
		const wire = toWireFormat(0, 'issue', 'letsencrypt.org');
		expect(parseCaaRecord(wire)).toEqual({ flags: 0, tag: 'issue', value: 'letsencrypt.org' });
	});

	it('parses the critical flag (128) in wire format', () => {
		const wire = toWireFormat(128, 'issue', 'letsencrypt.org');
		expect(parseCaaRecord(wire)).toEqual({ flags: 128, tag: 'issue', value: 'letsencrypt.org' });
	});

	it('parses the issuewild tag in wire format', () => {
		const wire = toWireFormat(0, 'issuewild', 'letsencrypt.org');
		expect(parseCaaRecord(wire)).toEqual({ flags: 0, tag: 'issuewild', value: 'letsencrypt.org' });
	});

	it('parses the iodef tag in wire format', () => {
		const wire = toWireFormat(0, 'iodef', 'mailto:security@example.com');
		expect(parseCaaRecord(wire)).toEqual({ flags: 0, tag: 'iodef', value: 'mailto:security@example.com' });
	});

	it('parses the bare "#" marker form identically to the "\\#" form', () => {
		const wire = toWireFormat(0, 'issue', 'letsencrypt.org', { plainHash: true });
		expect(parseCaaRecord(wire)).toEqual({ flags: 0, tag: 'issue', value: 'letsencrypt.org' });
	});

	it('lowercases a tag decoded from hex bytes just like the presentation-format path', () => {
		// Wire format carries the tag as raw bytes, so this exercises tag.toLowerCase() on the
		// hex-decode path specifically (a mixed-case tag never appears on the wire in practice,
		// but the decoder does not special-case case, so verify it is normalized all the same).
		const wire = toWireFormat(0, 'ISSUE', 'letsencrypt.org');
		expect(parseCaaRecord(wire)?.tag).toBe('issue');
	});

	it('preserves RFC 8657 parameters through the hex value bytes', () => {
		const wire = toWireFormat(0, 'issue', 'letsencrypt.org; accounturi=https://acme.example/acct/1');
		expect(parseCaaRecord(wire)).toEqual({
			flags: 0,
			tag: 'issue',
			value: 'letsencrypt.org; accounturi=https://acme.example/acct/1',
		});
	});
});

describe('parseCaaRecord — malformed wire-format input returns null, never throws', () => {
	it('too few hex byte tokens to contain even flags+tagLen', () => {
		expect(parseCaaRecord('\\# 01 00')).toBeNull();
	});

	it('declared tagLen longer than the remaining hex bytes', () => {
		// flags=00, tagLen=05 ("issue"), but only 2 bytes follow — not enough for the tag, let
		// alone a value.
		expect(parseCaaRecord('\\# 04 00 05 69 73')).toBeNull();
	});

	it('non-hex flags byte', () => {
		expect(parseCaaRecord('\\# 05 zz 05 69 73 73 75 65')).toBeNull();
	});

	it('non-hex tagLen byte', () => {
		expect(parseCaaRecord('\\# 05 00 zz 69 73 73 75 65')).toBeNull();
	});
});
