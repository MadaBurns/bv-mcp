import { describe, expect, it } from 'vitest';
import { parseCaaRecord } from '../src/lib/dns';

describe('dns record helpers', () => {
	it('parses human-readable CAA records', () => {
		expect(parseCaaRecord('0 issue "letsencrypt.org"')).toEqual({
			flags: 0,
			tag: 'issue',
			value: 'letsencrypt.org',
		});
	});

	it('parses hex wire-format CAA records', () => {
		expect(parseCaaRecord('\\# 16 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67')).toEqual({
			flags: 0,
			tag: 'issue',
			value: 'letsencrypt.org',
		});
	});
});