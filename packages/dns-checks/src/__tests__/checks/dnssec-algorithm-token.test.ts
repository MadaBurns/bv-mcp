// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { parseDnssecAlgorithmToken, parseDnskeyAlgorithm, parseDsRecord } from '../../checks/dnssec-analysis';

describe('parseDnssecAlgorithmToken', () => {
	it('parses decimal strings unchanged', () => {
		expect(parseDnssecAlgorithmToken('13')).toBe(13);
		expect(parseDnssecAlgorithmToken('8')).toBe(8);
		expect(parseDnssecAlgorithmToken('2')).toBe(2);
	});

	it('parses IANA mnemonics (Cloudflare DoH format)', () => {
		expect(parseDnssecAlgorithmToken('ECDSAP256SHA256')).toBe(13);
		expect(parseDnssecAlgorithmToken('RSASHA256')).toBe(8);
		expect(parseDnssecAlgorithmToken('ED25519')).toBe(15);
	});

	it('normalizes hyphen/underscore/case variants before lookup', () => {
		expect(parseDnssecAlgorithmToken('DSA-NSEC3-SHA1')).toBe(6);
		expect(parseDnssecAlgorithmToken('rsasha1-nsec3-sha1')).toBe(7);
		expect(parseDnssecAlgorithmToken('ecc_gost')).toBe(12);
	});

	it('returns null for unknown tokens', () => {
		expect(parseDnssecAlgorithmToken('bogus')).toBeNull();
		expect(parseDnssecAlgorithmToken('')).toBeNull();
	});
});

describe('parseDnskeyAlgorithm (Cloudflare mnemonic + numeric parity)', () => {
	it('parses Cloudflare mnemonic algorithm field', () => {
		expect(parseDnskeyAlgorithm('256 3 ECDSAP256SHA256 AAAA')).toBe(13);
	});

	it('keeps numeric parsing unchanged', () => {
		expect(parseDnskeyAlgorithm('257 3 8 AwEAA...')).toBe(8);
		expect(parseDnskeyAlgorithm('257 3 13 mdsswUyr3DPW...')).toBe(13);
		expect(parseDnskeyAlgorithm('bad-record')).toBeNull();
	});
});

describe('parseDsRecord (Cloudflare mnemonic + numeric parity)', () => {
	it('parses Cloudflare mnemonic algorithm field', () => {
		expect(parseDsRecord('19718 ECDSAP256SHA256 2 8acb')).toEqual({ algorithm: 13, digestType: 2 });
	});

	it('keeps numeric parsing unchanged', () => {
		expect(parseDsRecord('12345 13 2 abc')).toEqual({ algorithm: 13, digestType: 2 });
		expect(parseDsRecord('invalid')).toBeNull();
	});
});
