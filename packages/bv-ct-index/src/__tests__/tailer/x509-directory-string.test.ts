// SPDX-License-Identifier: BUSL-1.1
/**
 * `parseTbsCertificate`'s directory-string decoding (the issuer CN/O and the subject CN fallback) on
 * synthetic TBSCertificates. The real-leaf fixtures in parse.test.ts only carry UTF8String and
 * PrintableString values, so the BMPString branch and the single-byte Latin-1 branch are built by hand here.
 */

import { describe, expect, it } from 'vitest';
import { parseTbsCertificate } from '../../tailer/x509';

const UTF8_STRING = 0x0c;
const PRINTABLE_STRING = 0x13;
const BMP_STRING = 0x1e;
const OID_CN = [0x06, 0x03, 0x55, 0x04, 0x03];
const OID_O = [0x06, 0x03, 0x55, 0x04, 0x0a];

function tlv(tag: number, content: number[]): number[] {
	if (content.length < 0x80) return [tag, content.length, ...content];
	return [tag, 0x82, content.length >> 8, content.length & 0xff, ...content];
}

const seq = (...parts: number[][]) => tlv(0x30, parts.flat());
const text = (value: string) => [...new TextEncoder().encode(value)];
const latin1Bytes = (value: string) => [...value].map((c) => c.charCodeAt(0));
const bmpBytes = (value: string) => [...value].flatMap((c) => [c.charCodeAt(0) >> 8, c.charCodeAt(0) & 0xff]);

/** Name = SEQUENCE OF SET OF SEQUENCE { type OID, value }. */
function name(attributes: { oid: number[]; tag: number; bytes: number[] }[]): number[] {
	return seq(...attributes.map((a) => tlv(0x31, seq(a.oid, tlv(a.tag, a.bytes)))));
}

const VALIDITY = seq(tlv(0x17, text('260101000000Z')), tlv(0x17, text('270101000000Z')));
const SIGNATURE_ALG = seq([0x06, 0x01, 0x2a]);
const SPKI = seq(SIGNATURE_ALG, [0x03, 0x01, 0x00]);

function tbs(issuer: number[], subject: number[]): Uint8Array {
	return Uint8Array.from(seq([0x02, 0x01, 0x01], SIGNATURE_ALG, issuer, VALIDITY, subject, SPKI));
}

describe('parseTbsCertificate directory strings', () => {
	it('decodes a UTF8String issuer CN as UTF-8', () => {
		const issuer = name([{ oid: OID_CN, tag: UTF8_STRING, bytes: text('Cafe é CA') }]);
		const subject = name([{ oid: OID_CN, tag: UTF8_STRING, bytes: text('example.test') }]);
		expect(parseTbsCertificate(tbs(issuer, subject)).issuer).toBe('Cafe é CA');
	});

	it('decodes a BMPString issuer CN as big-endian UTF-16 code units', () => {
		const issuer = name([{ oid: OID_CN, tag: BMP_STRING, bytes: bmpBytes('Zürich CA 中') }]);
		const subject = name([{ oid: OID_CN, tag: UTF8_STRING, bytes: text('example.test') }]);
		expect(parseTbsCertificate(tbs(issuer, subject)).issuer).toBe('Zürich CA 中');
	});

	it('drops a dangling odd trailing byte of a BMPString instead of reading past its end', () => {
		const issuer = name([{ oid: OID_CN, tag: BMP_STRING, bytes: [...bmpBytes('AB'), 0x43] }]);
		const subject = name([{ oid: OID_CN, tag: UTF8_STRING, bytes: text('example.test') }]);
		expect(parseTbsCertificate(tbs(issuer, subject)).issuer).toBe('AB');
	});

	it('decodes a single-byte string type (Printable/IA5/Teletex) as Latin-1, one char per byte', () => {
		const issuer = name([{ oid: OID_CN, tag: PRINTABLE_STRING, bytes: latin1Bytes('Café CA') }]);
		const subject = name([{ oid: OID_CN, tag: UTF8_STRING, bytes: text('example.test') }]);
		expect(parseTbsCertificate(tbs(issuer, subject)).issuer).toBe('Café CA');
	});

	it('falls back to the issuer organization, decoded the same way, when there is no issuer CN', () => {
		const issuer = name([{ oid: OID_O, tag: BMP_STRING, bytes: bmpBytes('Org é') }]);
		const subject = name([{ oid: OID_CN, tag: UTF8_STRING, bytes: text('example.test') }]);
		expect(parseTbsCertificate(tbs(issuer, subject)).issuer).toBe('Org é');
	});

	it('reads the subject CN as the name list when there is no SAN extension, in each string encoding', () => {
		const issuer = name([{ oid: OID_CN, tag: UTF8_STRING, bytes: text('CA') }]);
		const subject = name([
			{ oid: OID_CN, tag: UTF8_STRING, bytes: text('utf8.example') },
			{ oid: OID_CN, tag: BMP_STRING, bytes: bmpBytes('bmp.example') },
			{ oid: OID_CN, tag: PRINTABLE_STRING, bytes: latin1Bytes('latin.example') },
		]);
		expect(parseTbsCertificate(tbs(issuer, subject)).names).toEqual(['utf8.example', 'bmp.example', 'latin.example']);
	});
});
