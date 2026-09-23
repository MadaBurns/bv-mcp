// SPDX-License-Identifier: BUSL-1.1

/**
 * RFC 9460 wire-format SvcParams for `parseHttpsRecordWire` (CRAP 333, issue #1094a).
 *
 * `parseHttpsRecordWire` is not exported — Cloudflare DoH JSON returns HTTPS (type 65)
 * answers as RFC 3597 generic wire format (`\# <length> <hex>`), and this file drives
 * that parser exclusively through the public `checkSVCBHTTPS` entry point with a
 * mocked `queryDNS`, exactly as production does. Every wire record below is built
 * from primitive byte arrays (never hand-typed hex) so the encoding is traceable back
 * to RFC 9460 §2 (SvcPriority, TargetName, SvcParams) and RFC 7301 (ALPN protocol IDs).
 */

import { describe, expect, it, vi } from 'vitest';

import { checkSVCBHTTPS } from '../../checks/check-svcb-https';
import type { CheckResult, DNSQueryFunction } from '../../types';

// ── Wire-format builders — no hand-typed hex anywhere below ─────────────────

function bytesToHex(bytes: number[]): string {
	return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** RFC 3597 generic wire-format record: `\# <declared-length> <hex>`. `declaredLenOverride` lets a test lie about the length. */
function rawWire(declaredLen: number, hex: string): string {
	return `\\# ${declaredLen} ${hex}`;
}

function wireRecord(bytes: number[], declaredLenOverride?: number): string {
	return rawWire(declaredLenOverride ?? bytes.length, bytesToHex(bytes));
}

function u16(n: number): number[] {
	return [(n >> 8) & 0xff, n & 0xff];
}

/** DNS wire-format name: length-prefixed labels terminated by a zero-length root label. `[]` = the root name alone. */
function encodeName(labels: string[]): number[] {
	const out: number[] = [];
	for (const label of labels) {
		out.push(label.length);
		for (let i = 0; i < label.length; i++) out.push(label.charCodeAt(i));
	}
	out.push(0);
	return out;
}

/** RFC 7301 ALPN value: a sequence of 1-byte-length-prefixed protocol-id strings. */
function encodeAlpnValue(protocols: string[]): number[] {
	const out: number[] = [];
	for (const p of protocols) {
		out.push(p.length);
		for (let i = 0; i < p.length; i++) out.push(p.charCodeAt(i));
	}
	return out;
}

/** One SvcParam: 2-byte key, 2-byte length, value bytes (RFC 9460 §2.1). */
function encodeParam(key: number, value: number[]): number[] {
	return [...u16(key), ...u16(value.length), ...value];
}

/** Full HTTPS RDATA: SvcPriority + TargetName + concatenated SvcParams, as one wire-format record string. */
function httpsRecord(priority: number, targetLabels: string[], params: number[][] = []): string {
	return wireRecord([...u16(priority), ...encodeName(targetLabels), ...params.flat()]);
}

function mockDNS(records: string[]): DNSQueryFunction {
	return vi.fn(async () => records);
}

function findingTitled(result: CheckResult, title: string) {
	return result.findings.find((f) => f.title === title);
}

const DOMAIN = 'example.com';

describe('checkSVCBHTTPS — RFC 9460 wire-format SvcParams (parseHttpsRecordWire)', () => {
	describe('well-formed wire records', () => {
		it('parses SvcPriority + ALPN + ECH from a root TargetName, tolerating ipv4hint/ipv6hint/port/unknown-key/zero-length params in non-ascending key order', async () => {
			const record = httpsRecord(1, [], [
				encodeParam(3, u16(8443)), // port — placed BEFORE alpn: RFC 9460 key order is not required to be ascending on the wire
				encodeParam(1, encodeAlpnValue(['h2', 'h3'])), // alpn
				encodeParam(2, []), // no-default-alpn — zero-length value
				encodeParam(65280, [9, 9]), // private-use key (65280-65534): must be skipped, not misread as alpn/ech
				encodeParam(4, [192, 0, 2, 1]), // ipv4hint
				encodeParam(6, Array.from({ length: 16 }, (_unused, i) => i)), // ipv6hint
				encodeParam(5, [1, 2, 3, 4]), // ech
			]);

			const result = await checkSVCBHTTPS(DOMAIN, mockDNS([record]));

			expect(result.recordPresent).toBe(true);
			const configured = findingTitled(result, 'HTTPS record configured');
			expect(configured?.metadata).toMatchObject({ priority: 1, alpn: ['h2', 'h3'], ech: true });
			expect(findingTitled(result, 'HTTP/3 (QUIC) advertised via HTTPS record')).toBeDefined();
			expect(findingTitled(result, 'Encrypted Client Hello (ECH) advertised')).toBeDefined();
			expect(findingTitled(result, 'HTTPS record does not advertise HTTP/2')).toBeUndefined();
			expect(findingTitled(result, 'HTTPS record missing ALPN parameter')).toBeUndefined();
		});

		it('parses a non-root TargetName with a single ALPN protocol', async () => {
			const record = httpsRecord(2, ['svc', 'example', 'com'], [encodeParam(1, encodeAlpnValue(['h2']))]);

			const result = await checkSVCBHTTPS(DOMAIN, mockDNS([record]));

			const configured = findingTitled(result, 'HTTPS record configured');
			expect(configured?.metadata).toMatchObject({ priority: 2, alpn: ['h2'], ech: false });
			expect(findingTitled(result, 'HTTPS record does not advertise HTTP/2')).toBeUndefined();
			expect(findingTitled(result, 'HTTP/3 (QUIC) advertised via HTTPS record')).toBeUndefined();
		});

		it('treats SvcPriority 0 as AliasMode and does not evaluate ALPN/ECH', async () => {
			const record = httpsRecord(0, ['alias', 'example', 'com']);

			const result = await checkSVCBHTTPS(DOMAIN, mockDNS([record]));

			const alias = findingTitled(result, 'HTTPS record in alias mode');
			expect(alias?.metadata).toMatchObject({ mode: 'alias' });
			// AliasMode suppresses the ALPN-based summary findings entirely (`!hasAliasMode` gate).
			expect(findingTitled(result, 'HTTPS record does not advertise HTTP/2')).toBeUndefined();
			expect(findingTitled(result, 'HTTPS record missing ALPN parameter')).toBeUndefined();
		});

		it('handles a zero-length ALPN value without error and reports it as a missing ALPN parameter', async () => {
			const record = httpsRecord(1, [], [encodeParam(1, [])]);

			const result = await checkSVCBHTTPS(DOMAIN, mockDNS([record]));

			const configured = findingTitled(result, 'HTTPS record configured');
			expect(configured?.metadata).toMatchObject({ priority: 1, alpn: [], ech: false });
			expect(findingTitled(result, 'HTTPS record missing ALPN parameter')).toBeDefined();
		});
	});

	describe('SvcParam-level truncation — parses what it can, never throws', () => {
		it('stops SvcParam parsing (without throwing) when a param length overruns the remaining buffer, keeping params parsed before the break', async () => {
			const echParam = encodeParam(5, [9]); // parsed successfully first
			const truncatedAlpnHeader = [...u16(1), ...u16(10)]; // alpn key declares 10 value bytes; none follow
			const record = wireRecord([...u16(1), 0, ...echParam, ...truncatedAlpnHeader]);

			const result = await checkSVCBHTTPS(DOMAIN, mockDNS([record]));

			const configured = findingTitled(result, 'HTTPS record configured');
			expect(configured?.metadata).toMatchObject({ priority: 1, alpn: [], ech: true });
		});

		it('drops a truncated ALPN protocol-id entry but keeps parsing subsequent SvcParams', async () => {
			const truncatedAlpnValue = [5, 104, 50]; // claims a 5-byte protocol id but only 2 bytes ('h','2') are present
			const record = wireRecord([...u16(1), 0, ...encodeParam(1, truncatedAlpnValue), ...encodeParam(5, [9])]);

			const result = await checkSVCBHTTPS(DOMAIN, mockDNS([record]));

			const configured = findingTitled(result, 'HTTPS record configured');
			// The ALPN entry itself is dropped (never pushed), but the outer loop still
			// advances past it correctly and parses the ECH param that follows.
			expect(configured?.metadata).toMatchObject({ priority: 1, alpn: [], ech: true });
		});
	});

	describe('malformed and hostile wire records — safe fallback, never a throw', () => {
		const priorityPlusRoot = [...u16(1), 0]; // minimum valid encoding: priority=1 + root TargetName, no params

		const cases: Array<[string, string]> = [
			// hexStart=1 branch: the length token is glued to the marker with no space
			// (`\#3` instead of `\# 3`), so `parseInt('\#3', 10)` is NaN.
			['length token glued to the marker (no space) parses as NaN and is rejected', wireRecord(priorityPlusRoot).replace('\\# ', '\\#')],
			// declaredLen below the 3-byte minimum (2 bytes cannot even hold priority + a root label).
			['declared length below the 3-byte minimum is rejected', rawWire(2, bytesToHex([0, 1]))],
			// declaredLen valid but the supplied hex is shorter than declaredLen*2.
			['hex payload shorter than the declared length is rejected', rawWire(5, bytesToHex([0, 1, 0, 0, 1]).slice(0, 8))],
			// declaredLen/hex length agree, but a byte pair is not valid hex.
			['non-hex characters in the payload are rejected', rawWire(3, '00zz00')],
			// TargetName label length uses a DNS-compression-pointer prefix (>= 0xc0), forbidden in SVCB records.
			['a DNS-compression pointer in TargetName (labelLen >= 0xc0) is rejected', wireRecord([...u16(1), 0xc0])],
			// TargetName label length claims more bytes than remain in the buffer.
			['a TargetName label length overrunning the buffer is rejected', wireRecord([...u16(1), 5, 97, 98])],
		];

		it.each(cases)('%s — no throw, falls back to presentation parsing', async (_label, record) => {
			// Every case above makes `parseHttpsRecordWire` return null. `checkSVCBHTTPS`
			// then falls back to the presentation-format regexes on the same raw string;
			// since none of these malformed strings contain a leading digit or `alpn=`/`ech=`
			// text, that fallback abstains to priority=null, alpn=[] rather than throwing or
			// misreporting a value it never measured.
			const result = await checkSVCBHTTPS(DOMAIN, mockDNS([record]));

			expect(result.category).toBe('svcb_https');
			const configured = findingTitled(result, 'HTTPS record configured');
			expect(configured?.metadata).toMatchObject({ priority: null, alpn: [], ech: false });
			expect(findingTitled(result, 'HTTPS record missing ALPN parameter')).toBeDefined();
		});
	});
});
