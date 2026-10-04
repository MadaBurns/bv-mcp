// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { parseTlsRptRua } from '../../checks/tls-rpt-utils';
import { checkTLSRPT } from '../../checks/check-tlsrpt';
import { getTlsRptRecordFindings } from '../../checks/mta-sts-analysis';
import type { DNSQueryFunction } from '../../types';

function txtDNS(record: string): DNSQueryFunction {
	return vi.fn(async (domain: string) => (domain === '_smtp._tls.example.com' ? [record] : []));
}

describe('parseTlsRptRua', () => {
	it('reads a single mailto destination', () => {
		const rua = parseTlsRptRua('v=TLSRPTv1; rua=mailto:tls@example.com');
		expect(rua).toEqual({ present: true, uris: ['mailto:tls@example.com'], invalid: [] });
	});

	it('accepts an https collection endpoint', () => {
		expect(parseTlsRptRua('v=TLSRPTv1; rua=https://collect.example.com/tls').invalid).toEqual([]);
	});

	it('keeps every entry of a comma list whose separator is followed by a space', () => {
		// RFC 8460 §3.1 uses the CSV list from RFC 2822 §3.2.5, where the separator is
		// ", ". The old `[^;\s]+` capture stopped at that space, which left an empty
		// element behind and reported it as an invalid scheme.
		const rua = parseTlsRptRua('v=TLSRPTv1; rua=mailto:a@example.com, mailto:b@example.com');
		expect(rua.uris).toEqual(['mailto:a@example.com', 'mailto:b@example.com']);
		expect(rua.invalid).toEqual([]);
	});

	it('validates every entry, not just the one before the first space', () => {
		// The mirror defect: the `mta_sts` reader tested the whole captured value against a
		// single-URI regex, which `[^@\s]+` let match across a comma, so a garbage second
		// destination was never seen.
		const rua = parseTlsRptRua('v=TLSRPTv1; rua=mailto:a@example.com,junk-not-a-uri');
		expect(rua.invalid).toEqual(['junk-not-a-uri']);
	});

	it('reports each invalid entry when several are bad', () => {
		const rua = parseTlsRptRua('v=TLSRPTv1; rua=ftp://a/x, mailto:no-at-sign, https://ok.example.com');
		expect(rua.invalid).toEqual(['ftp://a/x', 'mailto:no-at-sign']);
	});

	it('does not read a tag that merely ends in "rua"', () => {
		// `rua\s*=` with no delimiter anchor matched `xrua=`, which invented a rua verdict for
		// an unrelated tag and masked the genuinely missing one.
		const rua = parseTlsRptRua('v=TLSRPTv1; xrua=ftp://bad.example.com/x');
		expect(rua.present).toBe(false);
	});

	it('treats an empty rua value as present but unusable', () => {
		const rua = parseTlsRptRua('v=TLSRPTv1; rua=');
		expect(rua.present).toBe(true);
		expect(rua.uris).toEqual([]);
	});

	it('accepts a quoted value', () => {
		const rua = parseTlsRptRua('v=TLSRPTv1; rua="mailto:a@example.com, mailto:b@example.com"');
		expect(rua.uris).toEqual(['mailto:a@example.com', 'mailto:b@example.com']);
		expect(rua.invalid).toEqual([]);
	});

	it('rejects a dotless mailto host, as both readers did before', () => {
		expect(parseTlsRptRua('v=TLSRPTv1; rua=mailto:postmaster@localhost').invalid).toEqual([
			'mailto:postmaster@localhost',
		]);
	});

	it('takes the first rua= tag when one record carries two', () => {
		const rua = parseTlsRptRua('v=TLSRPTv1; rua=mailto:a@example.com; rua=ftp://b/x');
		expect(rua.uris).toEqual(['mailto:a@example.com']);
		expect(rua.invalid).toEqual([]);
	});
});

describe('tlsrpt and mta_sts reach the same verdict on the same record', () => {
	// The two checks used to disagree in both directions, so a domain could be penalised in
	// one category and credited in the other for identical DNS data.
	const RECORDS = [
		'v=TLSRPTv1; rua=mailto:a@example.com',
		'v=TLSRPTv1; rua=mailto:a@example.com, mailto:b@example.com',
		'v=TLSRPTv1; rua=mailto:a@example.com,https://c.example.com/x',
		'v=TLSRPTv1; rua=mailto:a@example.com,junk-not-a-uri',
		'v=TLSRPTv1; rua=ftp://bad.example.com/x',
		'v=TLSRPTv1;',
		'v=TLSRPTv1; xrua=ftp://bad.example.com/x',
	];

	it.each(RECORDS)('%s', async (record) => {
		const tlsrpt = await checkTLSRPT('example.com', txtDNS(record));
		const tlsrptFlagged = tlsrpt.findings.some((f) => f.severity !== 'info');
		const mtaStsFlagged = getTlsRptRecordFindings([record]).findings.length > 0;
		expect(tlsrptFlagged).toBe(mtaStsFlagged);
	});

	it('credits a list whose separator is followed by a space instead of penalising it', async () => {
		const record = 'v=TLSRPTv1; rua=mailto:a@example.com, mailto:b@example.com';
		const result = await checkTLSRPT('example.com', txtDNS(record));
		expect(result.findings.map((f) => f.title)).toEqual(['TLS-RPT record configured']);
		expect(result.findings[0].severity).toBe('info');
	});

	it('penalises an invalid second destination in the scoring path that used to miss it', () => {
		const findings = getTlsRptRecordFindings(['v=TLSRPTv1; rua=mailto:a@example.com,junk-not-a-uri']);
		expect(findings.findings[0].title).toBe('TLS-RPT invalid rua format');
		expect(findings.findings[0].severity).toBe('medium');
	});
});
