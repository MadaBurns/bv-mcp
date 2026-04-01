import { describe, expect, it } from 'vitest';

import { getIpTargetFindings, getNullMxFinding, getPresenceFinding, getSingleMxFinding, isNullMxRecord, parseMxRecords } from '../src/tools/mx-analysis';

describe('mx-analysis', () => {
	it('parses MX records into structured values', () => {
		expect(parseMxRecords(['10 mx1.example.com.', '20 mx2.example.com.'])).toEqual([
			{ priority: 10, exchange: 'mx1.example.com', raw: '10 mx1.example.com.' },
			{ priority: 20, exchange: 'mx2.example.com', raw: '20 mx2.example.com.' },
		]);
	});

	it('detects null MX records', () => {
		const [record] = parseMxRecords(['0 .']);
		expect(isNullMxRecord(record)).toBe(true);
		expect(getNullMxFinding().title).toBe('Null MX record (RFC 7505)');
	});

	it('reports presence and single-MX redundancy findings', () => {
		const records = parseMxRecords(['10 mx.example.com.']);
		expect(getPresenceFinding(records).detail).toContain('1 mail exchange record');
		expect(getSingleMxFinding(records)?.severity).toBe('low');
		expect(getSingleMxFinding(parseMxRecords(['10 mx1.example.com.', '20 mx2.example.com.']))).toBeNull();
	});

	it('flags MX targets that are IP addresses', () => {
		const findings = getIpTargetFindings(parseMxRecords(['10 192.168.1.1', '20 mx.example.com.']));
		expect(findings).toHaveLength(1);
		expect(findings[0].title).toBe('MX points to IP address');
		expect(findings[0].severity).toBe('medium');
	});
});