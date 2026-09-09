// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import {
	getIpTargetFindings,
	getNullMxFinding,
	getPresenceFinding,
	getSingleMxFinding,
	isNullMxRecord,
	parseMxRecords,
} from '../../checks/mx-analysis';

// Ported from the Worker-side `test/mx-analysis.spec.ts` when its subject
// (`src/tools/mx-analysis.ts`, a verbatim duplicate of this module) was
// deleted — the package export became the single implementation in #933.
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

	it('accepts exchange-only shapes for null-MX classification', () => {
		// Worker-side MX shapes carry no `raw`; the signature is Pick<'exchange'>.
		expect(isNullMxRecord({ exchange: '' })).toBe(true);
		expect(isNullMxRecord({ exchange: '.' })).toBe(true);
		expect(isNullMxRecord({ exchange: 'mx.example.com' })).toBe(false);
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
