// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import {
	getIpTargetFindings,
	getLoopbackMxFinding,
	getNullMxFinding,
	getPresenceFinding,
	getSingleMxFinding,
	isLoopbackMxRecord,
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

		// #944 (Option A) — null MX is ONLY the RFC 7505 form. A loopback exchange
		// receives no mail either, but classifying it here would silently reward a
		// non-standard config with the null-MX "not a mail control" path and re-grade
		// the domain. These negatives pin the decision; see the decision record on
		// `isNullMxRecord`. Measured: 0/992 in a stratified Tranco 1000 corpus,
		// 15/29,385 (0.051%) in a 29,780-domain sample, all of them `0 localhost.`.
		expect(isNullMxRecord({ exchange: 'localhost' })).toBe(false);
		expect(isNullMxRecord({ exchange: '127.0.0.1' })).toBe(false);
		expect(isNullMxRecord({ exchange: '::1' })).toBe(false);
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

describe('isLoopbackMxRecord', () => {
	it('matches loopback exchanges in every observed and normalised form', () => {
		// `localhost.` / `LOCALHOST.` cover Worker-side shapes, which reach this
		// predicate before `parseMxRecords` has stripped the dot or lowercased.
		for (const exchange of [
			'localhost',
			'localhost.',
			'LOCALHOST.',
			'mail.localhost',
			'localhost.localdomain',
			'127.0.0.1',
			'127.1.2.3',
			'::1',
		]) {
			expect(isLoopbackMxRecord({ exchange }), exchange).toBe(true);
		}
		// The wild form: all 15 loopback zones in the 29,780-domain sample published
		// exactly `0 localhost.`, which parses to exchange `localhost`.
		const [parsed] = parseMxRecords(['0 localhost.']);
		expect(parsed.exchange).toBe('localhost');
		expect(isLoopbackMxRecord(parsed)).toBe(true);
	});

	it('is a loopback matcher, not an "unroutable target" matcher', () => {
		// `.invalid` is the load-bearing negative: 22 domains in the same wild sample
		// carried Microsoft 365 `msNNNNNNNN.msv1.invalid` verification pseudo-MX
		// records on HEALTHY tenants, so an unroutable-target matcher would penalise
		// ordinary M365 customers (the SERVICE_SPF_DOMAINS over-match class).
		// `localhostings.com` is the suffix-collision guard — the same class as
		// "should avoid false positive suffix matches" in test/check-mx.spec.ts.
		for (const exchange of ['ms63602385.msv1.invalid', '0.0.0.0', 'mx.example.com', 'localhostings.com']) {
			expect(isLoopbackMxRecord({ exchange }), exchange).toBe(false);
		}
	});

	it('emits ONE medium finding for the whole loopback set, naming the exchanges', () => {
		// One finding, not one per record: penalties are additive and `mx` has no cap.
		const finding = getLoopbackMxFinding(parseMxRecords(['0 localhost.', '10 127.0.0.1']));
		expect(finding.title).toBe('MX points at localhost');
		expect(finding.severity).toBe('medium');
		expect(finding.category).toBe('mx');
		expect(finding.detail).toContain('localhost');
		expect(finding.detail).toContain('127.0.0.1');
		expect(finding.detail).toContain('RFC 7505');
		// MX records were MEASURED and are present — a defect, not an absent control.
		expect(finding.metadata?.missingControl).toBeFalsy();
	});
});
