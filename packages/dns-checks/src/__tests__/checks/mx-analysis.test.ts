// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import {
	getInvalidMxExchangeFinding,
	getIpTargetFindings,
	getLoopbackMxFinding,
	getNullMxFinding,
	getPresenceFinding,
	getSingleMxFinding,
	isInvalidMxExchangeRecord,
	isLoopbackMxRecord,
	isMailRoutingMxRecord,
	isNullMxRecord,
	isSyntacticallyValidHostname,
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

/**
 * #1114 — an MX exchange that is not a syntactically valid hostname (`300 ~.`,
 * measured live on a ServiceNow lookalike) cannot route mail. RFC 5321 §4.1.2
 * `Domain` / RFC 1123 §2.1: labels are letters, digits and hyphen, 1-63 octets,
 * no leading/trailing hyphen, total <= 253. Underscore is NOT allowed in a
 * hostname (it is legal in general DNS owner names such as `_dmarc`, which is
 * exactly why a hostname-specific predicate is needed here).
 */
describe('isSyntacticallyValidHostname', () => {
	it('accepts RFC 1123 hostnames, with or without a trailing dot', () => {
		for (const name of [
			'mx.example.com',
			'mx.example.com.',
			'MX1.Example.COM',
			'aspmx.l.google.com',
			'3com.example', // RFC 1123 relaxed the first character to allow a digit
			'a-b.example',
			'xn--bcher-kva.example', // punycode IDN
			'ms63602385.msv1.invalid', // M365 verification pseudo-MX: syntactically valid (#944)
			'192.0.2.10', // IP literals are syntactically valid; `getIpTargetFindings` owns them
			`${'a'.repeat(63)}.example`,
		]) {
			expect(isSyntacticallyValidHostname(name), name).toBe(true);
		}
	});

	it('rejects names that break LDH label syntax', () => {
		for (const name of [
			'~',
			'~.',
			'mail_server.example.com',
			'mail_server.example.com.',
			'',
			'.',
			'a..example',
			'-mx.example.com',
			'mx-.example.com',
			'mx example.com',
			'*.example.com',
			'::1',
			`${'a'.repeat(64)}.example`,
			`${'a.'.repeat(127)}ab`, // 255 octets
		]) {
			expect(isSyntacticallyValidHostname(name), JSON.stringify(name)).toBe(false);
		}
	});

	it('enforces the 253-octet total (trailing dot not counted)', () => {
		const at253 = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`;
		expect(at253.length).toBe(253);
		expect(isSyntacticallyValidHostname(at253)).toBe(true);
		expect(isSyntacticallyValidHostname(`${at253}.`)).toBe(true);
		expect(isSyntacticallyValidHostname(`${at253}d`)).toBe(false);
	});
});

describe('isInvalidMxExchangeRecord / isMailRoutingMxRecord (#1114)', () => {
	it('classifies the wild `300 ~.` and an underscore exchange as invalid, not mail-routing', () => {
		for (const raw of ['300 ~.', '10 mail_server.example.com.']) {
			const [record] = parseMxRecords([raw]);
			expect(isInvalidMxExchangeRecord(record), raw).toBe(true);
			expect(isMailRoutingMxRecord(record), raw).toBe(false);
		}
	});

	it('leaves null MX and loopback to their own classifiers', () => {
		// Null MX is its own no-mail declaration; loopback is the #944 Option-A defect
		// that stays a present mail control. Neither is "invalid".
		for (const raw of ['0 .', '0 localhost.', '10 ::1', '10 127.0.0.1']) {
			const [record] = parseMxRecords([raw]);
			expect(isInvalidMxExchangeRecord(record), raw).toBe(false);
		}
		expect(isMailRoutingMxRecord(parseMxRecords(['0 .'])[0])).toBe(false);
		// #944 Option A: loopback still counts as inbound-mail-receiving.
		expect(isMailRoutingMxRecord(parseMxRecords(['0 localhost.'])[0])).toBe(true);
		expect(isMailRoutingMxRecord(parseMxRecords(['10 ::1'])[0])).toBe(true);
	});

	it('treats a valid-but-unresolvable exchange as mail-routing (dangling is a separate verdict)', () => {
		const [record] = parseMxRecords(['10 ghost.example.com.']);
		expect(isInvalidMxExchangeRecord(record)).toBe(false);
		expect(isMailRoutingMxRecord(record)).toBe(true);
	});

	it('accepts Worker-side shapes (trailing dot, mixed case, no raw)', () => {
		expect(isMailRoutingMxRecord({ exchange: 'MX.Example.com.' })).toBe(true);
		expect(isInvalidMxExchangeRecord({ exchange: '~.' })).toBe(true);
	});

	it('emits ONE low finding naming every invalid literal, without missingControl', () => {
		const finding = getInvalidMxExchangeFinding(parseMxRecords(['300 ~.', '10 mail_server.example.com.']));
		expect(finding.title).toBe('Invalid MX exchange hostname');
		expect(finding.severity).toBe('low');
		expect(finding.category).toBe('mx');
		expect(finding.detail).toContain('"~"');
		expect(finding.detail).toContain('mail_server.example.com');
		expect(finding.detail).toContain('RFC 7505');
		expect(finding.metadata?.missingControl).toBeFalsy();
	});
});
