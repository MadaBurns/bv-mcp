// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #841 — the DANE info finding claimed "Valid TLSA record configured" for any
 * syntactically well-formed TLSA record, without ever comparing the pinned data to
 * the certificate the host actually serves. A stale DANE-EE pin (which actively
 * breaks every DANE-validating client, and is DNSSEC-enforced) read as a pass.
 *
 * This file pins the NO-PROBE posture (scoring model 1.18.0): when no served
 * certificate reaches the package — every BSL self-host, and every `check_dane`
 * (SMTP, port 25) call, which a browser probe cannot serve — the finding must be
 * HONEST: state presence + syntactic validity, state that the certificate match was
 * NOT verified, and carry machine-readable metadata saying so.
 *
 * Real verification landed in scoring model 1.22.0: the bv-mcp wrapper captures the
 * served leaf / SPKI over the operator-only bv-tls-probe binding (CDP
 * `Security.visibleSecurityStateChanged` carries the DER chain) and passes it in as
 * `ServedCertificate`; the verified / mismatch / unmeasured ladder is pinned by
 * dane-pin-verification.test.ts. Nothing in this file is superseded by that — the
 * posture it pins is exactly what a consumer WITHOUT the probe still gets.
 *
 * Pinned here:
 *  1. The low finding never uses the word "Valid" for an unverified pin.
 *  2. The detail states the certificate match was not verified.
 *  3. metadata.certificateMatchVerified === false (machine-readable marker).
 *  4. An unverified pin receives a small deduction instead of full marks.
 *  5. The title "DANE TLSA configured for <name>" is unchanged. (Maturity staging no
 *     longer regex-matches it — since 1.22.0 it counts a DANE pin toward Stage 4 only
 *     when the finding carries `certificateMatchVerified: true`.)
 */

import { describe, it, expect } from 'vitest';
import { analyzeTlsaRecords } from '../../checks/dane-analysis';
import { checkDANEHTTPS } from '../../checks/check-dane-https';
import type { DNSQueryFunction, RawDNSQueryFunction } from '../../types';

const SHA256_HASH = '0000000000000000000000000000000000000000000000000000000000000001';

describe('analyzeTlsaRecords — honest labeling of unverified pins (#841)', () => {
	it('does not claim "Valid" for a single well-formed record it never verified', () => {
		const findings = analyzeTlsaRecords([`3 1 1 ${SHA256_HASH}`], '_443._tcp.example.com', true);
		const unverified = findings.find((f) => f.title.startsWith('DANE TLSA configured'));
		expect(unverified).toBeDefined();
		expect(unverified!.severity).toBe('low');
		expect(unverified!.title).toBe('DANE TLSA configured for _443._tcp.example.com');
		expect(unverified!.detail).not.toMatch(/valid tlsa/i);
		expect(unverified!.detail).toMatch(/does not verify/i);
		expect(unverified!.detail).toMatch(/well-formed/i);
		expect(unverified!.metadata?.certificateMatchVerified).toBe(false);
	});

	it('does not overstate stale-pin impact — rejection is conditional on DNSSEC + no matching association (PR #845 review)', () => {
		// This SAME detail string is emitted for unsigned zones (where RFC 7671
		// clients treat the RRset as unusable and fall back — nothing breaks) and
		// for multi-record rollover RRsets (one stale association among a matching
		// set breaks nothing). The prose must not claim unconditional breakage.
		for (const hasDnssec of [true, false]) {
			const findings = analyzeTlsaRecords([`3 1 1 ${SHA256_HASH}`], '_443._tcp.example.com', hasDnssec);
			const unverified = findings.find((f) => f.title.startsWith('DANE TLSA configured'));
			expect(unverified).toBeDefined();
			expect(unverified!.detail).not.toMatch(/which breaks DANE-validating clients/i);
			expect(unverified!.detail).toMatch(/DNSSEC-authenticated/);
		}
	});

	it('does not claim verification for multiple well-formed records either', () => {
		const findings = analyzeTlsaRecords([`3 1 1 ${SHA256_HASH}`, `2 0 1 ${SHA256_HASH}`], '_443._tcp.example.com', true);
		const unverified = findings.find((f) => f.title.startsWith('DANE TLSA configured'));
		expect(unverified).toBeDefined();
		expect(unverified!.detail).not.toMatch(/valid tlsa/i);
		expect(unverified!.detail).toMatch(/does not verify/i);
		expect(unverified!.metadata?.certificateMatchVerified).toBe(false);
		expect(unverified!.metadata?.validRecordCount).toBe(2);
	});
});

describe('checkDANEHTTPS — unverified pins do not receive full marks (#841)', () => {
	it('a well-formed DANE-EE pin + DNSSEC scores 95 until its certificate match is verified', async () => {
		const queryDNS: DNSQueryFunction = async (name, type) => {
			if (type === 'TLSA' && name === '_443._tcp.example.com') return [`3 1 1 ${SHA256_HASH}`];
			return [];
		};
		const rawQueryDNS: RawDNSQueryFunction = async () => ({ AD: true, Answer: [] });

		const result = await checkDANEHTTPS('example.com', queryDNS, { rawQueryDNS });

		expect(result.score).toBe(95);
		expect(result.passed).toBe(true);
		expect(result.recordPresent).toBe(true);

		const unverified = result.findings.find((f) => f.title.startsWith('DANE TLSA configured'));
		expect(unverified).toBeDefined();
		expect(unverified!.category).toBe('dane_https');
		expect(unverified!.severity).toBe('low');
		expect(unverified!.detail).not.toMatch(/valid tlsa/i);
		expect(unverified!.detail).toMatch(/does not verify/i);
		expect(unverified!.metadata?.certificateMatchVerified).toBe(false);
	});
});
