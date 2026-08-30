// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #841 — the DANE info finding claimed "Valid TLSA record configured" for any
 * syntactically well-formed TLSA record, without ever comparing the pinned data to
 * the certificate the host actually serves. A stale DANE-EE pin (which actively
 * breaks every DANE-validating client, and is DNSSEC-enforced) read as a pass.
 *
 * Full pin verification needs the live leaf/SPKI, which neither this runtime-agnostic
 * package nor the Workers host can obtain today (fetch() exposes no peer certificate;
 * bv-tls-probe returns TLS-version data only; CT tells you what a CA published, not
 * what a server serves). Until a probe extension lands, the finding must be HONEST:
 * state presence + syntactic validity, state that the certificate match was NOT
 * verified, and carry machine-readable metadata saying so.
 *
 * Pinned here:
 *  1. The info finding never uses the word "Valid" for an unverified pin.
 *  2. The detail states the certificate match was not verified.
 *  3. metadata.certificateMatchVerified === false (machine-readable marker).
 *  4. No scoring change: severity stays info; a well-formed TLSA + DNSSEC still
 *     scores 100 with recordPresent true (weight changes are operator-gated).
 *  5. The load-bearing title "DANE TLSA configured for <name>" is unchanged —
 *     maturity staging regex-matches it.
 */

import { describe, it, expect } from 'vitest';
import { analyzeTlsaRecords } from '../../checks/dane-analysis';
import { checkDANEHTTPS } from '../../checks/check-dane-https';
import type { DNSQueryFunction, RawDNSQueryFunction } from '../../types';

const SHA256_HASH = '0000000000000000000000000000000000000000000000000000000000000001';

describe('analyzeTlsaRecords — honest labeling of unverified pins (#841)', () => {
	it('does not claim "Valid" for a single well-formed record it never verified', () => {
		const findings = analyzeTlsaRecords([`3 1 1 ${SHA256_HASH}`], '_443._tcp.example.com', true);
		const info = findings.find((f) => f.severity === 'info');
		expect(info).toBeDefined();
		expect(info!.title).toBe('DANE TLSA configured for _443._tcp.example.com');
		expect(info!.detail).not.toMatch(/valid tlsa/i);
		expect(info!.detail).toMatch(/does not verify/i);
		expect(info!.detail).toMatch(/well-formed/i);
		expect(info!.metadata?.certificateMatchVerified).toBe(false);
	});

	it('does not claim verification for multiple well-formed records either', () => {
		const findings = analyzeTlsaRecords([`3 1 1 ${SHA256_HASH}`, `2 0 1 ${SHA256_HASH}`], '_443._tcp.example.com', true);
		const info = findings.find((f) => f.severity === 'info');
		expect(info).toBeDefined();
		expect(info!.detail).not.toMatch(/valid tlsa/i);
		expect(info!.detail).toMatch(/does not verify/i);
		expect(info!.metadata?.certificateMatchVerified).toBe(false);
		expect(info!.metadata?.validRecordCount).toBe(2);
	});
});

describe('checkDANEHTTPS — no scoring change from the relabel (#841)', () => {
	it('a well-formed DANE-EE pin + DNSSEC still scores 100, but the finding is honest', async () => {
		const queryDNS: DNSQueryFunction = async (name, type) => {
			if (type === 'TLSA' && name === '_443._tcp.example.com') return [`3 1 1 ${SHA256_HASH}`];
			return [];
		};
		const rawQueryDNS: RawDNSQueryFunction = async () => ({ AD: true, Answer: [] });

		const result = await checkDANEHTTPS('example.com', queryDNS, { rawQueryDNS });

		expect(result.score).toBe(100);
		expect(result.passed).toBe(true);
		expect(result.recordPresent).toBe(true);

		const info = result.findings.find((f) => f.severity === 'info');
		expect(info).toBeDefined();
		expect(info!.category).toBe('dane_https');
		expect(info!.detail).not.toMatch(/valid tlsa/i);
		expect(info!.detail).toMatch(/does not verify/i);
		expect(info!.metadata?.certificateMatchVerified).toBe(false);
	});
});
