// SPDX-License-Identifier: BUSL-1.1

/**
 * Output pin for analyzeTlsaRecords / buildVerifiedVerdict / verifyTlsaAssociations (SQ-378, CRAP H1).
 *
 * Snapshots capture the COMPLETE finding list (order, severity, title, detail, metadata) for each
 * TLSA usage / selector / matching type and for every verdict leg (verified, mismatch,
 * unverifiable, truncated chain, unmeasured probe, no probe), so a behaviour-preserving split
 * cannot move a score-relevant field. Snapshots were captured from the pre-split implementation
 * and must not be regenerated to make a refactor pass.
 */

import { describe, it, expect } from 'vitest';
import { analyzeTlsaRecords, verifyTlsaAssociations } from '../src/checks/dane-analysis';
import type { ServedCertificate } from '../src/checks/dane-analysis';

const H1 = 'a'.repeat(64);
const H2 = 'b'.repeat(64);
const H3 = 'c'.repeat(64);
const H512 = 'd'.repeat(128);
const OTHER = 'e'.repeat(64);

const rec = (usage: number, selector: number, mt: number, data: string) => `${usage} ${selector} ${mt} ${data}`;

const leaf = (over: Partial<ServedCertificate> = {}): ServedCertificate => ({
	host: 'mail.example.com',
	port: 25,
	capturedAt: '2026-10-01T00:00:00.000Z',
	leafSha256: H1,
	leafSpkiSha256: H2,
	leafSha512: H512,
	leafSpkiSha512: H512.toUpperCase(),
	leafDer: 'AQID',
	leafSpkiDer: 'BAUG',
	...over,
});

describe('analyzeTlsaRecords output pin', () => {
	describe('per-record validation', () => {
		it('no records yields no findings', () => {
			expect(analyzeTlsaRecords([], 'mail.example.com', true)).toMatchSnapshot();
		});

		it('malformed record', () => {
			expect(analyzeTlsaRecords(['nonsense'], 'mail.example.com', true)).toMatchSnapshot();
		});

		it('invalid usage', () => {
			expect(analyzeTlsaRecords([rec(4, 1, 1, H1)], 'mail.example.com', true)).toMatchSnapshot();
		});

		it('invalid selector', () => {
			expect(analyzeTlsaRecords([rec(3, 2, 1, H1)], 'mail.example.com', true)).toMatchSnapshot();
		});

		it('invalid matching type', () => {
			expect(analyzeTlsaRecords([rec(3, 1, 3, H1)], 'mail.example.com', true)).toMatchSnapshot();
		});

		it('negative-looking fields are malformed-or-invalid exactly as before', () => {
			expect(analyzeTlsaRecords([rec(-1, 1, 1, H1), rec(3, -1, 1, H1), rec(3, 1, -1, H1)], 'mail.example.com', true)).toMatchSnapshot();
		});

		it('wire-format record is parsed', () => {
			expect(analyzeTlsaRecords([`\\# 35 03 01 01 ${H1}`], 'mail.example.com', true)).toMatchSnapshot();
		});

		it('matching type 0 raises the full-certificate advisory', () => {
			expect(analyzeTlsaRecords([rec(3, 0, 0, '010203')], 'mail.example.com', true)).toMatchSnapshot();
		});

		it('mixed malformed + invalid + valid keeps finding order', () => {
			expect(
				analyzeTlsaRecords(['bad', rec(9, 1, 1, H1), rec(3, 7, 1, H1), rec(3, 1, 9, H1), rec(3, 1, 0, '01'), rec(3, 1, 1, H1)], 'mail.example.com', false),
			).toMatchSnapshot();
		});
	});

	describe('DNSSEC dependency (usage 2 and 3)', () => {
		for (const usage of [0, 1, 2, 3]) {
			it(`usage ${usage} with hasDnssec=false`, () => {
				expect(analyzeTlsaRecords([rec(usage, 1, 1, H1)], 'mail.example.com', false)).toMatchSnapshot();
			});

			it(`usage ${usage} with hasDnssec=true`, () => {
				expect(analyzeTlsaRecords([rec(usage, 1, 1, H1)], 'mail.example.com', true)).toMatchSnapshot();
			});
		}

		it('the DANE-without-DNSSEC finding is deduplicated per host across usages', () => {
			expect(analyzeTlsaRecords([rec(3, 1, 1, H1), rec(2, 1, 1, H2), rec(3, 0, 1, H3)], 'mail.example.com', false)).toMatchSnapshot();
		});
	});

	describe('verdict without a served certificate', () => {
		const one = [rec(3, 1, 1, H1)];
		const two = [rec(3, 1, 1, H1), rec(3, 1, 1, H2)];

		it('no verification context: one record', () => {
			expect(analyzeTlsaRecords(one, 'mail.example.com', true)).toMatchSnapshot();
		});

		it('no verification context: several records', () => {
			expect(analyzeTlsaRecords(two, 'mail.example.com', true)).toMatchSnapshot();
		});

		it('probe unavailable', () => {
			expect(analyzeTlsaRecords(one, 'mail.example.com', true, { certificateProbe: 'unavailable' })).toMatchSnapshot();
		});

		it('probe pending without a reason', () => {
			expect(analyzeTlsaRecords(one, 'mail.example.com', true, { certificateProbe: 'pending' })).toMatchSnapshot();
		});

		it('probe failed without a reason', () => {
			expect(analyzeTlsaRecords(one, 'mail.example.com', true, { certificateProbe: 'failed' })).toMatchSnapshot();
		});

		it('probe failed with an explicit reason', () => {
			expect(
				analyzeTlsaRecords(two, 'mail.example.com', true, { certificateProbe: 'failed', certificateProbeReason: 'off_host_redirect' }),
			).toMatchSnapshot();
		});

		it('probe pending with an explicit reason', () => {
			expect(
				analyzeTlsaRecords(one, 'mail.example.com', true, { certificateProbe: 'pending', certificateProbeReason: 'certificate_probe_pending' }),
			).toMatchSnapshot();
		});

		it('servedCertificate null falls through to the probe outcome', () => {
			expect(analyzeTlsaRecords(one, 'mail.example.com', true, { servedCertificate: null, certificateProbe: 'failed' })).toMatchSnapshot();
		});

		it('only malformed records: no verdict at all', () => {
			expect(analyzeTlsaRecords(['bad', rec(9, 1, 1, H1)], 'mail.example.com', true, { certificateProbe: 'failed' })).toMatchSnapshot();
		});
	});

	describe('verified verdict by usage and selector', () => {
		it('DANE-EE (3) selector 1 matching type 1 matches leaf SPKI SHA-256', () => {
			expect(analyzeTlsaRecords([rec(3, 1, 1, H2)], 'mail.example.com', true, { servedCertificate: leaf() })).toMatchSnapshot();
		});

		it('DANE-EE (3) selector 0 matching type 1 matches leaf SHA-256', () => {
			expect(analyzeTlsaRecords([rec(3, 0, 1, H1)], 'mail.example.com', true, { servedCertificate: leaf() })).toMatchSnapshot();
		});

		it('DANE-EE (3) selector 1 matching type 2 matches leaf SPKI SHA-512 (case-insensitive)', () => {
			expect(analyzeTlsaRecords([rec(3, 1, 2, H512)], 'mail.example.com', true, { servedCertificate: leaf() })).toMatchSnapshot();
		});

		it('DANE-EE (3) selector 0 matching type 0 matches the full DER', () => {
			expect(analyzeTlsaRecords([rec(3, 0, 0, '010203')], 'mail.example.com', true, { servedCertificate: leaf() })).toMatchSnapshot();
		});

		it('DANE-EE (3) selector 1 matching type 0 matches the full SPKI DER', () => {
			expect(analyzeTlsaRecords([rec(3, 1, 0, '040506')], 'mail.example.com', true, { servedCertificate: leaf() })).toMatchSnapshot();
		});

		it('PKIX-EE (1) binds the leaf only', () => {
			expect(analyzeTlsaRecords([rec(1, 0, 1, H1)], 'mail.example.com', true, { servedCertificate: leaf() })).toMatchSnapshot();
		});

		it('PKIX-EE (1) does not match a chain member', () => {
			const cert = leaf({ chain: [{ sha256: H1 }, { sha256: H3 }] });
			expect(analyzeTlsaRecords([rec(1, 0, 1, H3)], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});

		it('DANE-TA (2) matches a non-leaf chain member', () => {
			const cert = leaf({ chain: [{ sha256: H1 }, { sha256: H3 }] });
			expect(analyzeTlsaRecords([rec(2, 0, 1, H3)], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});

		it('DANE-TA (2) selector 1 matches a chain member SPKI digest', () => {
			const cert = leaf({ chain: [{ spkiSha256: H1 }, { spkiSha256: H3 }] });
			expect(analyzeTlsaRecords([rec(2, 1, 1, H3)], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});

		it('PKIX-TA (0) matches the leaf when it is also the anchor (RFC 7671 5.2)', () => {
			const cert = leaf({ chain: [{ sha256: H1 }, { sha256: H3 }] });
			expect(analyzeTlsaRecords([rec(0, 0, 1, H1)], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});

		it('PKIX-TA (0) with no chain falls back to the leaf fields', () => {
			expect(analyzeTlsaRecords([rec(0, 0, 1, H1)], 'mail.example.com', true, { servedCertificate: leaf() })).toMatchSnapshot();
		});

		it('chain entry inherits leaf material only at index 0', () => {
			const cert = leaf({ chain: [{}, { sha256: H3 }] });
			expect(analyzeTlsaRecords([rec(2, 0, 1, H1)], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});

		it('served certificate without capturedAt or leaf digests omits those metadata fields', () => {
			const cert: ServedCertificate = { host: 'mail.example.com', port: 443, leafSpkiSha256: H2 };
			expect(analyzeTlsaRecords([rec(3, 1, 1, H2)], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});
	});

	describe('verified verdict: rollover and partial comparisons', () => {
		it('one match plus one unmatched record (rollover, singular wording)', () => {
			expect(
				analyzeTlsaRecords([rec(3, 1, 1, H2), rec(3, 1, 1, OTHER)], 'mail.example.com', true, { servedCertificate: leaf() }),
			).toMatchSnapshot();
		});

		it('one match plus two unmatched records (plural wording)', () => {
			expect(
				analyzeTlsaRecords([rec(3, 1, 1, H2), rec(3, 1, 1, OTHER), rec(3, 0, 1, OTHER)], 'mail.example.com', true, { servedCertificate: leaf() }),
			).toMatchSnapshot();
		});

		it('match plus an unverifiable record lists both buckets', () => {
			const cert = leaf({ leafSpkiSha512: undefined });
			expect(
				analyzeTlsaRecords([rec(3, 1, 1, H2), rec(3, 1, 2, H512), rec(3, 1, 1, OTHER)], 'mail.example.com', true, { servedCertificate: cert }),
			).toMatchSnapshot();
		});

		it('multiple matches report the first as the match and count the rest as matched', () => {
			expect(
				analyzeTlsaRecords([rec(3, 1, 1, H2), rec(3, 0, 1, H1)], 'mail.example.com', true, { servedCertificate: leaf() }),
			).toMatchSnapshot();
		});
	});

	describe('mismatch verdict (high, measured defect)', () => {
		it('single unmatched association', () => {
			expect(analyzeTlsaRecords([rec(3, 1, 1, OTHER)], 'mail.example.com', true, { servedCertificate: leaf() })).toMatchSnapshot();
		});

		it('several unmatched associations', () => {
			expect(
				analyzeTlsaRecords([rec(3, 1, 1, OTHER), rec(1, 0, 1, H3), rec(3, 1, 2, 'f'.repeat(128))], 'mail.example.com', true, { servedCertificate: leaf() }),
			).toMatchSnapshot();
		});

		it('mismatch when the served cert has no capturedAt or digests ("unavailable" wording)', () => {
			const cert: ServedCertificate = { host: 'mail.example.com', port: 25, leafSpkiSha256: H2, leafSha256: undefined };
			expect(analyzeTlsaRecords([rec(3, 1, 1, OTHER)], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});

		it('subject-term smuggling in the pinned data stays declared as subject data', () => {
			expect(
				analyzeTlsaRecords([rec(3, 1, 1, 'missing')], 'mail.example.com', true, { servedCertificate: leaf() }),
			).toMatchSnapshot();
		});

		it('DANE-TA mismatch across every retained chain entry', () => {
			const cert = leaf({ chain: [{ sha256: H1 }, { sha256: H3 }] });
			expect(analyzeTlsaRecords([rec(2, 0, 1, OTHER)], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});
	});

	describe('unverifiable verdict (falls back to present-not-verified)', () => {
		it('probe omitted the digest the record needs', () => {
			const cert = leaf({ leafSpkiSha256: undefined });
			expect(analyzeTlsaRecords([rec(3, 1, 1, H2)], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});

		it('full-data pin with undecodable base64 is uncomparable', () => {
			const cert = leaf({ leafDer: '***not base64***' });
			expect(analyzeTlsaRecords([rec(3, 0, 0, '010203')], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});

		it('full-data pin with no DER at all is uncomparable', () => {
			const cert = leaf({ leafDer: undefined });
			expect(analyzeTlsaRecords([rec(3, 0, 0, '010203')], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});

		it('placeholder pinned data compares as a mismatch', () => {
			expect(analyzeTlsaRecords(['3 1 1 -'], 'mail.example.com', true, { servedCertificate: leaf() })).toMatchSnapshot();
		});

		it('one uncomparable chain member withholds the mismatch verdict for a trust anchor', () => {
			const cert = leaf({ chain: [{ sha256: H1 }, {}] });
			expect(analyzeTlsaRecords([rec(2, 0, 1, OTHER)], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});

		it('unverifiable plus unmatched keeps both lists on the fallback finding', () => {
			const cert = leaf({ leafSpkiSha512: undefined });
			expect(
				analyzeTlsaRecords([rec(3, 1, 2, H512), rec(3, 1, 1, OTHER)], 'mail.example.com', true, { servedCertificate: cert }),
			).toMatchSnapshot();
		});
	});

	describe('truncated chain', () => {
		const truncated = (over: Partial<ServedCertificate> = {}) =>
			leaf({ chain: [{ sha256: H1 }, { sha256: H3 }], chainTruncated: true, chainLength: 9, ...over });

		it('trust-anchor pin matching no retained entry is withheld, with chainLength', () => {
			expect(analyzeTlsaRecords([rec(2, 0, 1, OTHER)], 'mail.example.com', true, { servedCertificate: truncated() })).toMatchSnapshot();
		});

		it('truncation without a reported chain length', () => {
			expect(
				analyzeTlsaRecords([rec(0, 0, 1, OTHER)], 'mail.example.com', true, { servedCertificate: truncated({ chainLength: undefined }) }),
			).toMatchSnapshot();
		});

		it('truncated chain plus an unmatched end-entity pin lists the unmatched association', () => {
			expect(
				analyzeTlsaRecords([rec(2, 0, 1, OTHER), rec(3, 1, 1, OTHER)], 'mail.example.com', true, { servedCertificate: truncated() }),
			).toMatchSnapshot();
		});

		it('a trust-anchor match inside the retained entries still verifies', () => {
			expect(analyzeTlsaRecords([rec(2, 0, 1, H3)], 'mail.example.com', true, { servedCertificate: truncated() })).toMatchSnapshot();
		});

		it('truncation does not turn an end-entity mismatch into a withheld verdict', () => {
			expect(analyzeTlsaRecords([rec(3, 1, 1, OTHER)], 'mail.example.com', true, { servedCertificate: truncated() })).toMatchSnapshot();
		});

		it('truncated plus an uncomparable end-entity pin takes the truncated leg', () => {
			const cert = truncated({ leafSpkiSha256: undefined });
			expect(analyzeTlsaRecords([rec(2, 0, 1, OTHER), rec(3, 1, 1, H2)], 'mail.example.com', true, { servedCertificate: cert })).toMatchSnapshot();
		});
	});

	it('a served certificate outranks a pending probe outcome', () => {
		expect(
			analyzeTlsaRecords([rec(3, 1, 1, H2)], 'mail.example.com', true, { servedCertificate: leaf(), certificateProbe: 'pending' }),
		).toMatchSnapshot();
	});
});

describe('verifyTlsaAssociations output pin', () => {
	it('classifies matched, unmatched and unverifiable, dropping unparseable strings', () => {
		const cert = leaf({ leafSpkiSha512: undefined });
		expect(verifyTlsaAssociations([rec(3, 1, 1, H2), rec(3, 1, 1, OTHER), rec(3, 1, 2, H512), 'nonsense'], cert)).toMatchSnapshot();
	});

	it('usage, selector or matching type outside the known table is unverifiable', () => {
		expect(
			verifyTlsaAssociations(
				[
					{ usage: 7, selector: 1, matchingType: 1, certData: H1 },
					{ usage: 3, selector: 5, matchingType: 1, certData: H1 },
					{ usage: 3, selector: 1, matchingType: 9, certData: H1 },
				],
				leaf(),
			),
		).toMatchSnapshot();
	});

	it('truncated-chain bucket only collects trust-anchor usages', () => {
		const cert = leaf({ chain: [{ sha256: H1 }], chainTruncated: true });
		expect(verifyTlsaAssociations([rec(0, 0, 1, OTHER), rec(2, 0, 1, OTHER), rec(1, 0, 1, OTHER), rec(3, 0, 1, OTHER)], cert)).toMatchSnapshot();
	});

	it('whitespace and case in pinned data are canonicalised', () => {
		const cert = leaf({ leafSha256: H1.toUpperCase() });
		expect(verifyTlsaAssociations([{ usage: 3, selector: 0, matchingType: 1, certData: ` ${H1.slice(0, 10)} ${H1.slice(10)} ` }], cert)).toMatchSnapshot();
	});

	it('accepts pre-parsed records', () => {
		expect(verifyTlsaAssociations([{ usage: 3, selector: 1, matchingType: 1, certData: H2 }], leaf())).toMatchSnapshot();
	});

	it('empty pinned data is uncomparable (unverifiable), never unmatched', () => {
		expect(verifyTlsaAssociations([{ usage: 3, selector: 1, matchingType: 1, certData: '' }], leaf())).toMatchSnapshot();
	});
});
