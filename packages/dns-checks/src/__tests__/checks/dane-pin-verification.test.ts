// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #841 — DANE TLSA pins are VERIFIED against the certificate the host serves.
 *
 * Before scoring model 1.22.0 the check could only say "present and well-formed", and
 * the scoring was inverted: a stale DANE-EE pin (which breaks every DANE-validating
 * client) scored 100 while deleting it scored 95. With the served certificate in hand
 * (captured by bv-tls-probe, passed in as `ServedCertificate`) the end state is
 * monotone: verified 100 > absent 95 > mismatch 75.
 *
 * The digest vectors come from OpenSSL (see served-certificate.fixture.ts), so a green
 * run proves the comparison against an independent implementation.
 */

import { describe, it, expect } from 'vitest';
import { analyzeTlsaRecords, parseTlsaRecord, verifyTlsaAssociations, DANE_PIN_NOT_ASSESSED_REASONS } from '../../checks/dane-analysis';
import { checkDANEHTTPS } from '../../checks/check-dane-https';
import {
	buildCheckResult,
	computeScanScore,
	findingsIndicateMissingControl,
	getProfileWeights,
	scoreIndicatesMissingControl,
} from '../../scoring';
import type { CheckResult, DNSQueryFunction, RawDNSQueryFunction } from '../../types';
import {
	servedCertificate,
	LEAF_SHA256,
	LEAF_SHA512,
	LEAF_SPKI_SHA256,
	LEAF_SPKI_SHA512,
	LEAF_DER_HEX,
	LEAF_SPKI_DER_HEX,
	STALE_SHA256,
	INTERMEDIATE_SHA256,
	INTERMEDIATE_SHA512,
	INTERMEDIATE_SPKI_SHA256,
	INTERMEDIATE_SPKI_SHA512,
	INTERMEDIATE_DER_HEX,
} from './served-certificate.fixture';

const NAME = '_443._tcp.example.com';

function rec(usage: number, selector: number, matchingType: number, certData: string) {
	return { usage, selector, matchingType, certData };
}

describe('verifyTlsaAssociations — RFC 7671 usage × selector × matching type', () => {
	const cert = servedCertificate();

	it.each([
		// usage 3 DANE-EE and 1 PKIX-EE bind the LEAF
		['3 0 1 leaf cert sha256', rec(3, 0, 1, LEAF_SHA256)],
		['3 0 2 leaf cert sha512', rec(3, 0, 2, LEAF_SHA512)],
		['3 1 1 leaf SPKI sha256 (the recommended form)', rec(3, 1, 1, LEAF_SPKI_SHA256)],
		['3 1 2 leaf SPKI sha512', rec(3, 1, 2, LEAF_SPKI_SHA512)],
		['3 0 0 full leaf DER', rec(3, 0, 0, LEAF_DER_HEX)],
		['3 1 0 full leaf SPKI DER', rec(3, 1, 0, LEAF_SPKI_DER_HEX)],
		['1 1 1 PKIX-EE leaf SPKI sha256', rec(1, 1, 1, LEAF_SPKI_SHA256)],
		['1 0 1 PKIX-EE leaf cert sha256', rec(1, 0, 1, LEAF_SHA256)],
		// usage 2 DANE-TA and 0 PKIX-TA match ANY chain entry
		['2 0 1 DANE-TA intermediate cert sha256', rec(2, 0, 1, INTERMEDIATE_SHA256)],
		['2 0 2 DANE-TA intermediate cert sha512', rec(2, 0, 2, INTERMEDIATE_SHA512)],
		['2 1 1 DANE-TA intermediate SPKI sha256', rec(2, 1, 1, INTERMEDIATE_SPKI_SHA256)],
		['2 1 2 DANE-TA intermediate SPKI sha512', rec(2, 1, 2, INTERMEDIATE_SPKI_SHA512)],
		['2 0 0 DANE-TA intermediate full DER', rec(2, 0, 0, INTERMEDIATE_DER_HEX)],
		['2 1 1 DANE-TA where the TA IS the leaf (RFC 7671 §5.2)', rec(2, 1, 1, LEAF_SPKI_SHA256)],
		['0 0 1 PKIX-TA intermediate cert sha256', rec(0, 0, 1, INTERMEDIATE_SHA256)],
		['0 1 0 PKIX-TA leaf SPKI full DER (TA == EE)', rec(0, 1, 0, LEAF_SPKI_DER_HEX)],
	])('%s → matched', (_label, record) => {
		const v = verifyTlsaAssociations([record], cert);
		expect(v.matched).toEqual([record]);
		expect(v.unmatched).toEqual([]);
		expect(v.unverifiable).toEqual([]);
	});

	it.each([
		['3 1 1 stale SPKI pin (the #841 repro shape)', rec(3, 1, 1, STALE_SHA256)],
		['3 0 1 wrong object: SPKI digest pinned under selector 0', rec(3, 0, 1, LEAF_SPKI_SHA256)],
		['3 1 2 wrong algorithm: sha256 pinned as matching type 2', rec(3, 1, 2, LEAF_SPKI_SHA256)],
		['3 1 1 intermediate SPKI pinned as DANE-EE (EE binds the leaf only)', rec(3, 1, 1, INTERMEDIATE_SPKI_SHA256)],
		['1 0 1 PKIX-EE intermediate cert pinned (EE binds the leaf only)', rec(1, 0, 1, INTERMEDIATE_SHA256)],
		['2 1 1 DANE-TA digest absent from the whole chain', rec(2, 1, 1, STALE_SHA256)],
		['3 0 0 full DER off by one byte', rec(3, 0, 0, LEAF_DER_HEX.slice(0, -2) + '00')],
	])('%s → unmatched', (_label, record) => {
		const v = verifyTlsaAssociations([record], cert);
		expect(v.unmatched).toEqual([record]);
		expect(v.matched).toEqual([]);
		expect(v.unverifiable).toEqual([]);
	});

	it.each([
		['usage 4 (outside 0–3)', rec(4, 1, 1, LEAF_SPKI_SHA256)],
		['selector 2 (outside 0–1)', rec(3, 2, 1, LEAF_SPKI_SHA256)],
		['matching type 3 (outside 0–2)', rec(3, 1, 3, LEAF_SPKI_SHA256)],
		['empty certData', rec(3, 1, 1, '')],
	])('%s → unverifiable, never unmatched', (_label, record) => {
		const v = verifyTlsaAssociations([record], cert);
		expect(v.unverifiable).toEqual([record]);
		expect(v.unmatched).toEqual([]);
	});

	it('a TA selector-1 full-data pin against a non-leaf entry is unverifiable (the contract carries no SPKI DER there)', () => {
		const v = verifyTlsaAssociations([rec(2, 1, 0, INTERMEDIATE_DER_HEX)], cert);
		// The leaf entry IS comparable (leafSpkiDer) and differs; the intermediate is not.
		// A record with an uncomparable member is unverifiable, not a broken pin.
		expect(v.unverifiable).toHaveLength(1);
		expect(v.unmatched).toEqual([]);
	});

	it('probe material a comparison needs but lacks → unverifiable, not unmatched', () => {
		const bare = servedCertificate('example.com', { leafSha512: undefined, chain: [] });
		const v = verifyTlsaAssociations([rec(3, 0, 2, LEAF_SHA512)], bare);
		expect(v.unverifiable).toHaveLength(1);
		expect(v.unmatched).toEqual([]);
	});

	it('chainTruncated: a TA pin matching no RETAINED entry is unverifiable (truncatedChain), a leaf pin is still unmatched', () => {
		const truncated = servedCertificate('example.com', { chainTruncated: true, chainLength: 11 });
		const ta = verifyTlsaAssociations([rec(2, 1, 1, STALE_SHA256), rec(0, 0, 1, STALE_SHA256)], truncated);
		expect(ta.unmatched).toEqual([]);
		expect(ta.unverifiable).toHaveLength(2);
		expect(ta.truncatedChain).toHaveLength(2);
		const ee = verifyTlsaAssociations([rec(3, 1, 1, STALE_SHA256), rec(1, 0, 1, STALE_SHA256)], truncated);
		expect(ee.unmatched).toHaveLength(2);
		expect(ee.truncatedChain).toEqual([]);
		// A TA pin that DOES match a retained entry is still matched.
		expect(verifyTlsaAssociations([rec(2, 0, 1, INTERMEDIATE_SHA256)], truncated).matched).toHaveLength(1);
		// Without truncation the same TA pin is a plain mismatch.
		expect(verifyTlsaAssociations([rec(2, 1, 1, STALE_SHA256)], servedCertificate()).unmatched).toHaveLength(1);
	});

	it('an empty chain falls back to the leaf for TA usages', () => {
		const leafOnly = servedCertificate('example.com', { chain: [] });
		expect(verifyTlsaAssociations([rec(2, 1, 1, LEAF_SPKI_SHA256)], leafOnly).matched).toHaveLength(1);
		expect(verifyTlsaAssociations([rec(2, 1, 1, INTERMEDIATE_SPKI_SHA256)], leafOnly).unmatched).toHaveLength(1);
	});

	it('comparison is case-insensitive and whitespace-tolerant on both sides', () => {
		const shouty = servedCertificate('example.com', { leafSpkiSha256: LEAF_SPKI_SHA256.toUpperCase() });
		const spaced = `${LEAF_SPKI_SHA256.slice(0, 32)} ${LEAF_SPKI_SHA256.slice(32).toUpperCase()}`;
		expect(verifyTlsaAssociations([rec(3, 1, 1, spaced)], shouty).matched).toHaveLength(1);
	});

	it('accepts presentation strings, parsing them; unparseable strings are dropped', () => {
		const v = verifyTlsaAssociations([`3 1 1 ${LEAF_SPKI_SHA256}`, `3 1 1 ${STALE_SHA256}`, 'garbage'], cert);
		expect(v.matched).toEqual([parseTlsaRecord(`3 1 1 ${LEAF_SPKI_SHA256}`)]);
		expect(v.unmatched).toEqual([parseTlsaRecord(`3 1 1 ${STALE_SHA256}`)]);
		expect(v.unverifiable).toEqual([]);
	});
});

describe('analyzeTlsaRecords — verdict ladder with a served certificate', () => {
	const cert = servedCertificate();

	it('a matching association → info, certificateMatchVerified: true, matched digests in metadata', () => {
		const findings = analyzeTlsaRecords([`3 1 1 ${LEAF_SPKI_SHA256}`], NAME, true);
		expect(findings).toHaveLength(1);
		const verified = analyzeTlsaRecords([`3 1 1 ${LEAF_SPKI_SHA256}`], NAME, true, { servedCertificate: cert });
		expect(verified).toHaveLength(1);
		const f = verified[0];
		expect(f.severity).toBe('info');
		expect(f.title).toBe(`DANE TLSA verified against the served certificate for ${NAME}`);
		expect(f.metadata).toMatchObject({
			certificateMatchVerified: true,
			matchedUsage: 3,
			matchedSelector: 1,
			matchedMatchingType: 1,
			matchedCertData: LEAF_SPKI_SHA256,
			matchedAssociations: [`3 1 1 ${LEAF_SPKI_SHA256}`],
			servedLeafSpkiSha256: LEAF_SPKI_SHA256,
			servedLeafSha256: LEAF_SHA256,
			servedHost: 'example.com',
			servedPort: 443,
		});
		expect(f.metadata?.inconclusive).toBeUndefined();
	});

	it('a rollover RRset (one stale + one current) → verified, with the stale member listed as unmatched', () => {
		const [f] = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`, `3 1 1 ${LEAF_SPKI_SHA256}`], NAME, true, { servedCertificate: cert });
		expect(f.severity).toBe('info');
		expect(f.metadata?.certificateMatchVerified).toBe(true);
		expect(f.metadata?.unmatchedAssociations).toEqual([`3 1 1 ${STALE_SHA256}`]);
		expect(f.detail).toMatch(/rollover/i);
	});

	it('no association matches → high "pin does not match", certificateMatchVerified: false, served SPKI + pinned list', () => {
		const [f] = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`], NAME, true, { servedCertificate: cert });
		expect(f.severity).toBe('high');
		expect(f.title).toBe(`DANE TLSA pin does not match the served certificate for ${NAME}`);
		expect(f.metadata).toMatchObject({
			certificateMatchVerified: false,
			servedLeafSpkiSha256: LEAF_SPKI_SHA256,
			pinned: [`3 1 1 ${STALE_SHA256}`],
		});
		expect(f.detail).toMatch(/DNSSEC-authenticated, DANE-validating clients reject the connection/);
		expect(f.detail).toContain(LEAF_SPKI_SHA256);
	});

	it('the mismatch finding is NOT a missing control — it must never arm the critical-gap ceiling', () => {
		const findings = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`, `2 0 1 ${STALE_SHA256}`], NAME, true, { servedCertificate: cert });
		const high = findings.filter((f) => f.severity === 'high');
		expect(high).toHaveLength(1);
		// Both the canonical predicate and the legacy prose predicate must decline.
		expect(findingsIndicateMissingControl(high)).toBe(false);
		expect(scoreIndicatesMissingControl(high)).toBe(false);
		// The words the prose regex keys on are absent from title AND detail.
		const text = `${high[0].title} ${high[0].detail}`;
		expect(text).not.toMatch(/missing|required|not\s+found/i);
		expect(text).not.toMatch(/no\s+[^\r\n]{1,64}\srecord/i);
		expect(high[0].metadata?.missingControl).toBeUndefined();
		// And the category scores 75 (ordinary −25), not 0.
		const result = buildCheckResult(
			'dane_https',
			findings.map((f) => ({ ...f, category: 'dane_https' as const })),
		);
		expect(result.score).toBe(75);
		expect(result.passed).toBe(true);
	});

	it('a zone owner cannot smuggle a regex trigger through the pinned data (subject-data redaction)', () => {
		// `3 1 1 missing` parses: certData = "missing". It matches no digest → high mismatch
		// whose prose interpolates the pin. The predicate must test the prose WITHOUT it.
		for (const token of ['missing', 'required', 'not found', 'no tlsa record']) {
			const findings = analyzeTlsaRecords([`3 1 1 ${token}`], NAME, true, { servedCertificate: cert });
			const high = findings.filter((f) => f.severity === 'high');
			expect(high).toHaveLength(1);
			// parseTlsaRecord joins the data parts without a separator, so a spaced token collapses.
			expect(high[0].detail).toContain(token.replace(/\s+/g, ''));
			expect(scoreIndicatesMissingControl(high)).toBe(false);
			expect(findingsIndicateMissingControl(high)).toBe(false);
			const result = buildCheckResult(
				'dane_https',
				findings.map((f) => ({ ...f, category: 'dane_https' as const })),
			);
			expect(result.score).toBe(75);
		}
	});

	it('chainTruncated + no TA match → info abstention (notAssessedReason chain_truncated), NOT a mismatch, no deduction', () => {
		const truncated = servedCertificate('example.com', { chainTruncated: true, chainLength: 11 });
		const findings = analyzeTlsaRecords([`2 1 1 ${STALE_SHA256}`], NAME, true, { servedCertificate: truncated });
		expect(findings.some((f) => f.severity === 'high')).toBe(false);
		const [f] = findings;
		expect(f.severity).toBe('info');
		expect(f.metadata).toMatchObject({
			certificateMatchVerified: false,
			inconclusive: true,
			notAssessedReason: 'chain_truncated',
			chainTruncated: true,
			chainLength: 11,
		});
		// Not a probe outcome marker — the condition is persistent for the host, so the
		// result must cache normally rather than re-try every scan.
		expect(f.metadata?.certificateProbe).toBeUndefined();
		expect(buildCheckResult('dane_https', [{ ...f, category: 'dane_https' }]).score).toBe(100);
	});

	it('chainTruncated with a stale LEAF pin beside an unverifiable TA pin → abstention (the set may still authenticate)', () => {
		const truncated = servedCertificate('example.com', { chainTruncated: true });
		const findings = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`, `2 1 1 ${STALE_SHA256}`], NAME, true, { servedCertificate: truncated });
		expect(findings.some((f) => f.severity === 'high')).toBe(false);
		expect(findings[0].metadata?.notAssessedReason).toBe('chain_truncated');
		expect(findings[0].metadata?.unmatchedAssociations).toEqual([`3 1 1 ${STALE_SHA256}`]);
	});

	it('chainTruncated with a stale LEAF-only RRset → still a mismatch (truncation cannot hide an end-entity pin)', () => {
		const truncated = servedCertificate('example.com', { chainTruncated: true });
		const [f] = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`], NAME, true, { servedCertificate: truncated });
		expect(f.severity).toBe('high');
	});

	it('a mixed unmatched + unverifiable set falls back to the honest "present, not verified" low (a broken pin is not established)', () => {
		const findings = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`, `2 1 0 ${INTERMEDIATE_DER_HEX}`], NAME, true, {
			servedCertificate: cert,
		});
		// The `2 1 0` record also earns its own "full certificate matching" low; the verdict is the consolidated one.
		expect(findings.some((x) => x.severity === 'high')).toBe(false);
		const f = findings.find((x) => x.title.startsWith('DANE TLSA configured'))!;
		expect(f).toBeDefined();
		expect(f.severity).toBe('low');
		expect(f.title).toBe(`DANE TLSA configured for ${NAME}`);
		expect(f.metadata?.certificateMatchVerified).toBe(false);
		expect(f.metadata?.unverifiableAssociations).toEqual([`2 1 0 ${INTERMEDIATE_DER_HEX}`]);
	});

	it('DNSSEC-absent + mismatch: both the DANE-without-DNSSEC high and the mismatch high fire (additive, not zeroing)', () => {
		const findings = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`], NAME, false, { servedCertificate: cert });
		expect(findings.map((f) => f.title)).toEqual([
			'DANE without DNSSEC',
			`DANE TLSA pin does not match the served certificate for ${NAME}`,
		]);
		const result = buildCheckResult(
			'dane_https',
			findings.map((f) => ({ ...f, category: 'dane_https' as const })),
		);
		expect(result.score).toBe(50);
	});
});

describe('analyzeTlsaRecords — probe outcomes without a certificate', () => {
	it('no probe capability (default) → the 1.18.0 low finding, byte-identical to before', () => {
		const before = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`], NAME, true);
		const explicit = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`], NAME, true, { certificateProbe: 'unavailable' });
		const empty = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`], NAME, true, {});
		expect(explicit).toEqual(before);
		expect(empty).toEqual(before);
		expect(before[0].severity).toBe('low');
		expect(before[0].title).toBe(`DANE TLSA configured for ${NAME}`);
		expect(before[0].metadata).toEqual({ name: NAME, validRecordCount: 1, certificateMatchVerified: false });
	});

	it.each([
		['pending', DANE_PIN_NOT_ASSESSED_REASONS.pending, /pending/],
		['failed', DANE_PIN_NOT_ASSESSED_REASONS.failed, /inconclusive/],
	] as const)('probe %s → info, inconclusive, notAssessedReason, NO deduction', (outcome, reason, titleRe) => {
		const [f] = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`], NAME, true, { certificateProbe: outcome });
		expect(f.severity).toBe('info');
		expect(f.title).toMatch(titleRe);
		expect(f.metadata).toMatchObject({
			certificateMatchVerified: false,
			inconclusive: true,
			notAssessedReason: reason,
			certificateProbe: outcome,
		});
		expect(f.metadata?.missingControl).toBeUndefined();
		const result = buildCheckResult('dane_https', [{ ...f, category: 'dane_https' }]);
		expect(result.score).toBe(100);
	});

	it('a caller-supplied reason token becomes the notAssessedReason', () => {
		const [f] = analyzeTlsaRecords([`3 1 1 ${STALE_SHA256}`], NAME, true, {
			certificateProbe: 'failed',
			certificateProbeReason: 'off_host_redirect',
		});
		expect(f.metadata?.notAssessedReason).toBe('off_host_redirect');
		expect(f.detail).toContain('off host redirect');
	});

	it('a served certificate wins over a stale probe outcome', () => {
		const [f] = analyzeTlsaRecords([`3 1 1 ${LEAF_SPKI_SHA256}`], NAME, true, {
			servedCertificate: servedCertificate(),
			certificateProbe: 'failed',
		});
		expect(f.metadata?.certificateMatchVerified).toBe(true);
	});
});

describe('checkDANEHTTPS — end state verified 100 > absent 95 > mismatch 75', () => {
	function dns(tlsa: string[]): { queryDNS: DNSQueryFunction; rawQueryDNS: RawDNSQueryFunction } {
		return {
			queryDNS: async (name, type) => (type === 'TLSA' && name === NAME ? tlsa : []),
			rawQueryDNS: async () => ({ AD: true, Answer: [] }),
		};
	}

	it('verified pin → 100, passed, not partial', async () => {
		const { queryDNS, rawQueryDNS } = dns([`3 1 1 ${LEAF_SPKI_SHA256}`]);
		const result = await checkDANEHTTPS('example.com', queryDNS, { rawQueryDNS, servedCertificate: servedCertificate() });
		expect(result.score).toBe(100);
		expect(result.passed).toBe(true);
		expect(result.partial).toBeUndefined();
		expect(result.checkStatus).toBeUndefined();
		expect(result.recordPresent).toBe(true);
		expect(result.findings[0].category).toBe('dane_https');
		expect(result.findings[0].metadata?.certificateMatchVerified).toBe(true);
	});

	it('absent TLSA → 95 (unchanged), even with a served certificate in hand', async () => {
		const { queryDNS, rawQueryDNS } = dns([]);
		const result = await checkDANEHTTPS('example.com', queryDNS, { rawQueryDNS, servedCertificate: servedCertificate() });
		expect(result.score).toBe(95);
		expect(result.findings[0].title).toBe('No DANE TLSA for HTTPS');
		expect(result.partial).toBeUndefined();
	});

	it('stale pin → 75, and the category is still scored (passed, no missing control)', async () => {
		const { queryDNS, rawQueryDNS } = dns([`3 1 1 ${STALE_SHA256}`]);
		const result = await checkDANEHTTPS('example.com', queryDNS, { rawQueryDNS, servedCertificate: servedCertificate() });
		expect(result.score).toBe(75);
		expect(result.passed).toBe(true);
		expect(result.partial).toBeUndefined();
		expect(result.findings[0].severity).toBe('high');
	});

	it('no probe capability → 95 with the unverified low (self-host posture, bit-for-bit unchanged)', async () => {
		const { queryDNS, rawQueryDNS } = dns([`3 1 1 ${STALE_SHA256}`]);
		const result = await checkDANEHTTPS('example.com', queryDNS, { rawQueryDNS });
		expect(result.score).toBe(95);
		expect(result.partial).toBeUndefined();
		expect(result.findings[0].severity).toBe('low');
	});

	it.each(['pending', 'failed'] as const)(
		'probe %s → 100, partial: true, checkStatus untouched (category stays completed)',
		async (outcome) => {
			const { queryDNS, rawQueryDNS } = dns([`3 1 1 ${STALE_SHA256}`]);
			const result = await checkDANEHTTPS('example.com', queryDNS, { rawQueryDNS, certificateProbe: outcome });
			expect(result.score).toBe(100);
			expect(result.partial).toBe(true);
			expect(result.checkStatus).toBeUndefined();
			expect(result.findings[0].metadata?.inconclusive).toBe(true);
		},
	);

	it('chain_truncated abstention → 100, NOT partial (persistent condition, caches normally)', async () => {
		const { queryDNS, rawQueryDNS } = dns([`2 1 1 ${STALE_SHA256}`]);
		const result = await checkDANEHTTPS('example.com', queryDNS, {
			rawQueryDNS,
			servedCertificate: servedCertificate('example.com', { chainTruncated: true, chainLength: 9 }),
		});
		expect(result.score).toBe(100);
		expect(result.partial).toBeUndefined();
		expect(result.findings[0].metadata?.notAssessedReason).toBe('chain_truncated');
	});

	it('the lazy resolver is called ONLY when TLSA records exist', async () => {
		let calls = 0;
		const resolve = async () => {
			calls++;
			return { servedCertificate: servedCertificate() };
		};
		const none = dns([]);
		await checkDANEHTTPS('example.com', none.queryDNS, { rawQueryDNS: none.rawQueryDNS, resolveServedCertificate: resolve });
		expect(calls).toBe(0);
		const some = dns([`3 1 1 ${LEAF_SPKI_SHA256}`]);
		const result = await checkDANEHTTPS('example.com', some.queryDNS, { rawQueryDNS: some.rawQueryDNS, resolveServedCertificate: resolve });
		expect(calls).toBe(1);
		expect(result.score).toBe(100);
	});

	it('a throwing resolver is a failed probe (unmeasured, partial), never a verdict', async () => {
		const { queryDNS, rawQueryDNS } = dns([`3 1 1 ${STALE_SHA256}`]);
		const result = await checkDANEHTTPS('example.com', queryDNS, {
			rawQueryDNS,
			resolveServedCertificate: async () => {
				throw new Error('binding exploded');
			},
		});
		expect(result.score).toBe(100);
		expect(result.partial).toBe(true);
		expect(result.findings[0].metadata?.notAssessedReason).toBe(DANE_PIN_NOT_ASSESSED_REASONS.failed);
	});

	it('the critical-gap ceiling does not arm on a mismatch in the web_only profile', async () => {
		const { queryDNS, rawQueryDNS } = dns([`3 1 1 ${STALE_SHA256}`]);
		const dane = await checkDANEHTTPS('example.com', queryDNS, { rawQueryDNS, servedCertificate: servedCertificate() });
		// A clean web-only roster; dane_https is CRITICAL for web_only, so a missing-control
		// reading here would cap the whole scan at 64.
		const clean = (category: CheckResult['category']) =>
			buildCheckResult(category, [{ category, title: 'ok', severity: 'info', detail: 'ok' }], true, true);
		const noMx = buildCheckResult('mx', [{ category: 'mx', title: 'No MX records', severity: 'info', detail: 'web-only' }], false, false);
		const checks: CheckResult[] = [noMx, clean('ssl'), clean('http_security'), clean('dnssec'), clean('caa'), clean('ns'), dane];
		const score = computeScanScore(checks, {
			profile: 'web_only',
			signals: [],
			weights: getProfileWeights('web_only'),
			detectedProvider: null,
		});
		expect(score.categoryScores.dane_https).toBe(75);
		expect(score.overall).not.toBeNull();
		expect(score.overall!).toBeGreaterThan(64);
	});
});
