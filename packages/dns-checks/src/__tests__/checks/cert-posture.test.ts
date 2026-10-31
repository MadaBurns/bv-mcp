// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { checkCertPosture } from '../../checks/check-cert-posture';
import { effectiveCaaIssuers } from '../../checks/caa-analysis';
import { identifyIssuingCa, parseIssuerDn } from '../../checks/cert-posture-analysis';
import { NON_SCORING_CATEGORIES } from '../../types';
import type { CertMetadata } from '../../cert/cert-metadata';
import type { CheckResult, DNSQueryFunction, Finding } from '../../types';
import type { ServedCertificate } from '../../checks/dane-analysis';

const DAY = 86400;
const NOW = 1_800_000_000; // fixed clock, epoch seconds

const LE_ISSUER = "C=US, O=Let's Encrypt, CN=R11";

function makeCert(overrides: Partial<CertMetadata> = {}): CertMetadata {
	return {
		domain: 'example.com',
		issuer: LE_ISSUER,
		notBefore: NOW - 30 * DAY,
		notAfter: NOW + 60 * DAY,
		sans: ['example.com'],
		serial: 'abc',
		source: 'ct',
		keyType: 'ec',
		keyBits: 256,
		sigAlg: 'ecdsa-with-SHA384',
		...overrides,
	};
}

/** Resolver double: CAA answers keyed by owner name; anything else is NOERROR/empty. */
function caaResolver(zones: Record<string, string[]>, rcodes: Record<string, number> = {}): DNSQueryFunction {
	const lookup = async (name: string) => ({ records: zones[name] ?? [], rcode: rcodes[name] ?? 0 });
	const fn = (async (name: string) => (await lookup(name)).records) as DNSQueryFunction;
	fn.withRcode = lookup;
	return fn;
}

const NO_CAA = caaResolver({});

function byTitle(result: CheckResult, fragment: string): Finding {
	const found = result.findings.find((f) => f.title.includes(fragment));
	if (!found) throw new Error(`no finding titled "${fragment}" in ${result.findings.map((f) => f.title).join(' | ')}`);
	return found;
}

async function run(cert: CertMetadata | null, queryDNS: DNSQueryFunction = NO_CAA, extra: { issuerDn?: string | null } = {}) {
	return checkCertPosture('example.com', queryDNS, { certificate: cert, nowSeconds: NOW, ...extra });
}

describe('checkCertPosture — expiry bands', () => {
	it.each([
		['expired', -3 * DAY, 'high', 'Certificate has expired'],
		['critical', 3 * DAY, 'high', 'within 7 days'],
		['warning', 20 * DAY, 'medium', 'within 30 days'],
		['ok', 90 * DAY, 'info', 'expiry is healthy'],
	])('%s → %s', async (band, offset, severity, title) => {
		const result = await run(makeCert({ notAfter: NOW + offset, notBefore: NOW + offset - 90 * DAY }));
		const finding = byTitle(result, title);
		expect(finding.severity).toBe(severity);
		expect(finding.metadata?.expiryBand).toBe(band);
	});

	it('a missing notAfter is not-assessed, never an ok expiry', async () => {
		const result = await run(makeCert({ notAfter: null }));
		const finding = byTitle(result, 'expiry not assessed');
		expect(finding.severity).toBe('info');
		expect(finding.metadata).toMatchObject({ notAssessed: true, expiryBand: 'unknown' });
		expect(result.findings.some((f) => f.metadata?.expiryBand === 'ok')).toBe(false);
	});
});

describe('checkCertPosture — key strength', () => {
	it.each([
		['RSA 1024', { keyType: 'rsa' as const, keyBits: 1024 }],
		['EC 192', { keyType: 'ec' as const, keyBits: 192 }],
	])('%s is a weak key (high)', async (_label, key) => {
		const finding = byTitle(await run(makeCert(key)), 'weak key or signature');
		expect(finding.severity).toBe('high');
		expect(finding.metadata?.keyStrengthBand).toBe('weak');
	});

	it('a SHA-1 signature is weak even with a healthy key size', async () => {
		const finding = byTitle(
			await run(makeCert({ keyType: 'rsa', keyBits: 2048, sigAlg: 'sha1WithRSAEncryption' })),
			'weak key or signature',
		);
		expect(finding.severity).toBe('high');
	});

	it.each([
		['RSA 3072', { keyType: 'rsa' as const, keyBits: 3072 }, 'strong'],
		['EC 256', { keyType: 'ec' as const, keyBits: 256 }, 'strong'],
		['RSA 2048', { keyType: 'rsa' as const, keyBits: 2048 }, 'acceptable'],
	])('%s is %s (info)', async (_label, key, band) => {
		const finding = byTitle(await run(makeCert(key)), 'key strength is');
		expect(finding.severity).toBe('info');
		expect(finding.metadata?.keyStrengthBand).toBe(band);
	});

	it.each([
		['no key material at all', { keyType: undefined, keyBits: undefined, sigAlg: undefined }],
		['an unknown key type with a size', { keyType: 'unknown' as const, keyBits: 4096, sigAlg: null }],
	])('%s is not-assessed, not strong and not weak', async (_label, key) => {
		const finding = byTitle(await run(makeCert(key)), 'key strength not assessed');
		expect(finding.severity).toBe('info');
		expect(finding.metadata).toMatchObject({ notAssessed: true, keyStrengthBand: 'unknown' });
	});
});

describe('checkCertPosture — validity window', () => {
	it('399 days is medium', async () => {
		const finding = byTitle(await run(makeCert({ notBefore: NOW - 100 * DAY, notAfter: NOW - 100 * DAY + 399 * DAY })), 'exceeds 398 days');
		expect(finding.severity).toBe('medium');
		expect(finding.metadata?.validityDays).toBe(399);
	});

	it('398 days is within limits (boundary)', async () => {
		const finding = byTitle(await run(makeCert({ notBefore: NOW - 100 * DAY, notAfter: NOW - 100 * DAY + 398 * DAY })), 'within limits');
		expect(finding.severity).toBe('info');
	});

	it('a missing notBefore is not-assessed', async () => {
		const finding = byTitle(await run(makeCert({ notBefore: null })), 'validity window not assessed');
		expect(finding.metadata?.notAssessed).toBe(true);
	});
});

describe('checkCertPosture — CAA allowed CA vs actual issuer', () => {
	it('issuer in the allowed set → info "CAA honoured"', async () => {
		const result = await run(makeCert(), caaResolver({ 'example.com': ['0 issue "letsencrypt.org"'] }));
		const finding = byTitle(result, 'CAA honoured');
		expect(finding.severity).toBe('info');
		expect(finding.metadata).toMatchObject({ caaOutcome: 'honoured', issuingCa: 'letsencrypt' });
	});

	it('RFC 8657 parameters on the grant do not hide the issuer', async () => {
		const result = await run(makeCert(), caaResolver({ 'example.com': ['0 issue "letsencrypt.org; accounturi=https://acme/x"'] }));
		expect(byTitle(result, 'CAA honoured').metadata?.caaOutcome).toBe('honoured');
	});

	it('a known CA outside the allowed set → high "does not authorise"', async () => {
		const result = await run(makeCert(), caaResolver({ 'example.com': ['0 issue "digicert.com"'] }));
		const finding = byTitle(result, 'does not authorise');
		expect(finding.severity).toBe('high');
		expect(finding.metadata).toMatchObject({ caaOutcome: 'unauthorised', issuingCa: 'letsencrypt', allowedIssuers: ['digicert.com'] });
	});

	it('an unmapped issuer → not-assessed naming the raw issuer, never a mismatch', async () => {
		const issuer = 'C=XX, O=Acme Private PKI, CN=Acme Issuing CA 7';
		const result = await run(makeCert({ issuer }), caaResolver({ 'example.com': ['0 issue "digicert.com"'] }));
		const finding = byTitle(result, 'CAA policy vs issuer not assessed');
		expect(finding.severity).toBe('info');
		expect(finding.detail).toContain('Acme Private PKI');
		expect(finding.metadata).toMatchObject({ notAssessed: true, caaOutcome: 'unmapped', rawIssuer: issuer });
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('no CAA anywhere → info, nothing to compare', async () => {
		const finding = byTitle(await run(makeCert()), 'nothing to compare');
		expect(finding.severity).toBe('info');
		expect(finding.metadata?.caaOutcome).toBe('absent');
	});

	it('issue ";" with a logged certificate → high', async () => {
		const finding = byTitle(await run(makeCert(), caaResolver({ 'example.com': ['0 issue ";"'] })), 'forbids all issuance');
		expect(finding.severity).toBe('high');
		expect(finding.metadata?.caaOutcome).toBe('no-issuance');
	});

	it('CAA with only iodef/issuewild does not restrict issuance', async () => {
		const result = await run(
			makeCert(),
			caaResolver({ 'example.com': ['0 iodef "mailto:sec@example.com"', '0 issuewild "digicert.com"'] }),
		);
		expect(byTitle(result, 'does not restrict issuance').metadata?.caaOutcome).toBe('unrestricted');
	});

	it('the RFC 8659 climb applies a parent policy to a subdomain', async () => {
		const result = await checkCertPosture('www.example.com', caaResolver({ 'example.com': ['0 issue "digicert.com"'] }), {
			certificate: makeCert({ domain: 'www.example.com' }),
			nowSeconds: NOW,
		});
		expect(byTitle(result, 'does not authorise').metadata?.caaFoundAt).toBe('example.com');
	});

	it('a SERVFAIL on the CAA lookup is not-assessed, never "absent" or "honoured"', async () => {
		const result = await run(makeCert(), caaResolver({}, { 'example.com': 2 }));
		const finding = byTitle(result, 'CAA policy vs issuer not assessed');
		expect(finding.metadata?.caaOutcome).toBe('inconclusive');
		expect(result.findings.some((f) => f.metadata?.caaOutcome === 'absent')).toBe(false);
	});

	it('a throwing resolver degrades only the CAA comparison; cert findings still stand', async () => {
		const thrower = (async () => {
			throw new Error('resolver down');
		}) as DNSQueryFunction;
		const result = await run(makeCert({ notAfter: NOW + 3 * DAY, notBefore: NOW - 87 * DAY }), thrower);
		expect(byTitle(result, 'CAA policy vs issuer not assessed').metadata?.caaOutcome).toBe('inconclusive');
		expect(byTitle(result, 'within 7 days').severity).toBe('high');
	});

	it('an explicit issuerDn overrides certificate.issuer', async () => {
		const result = await run(makeCert({ issuer: null }), caaResolver({ 'example.com': ['0 issue "pki.goog"'] }), {
			issuerDn: 'C=US, O=Google Trust Services, CN=WR2',
		});
		expect(byTitle(result, 'CAA honoured').metadata?.issuingCa).toBe('google-trust-services');
	});
});

describe('checkCertPosture — caveat, abstention, non-scoring', () => {
	it('every finding carries the CT caveat', async () => {
		const result = await run(makeCert(), caaResolver({ 'example.com': ['0 issue "digicert.com"'] }));
		expect(result.findings.length).toBeGreaterThanOrEqual(4);
		for (const finding of result.findings) {
			expect(finding.detail).toContain('Certificate Transparency logs (what was issued), not the certificate currently served');
			expect(finding.metadata?.certSource).toBe('ct');
		}
	});

	it('a live-sourced certificate gets the live caveat, not the CT one', async () => {
		const result = await run(makeCert({ source: 'live' }));
		// DANE findings compare CT-derived certificates whatever the posture certificate's source, so they keep the CT caveat.
		for (const finding of result.findings.filter((f) => !f.title.startsWith('DANE'))) {
			expect(finding.detail).toContain('live TLS handshake');
			expect(finding.detail).not.toContain('Certificate Transparency logs');
		}
	});

	it('a null certificate abstains with the not-assessed shape (never a pass)', async () => {
		const result = await run(null);
		expect(result).toMatchObject({ category: 'cert_posture', checkStatus: 'error', score: 0, passed: false, partial: true });
		expect(result.findings[0].metadata?.notAssessed).toBe(true);
	});

	it('a missing options object abstains the same way', async () => {
		const result = await checkCertPosture('example.com', NO_CAA);
		expect(result).toMatchObject({ checkStatus: 'error', score: 0, passed: false, partial: true });
	});

	it('is registered as a NON-SCORING category', () => {
		expect(NON_SCORING_CATEGORIES.has('cert_posture')).toBe(true);
	});
});

describe('checkCertPosture — healthy fixture (positive control)', () => {
	it('a modern, CAA-honoured, short-lived certificate yields only info findings', async () => {
		const result = await run(makeCert(), caaResolver({ 'example.com': ['0 issue "letsencrypt.org"', '0 iodef "mailto:sec@example.com"'] }));
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.map((f) => f.severity)).toEqual(['info', 'info', 'info', 'info', 'info']);
		expect(result.findings.some((f) => f.metadata?.notAssessed === true)).toBe(false);
		expect(result.findings.map((f) => f.title)).toEqual([
			'Certificate expiry is healthy',
			'Certificate key strength is strong',
			'Certificate validity window is within limits',
			'CAA honoured by the issuing CA',
			'DANE vs logged certificate: no TLSA record, nothing to compare',
		]);
	});

	it('the same fixture turns high when ONLY the CAA policy is changed (the discriminating variable)', async () => {
		const healthy = await run(makeCert(), caaResolver({ 'example.com': ['0 issue "letsencrypt.org"'] }));
		const tightened = await run(makeCert(), caaResolver({ 'example.com': ['0 issue "sectigo.com"'] }));
		expect(healthy.findings.some((f) => f.severity === 'high')).toBe(false);
		expect(tightened.findings.some((f) => f.severity === 'high')).toBe(true);
	});
});

describe('identifyIssuingCa / parseIssuerDn', () => {
	it.each([
		["C=US, O=Let's Encrypt, CN=R3", 'letsencrypt'],
		["C=US, O=Let's Encrypt, CN=E6", 'letsencrypt'],
		['C=US, O=Google Trust Services, CN=WE1', 'google-trust-services'],
		['C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1', 'digicert'],
		['C=GB, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA', 'sectigo'],
		['C=AT, O=ZeroSSL, CN=ZeroSSL RSA Domain Secure Site CA', 'zerossl'],
		['C=BE, O=GlobalSign nv-sa, CN=GlobalSign Atlas R3 DV TLS CA 2024 Q1', 'globalsign'],
		['C=US, O=Amazon, CN=Amazon RSA 2048 M02', 'amazon'],
		['C=US, O=SSL Corp, CN=SSL.com TLS RSA CA', 'ssl-com'],
		['CN=SSL.com RSA SSL subCA', 'ssl-com'],
		['C=US, O=Entrust, Inc., CN=Entrust OV TLS Issuing RSA CA 1', 'entrust'],
		['C=NO, O=Buypass AS-983163327, CN=Buypass Class 2 CA 5', 'buypass'],
		['C=US, O=GoDaddy.com, Inc., CN=Go Daddy Secure Certificate Authority - G2', 'godaddy'],
		["Let's Encrypt R3", 'letsencrypt'],
	])('%s → %s', (issuer, id) => {
		expect(identifyIssuingCa(issuer)?.id).toBe(id);
	});

	it.each([[null], [''], ['C=XX, O=Acme Private PKI, CN=Acme Issuing CA 7'], ['CN=Not SSL.com Issuing CA'], ['garbage']])(
		'%s → null (unknown, never a guess)',
		(issuer) => {
			expect(identifyIssuingCa(issuer)).toBeNull();
		},
	);

	it('parses O and CN separately and survives a hostile DN without throwing', () => {
		expect(parseIssuerDn('C=US, O=Foo Inc, CN=Bar')).toEqual({ org: 'Foo Inc', cn: 'Bar' });
		expect(parseIssuerDn(`${'O='.repeat(5000)}x`)).toBeTruthy();
	});
});

describe('effectiveCaaIssuers', () => {
	it('stops at the nearest name that publishes any CAA record', async () => {
		const caa = await effectiveCaaIssuers(
			'a.b.example.com',
			caaResolver({ 'b.example.com': ['0 issue "digicert.com"'], 'example.com': ['0 issue "letsencrypt.org"'] }),
		);
		expect(caa).toMatchObject({ foundAt: 'b.example.com', issuers: ['digicert.com'], inconclusive: false });
	});

	it('never queries a bare TLD', async () => {
		const seen: string[] = [];
		const resolver = (async (name: string) => {
			seen.push(name);
			return [];
		}) as DNSQueryFunction;
		await effectiveCaaIssuers('www.example.com', resolver);
		expect(seen).toEqual(['www.example.com', 'example.com']);
	});

	it('an unreadable name BELOW the governing RRset makes the answer inconclusive', async () => {
		const caa = await effectiveCaaIssuers(
			'www.example.com',
			caaResolver({ 'example.com': ['0 issue "digicert.com"'] }, { 'www.example.com': 2 }),
		);
		expect(caa).toMatchObject({ foundAt: 'example.com', inconclusive: true });
	});

	it('caps the retained issuer set and says so', async () => {
		const records = Array.from({ length: 80 }, (_, i) => `0 issue "ca${i}.example"`);
		const caa = await effectiveCaaIssuers('example.com', caaResolver({ 'example.com': records }));
		expect(caa.issuers).toHaveLength(32);
		expect(caa.issuersTruncated).toBe(true);
	});
});

describe('checkCertPosture — DANE TLSA vs logged certificates', () => {
	const SPKI_A = 'a'.repeat(64);
	const SPKI_B = 'b'.repeat(64);
	const SHA_CERT = 'c'.repeat(64);
	const TLSA_APEX = '_443._tcp.example.com';
	const TLSA_WWW = '_443._tcp.www.example.com';

	/** A CT-derived certificate as the host would inject it: digests only, no live probe. */
	function ctCert(overrides: Partial<ServedCertificate> = {}): ServedCertificate {
		return { host: 'example.com', port: 443, leafSpkiSha256: SPKI_A, leafSha256: SHA_CERT, ...overrides };
	}

	function runDane(zones: Record<string, string[]>, ctCertificates?: ServedCertificate[], certificate: CertMetadata | null = makeCert()) {
		return checkCertPosture('example.com', caaResolver(zones), { certificate, nowSeconds: NOW, ctCertificates });
	}

	function dane(result: CheckResult): Finding[] {
		return result.findings.filter((f) => f.title.startsWith('DANE vs logged certificate'));
	}

	it('a DANE-EE SPKI-sha256 pin that equals a logged certificate is an info pass', async () => {
		const findings = dane(await runDane({ [TLSA_APEX]: [`3 1 1 ${SPKI_A}`] }, [ctCert()]));
		expect(findings).toHaveLength(1);
		expect(findings[0]).toMatchObject({ severity: 'info', title: 'DANE vs logged certificate: TLSA matches a logged certificate' });
		expect(findings[0].metadata).toMatchObject({ daneOutcome: 'matched', tlsaName: TLSA_APEX, loggedCertificateCount: 1 });
		expect(findings[0].metadata?.notAssessed).toBeUndefined();
	});

	it('a match on ANY logged certificate suffices (RFC 7671), and the www owner name is queried too', async () => {
		const findings = dane(await runDane({ [TLSA_WWW]: [`3 1 1 ${SPKI_B}`] }, [ctCert(), ctCert({ leafSpkiSha256: SPKI_B })]));
		expect(findings.map((f) => f.metadata?.tlsaName)).toEqual([TLSA_WWW]);
		expect(findings[0].metadata?.daneOutcome).toBe('matched');
	});

	it('a pin that matches NO logged certificate is medium and says the served certificate may be private', async () => {
		const findings = dane(await runDane({ [TLSA_APEX]: [`3 1 1 ${SPKI_B}`] }, [ctCert()]));
		expect(findings).toHaveLength(1);
		expect(findings[0]).toMatchObject({ severity: 'medium', title: 'DANE vs logged certificate: TLSA matches no logged certificate' });
		expect(findings[0].metadata?.daneOutcome).toBe('mismatch');
		expect(findings[0].detail).toContain('may be private or not logged');
		expect(findings[0].detail).toContain('check the live endpoint');
	});

	it('the same TLSA turns from pass to medium when ONLY the logged certificate changes (discriminating variable)', async () => {
		const zones = { [TLSA_APEX]: [`3 1 1 ${SPKI_A}`] };
		const matching = dane(await runDane(zones, [ctCert()]));
		const other = dane(await runDane(zones, [ctCert({ leafSpkiSha256: SPKI_B })]));
		expect(matching[0].severity).toBe('info');
		expect(other[0].severity).toBe('medium');
	});

	it.each([
		['undefined', undefined],
		['an empty list', []],
	])('TLSA present but ctCertificates is %s is a distinct not-assessed, never a pass or a mismatch', async (_label, certs) => {
		const findings = dane(await runDane({ [TLSA_APEX]: [`3 1 1 ${SPKI_A}`] }, certs));
		expect(findings).toHaveLength(1);
		expect(findings[0]).toMatchObject({ severity: 'info', title: 'DANE vs logged certificate not assessed' });
		expect(findings[0].metadata).toMatchObject({ notAssessed: true, daneOutcome: 'no-certificate-supplied' });
	});

	it('no TLSA anywhere is one info "nothing to compare"', async () => {
		const findings = dane(await runDane({}, [ctCert()]));
		expect(findings).toHaveLength(1);
		expect(findings[0]).toMatchObject({ severity: 'info', title: 'DANE vs logged certificate: no TLSA record, nothing to compare' });
		expect(findings[0].metadata?.daneOutcome).toBe('no-tlsa');
	});

	it('a DANE-TA (usage 2) pin that misses a lone leaf is not-assessed for that record, not a mismatch', async () => {
		const findings = dane(await runDane({ [TLSA_APEX]: [`2 1 1 ${SPKI_B}`] }, [ctCert()]));
		expect(findings[0].metadata).toMatchObject({ notAssessed: true, daneOutcome: 'not-comparable' });
		expect(findings[0].severity).toBe('info');
	});

	it('a DANE-TA pin that misses every member of a supplied issuer chain IS a mismatch', async () => {
		const chained = ctCert({ chain: [{ spkiSha256: SPKI_A }, { spkiSha256: 'd'.repeat(64) }] });
		const findings = dane(await runDane({ [TLSA_APEX]: [`2 1 1 ${SPKI_B}`] }, [chained]));
		expect(findings[0].metadata?.daneOutcome).toBe('mismatch');
		expect(findings[0].severity).toBe('medium');
	});

	it('a DANE-TA pin matching an issuer in the supplied chain is a pass', async () => {
		const chained = ctCert({ chain: [{ spkiSha256: SPKI_A }, { spkiSha256: SPKI_B }] });
		const findings = dane(await runDane({ [TLSA_APEX]: [`2 1 1 ${SPKI_B}`] }, [chained]));
		expect(findings[0].metadata?.daneOutcome).toBe('matched');
	});

	it('a pin whose material the host did not supply (no SHA-512) is not-assessed, never a mismatch', async () => {
		const findings = dane(await runDane({ [TLSA_APEX]: [`3 1 2 ${'e'.repeat(128)}`] }, [ctCert()]));
		expect(findings[0].metadata?.daneOutcome).toBe('not-comparable');
	});

	it('an unparseable TLSA record is not-assessed', async () => {
		const findings = dane(await runDane({ [TLSA_APEX]: ['garbage'] }, [ctCert()]));
		expect(findings[0].metadata?.daneOutcome).toBe('not-comparable');
	});

	it('a failed TLSA lookup is not-assessed and suppresses the "no TLSA" claim', async () => {
		const resolver = caaResolver({}, { [TLSA_APEX]: 2 });
		const result = await checkCertPosture('example.com', resolver, { certificate: makeCert(), nowSeconds: NOW, ctCertificates: [ctCert()] });
		const findings = dane(result);
		expect(findings).toHaveLength(1);
		expect(findings[0].metadata).toMatchObject({ notAssessed: true, daneOutcome: 'lookup-failed', tlsaName: TLSA_APEX });
	});

	it('a THROWING TLSA lookup is not-assessed too', async () => {
		const throwing = (async (name: string) => {
			if (name.startsWith('_443._tcp.')) throw new Error('boom');
			return [];
		}) as DNSQueryFunction;
		const findings = dane(await checkCertPosture('example.com', throwing, { certificate: makeCert(), nowSeconds: NOW, ctCertificates: [ctCert()] }));
		expect(findings.map((f) => f.metadata?.daneOutcome)).toEqual(['lookup-failed', 'lookup-failed']);
	});

	it('ctCertificates without a posture certificate yields only the DANE findings (no abstention)', async () => {
		const result = await runDane({ [TLSA_APEX]: [`3 1 1 ${SPKI_A}`] }, [ctCert()], null);
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.map((f) => f.title)).toEqual(['DANE vs logged certificate: TLSA matches a logged certificate']);
	});

	it('does not query TLSA at all when there is neither a certificate nor ctCertificates', async () => {
		const seen: string[] = [];
		const resolver = (async (name: string) => {
			seen.push(name);
			return [];
		}) as DNSQueryFunction;
		await checkCertPosture('example.com', resolver, { certificate: null });
		expect(seen).toEqual([]);
	});
});
