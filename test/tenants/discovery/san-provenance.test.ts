// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it } from 'vitest';
import { buildSanCertificateProvenance } from '../../../src/tenants/discovery/san-provenance';

const fingerprint = 'ab'.repeat(32);
const full = {
	source: 'certspotter' as const,
	tbsSha256: fingerprint,
	dnsNames: ['seed.example.com', '*.example.com', 'www.example.net'],
	candidateDomains: ['www.example.net'],
	responseComplete: true,
};

describe('SAN discovery certificate provenance', () => {
	it('bounds candidate mappings independently of the unchanged discovery list', () => {
		const candidateDomains = Array.from({ length: 33 }, (_, i) => `candidate${i}.example.net`);
		const result = buildSanCertificateProvenance({ ...full, candidateDomains });
		expect(result.candidateDomains).toHaveLength(32);
		expect(result).toMatchObject({ candidateMappingComplete: false, coverage: 'unknown', registrableDomainCount: null });
		expect(candidateDomains).toHaveLength(33);
	});
	it('canonicalizes issuance identity and counts registrable apexes over the full certificate', () => {
		expect(buildSanCertificateProvenance({ ...full, tbsSha256: fingerprint.toUpperCase() })).toEqual({
			source: 'certspotter',
			issuanceSha256: fingerprint,
			candidateDomains: ['www.example.net'],
			candidateMappingComplete: true,
			coverage: 'complete',
			registrableDomainCount: 2,
		});
	});
	it('does not fabricate identity or fan-out from cursors, malformed fingerprints, or partial names', () => {
		for (const tbsSha256 of [undefined, '123', `${fingerprint} `, 123, 'zz'.repeat(32)]) {
			expect(buildSanCertificateProvenance({ ...full, tbsSha256 })).toMatchObject({
				issuanceSha256: null,
				coverage: 'unknown',
				registrableDomainCount: null,
			});
		}
		for (const dnsNames of [[], undefined, ['example.com', null], ['example.com', 'invalid..test'], Array(4097).fill('example.com')]) {
			expect(buildSanCertificateProvenance({ ...full, dnsNames })).toMatchObject({ coverage: 'unknown', registrableDomainCount: null });
		}
		expect(buildSanCertificateProvenance({ ...full, responseComplete: false })).toMatchObject({
			coverage: 'unknown',
			registrableDomainCount: null,
		});
	});
	it('withholds fan-out for query-matched and aggregate backends even when they carry a fingerprint', () => {
		for (const source of ['crtsh', 'certstream'] as const) {
			expect(buildSanCertificateProvenance({ ...full, source })).toMatchObject({ coverage: 'unknown', registrableDomainCount: null });
		}
	});
	it('certificate and precertificate observations retain the same issuance identity without merging candidates', () => {
		const cert = buildSanCertificateProvenance(full);
		const precert = buildSanCertificateProvenance({ ...full, candidateDomains: ['other.example.net'] });
		expect(precert.issuanceSha256).toBe(cert.issuanceSha256);
		expect(precert.candidateDomains).toEqual(['other.example.net']);
		expect(cert.candidateDomains).toEqual(['www.example.net']);
	});
});
