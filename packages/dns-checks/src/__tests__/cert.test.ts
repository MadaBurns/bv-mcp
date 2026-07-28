// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import {
	assessExpiry,
	assessKeyStrength,
	normalizeKeyType,
	ecCurveToBits,
	normalizeCertDate,
	mergeCertSources,
	buildCertMetadataUrl,
	parseCertMetadataFromCt,
	parseCertDerFromCt,
	enrichCertificateIntelligence,
	type CertMetadata,
	type DerKeyParser,
} from '../cert';

const NOW = 1_780_000_000; // epoch seconds

function issuance(over: Record<string, unknown> = {}) {
	return {
		not_before: '2026-05-01T00:00:00Z',
		not_after: '2026-08-01T00:00:00Z',
		dns_names: ['example.com', 'www.example.com'],
		issuer: { name: "Let's Encrypt" },
		serial: 'abc123',
		...over,
	};
}

function okResponse(payload: unknown): Response {
	return new Response(JSON.stringify(payload), { status: 200 });
}

describe('normalizeCertDate', () => {
	it('accepts ISO, the OpenSSL form, and a numeric epoch', () => {
		expect(normalizeCertDate('2026-05-01T00:00:00Z')).toBe(1777593600);
		expect(normalizeCertDate('May  1 00:00:00 2026 GMT')).toBe(1777593600);
		expect(normalizeCertDate(1777593600)).toBe(1777593600);
	});

	it('returns null for an unparseable or absent value rather than 0', () => {
		// 0 would read as "1970", a real-looking date. Null is the honest answer.
		expect(normalizeCertDate('not a date')).toBeNull();
		expect(normalizeCertDate(null)).toBeNull();
		expect(normalizeCertDate(Number.NaN)).toBeNull();
	});
});

describe('assessExpiry', () => {
	it('bands by days remaining', () => {
		expect(assessExpiry(NOW + 86400 * 200, NOW)).toEqual({ band: 'ok', daysRemaining: 200 });
		expect(assessExpiry(NOW + 86400 * 20, NOW)).toEqual({ band: 'warning', daysRemaining: 20 });
		expect(assessExpiry(NOW + 86400 * 3, NOW)).toEqual({ band: 'critical', daysRemaining: 3 });
		expect(assessExpiry(NOW - 86400 * 5, NOW)).toEqual({ band: 'expired', daysRemaining: -5 });
	});

	it('keeps `unknown` distinct from `ok` when there is no expiry date', () => {
		// Folding these together would report an unmeasured certificate as healthy.
		expect(assessExpiry(null, NOW)).toEqual({ band: 'unknown', daysRemaining: null });
	});

	it('bands the exact boundaries on the safe side', () => {
		expect(assessExpiry(NOW + 86400 * 7, NOW).band).toBe('critical');
		expect(assessExpiry(NOW + 86400 * 30, NOW).band).toBe('warning');
		expect(assessExpiry(NOW + 86400 * 31, NOW).band).toBe('ok');
	});
});

describe('assessKeyStrength', () => {
	it('bands RSA by modulus size', () => {
		expect(assessKeyStrength({ keyType: 'rsa', keyBits: 1024 }).band).toBe('weak');
		expect(assessKeyStrength({ keyType: 'rsa', keyBits: 2048 }).band).toBe('acceptable');
		expect(assessKeyStrength({ keyType: 'rsa', keyBits: 4096 }).band).toBe('strong');
	});

	it('bands EC by curve size', () => {
		expect(assessKeyStrength({ keyType: 'ec', keyBits: 224 }).band).toBe('weak');
		expect(assessKeyStrength({ keyType: 'ec', keyBits: 256 }).band).toBe('strong');
	});

	it('bands weak on a weak signature ALONE, with no key material', () => {
		// MD5/SHA-1 is a defect on its own terms — it does not need a key size to judge.
		const md5 = assessKeyStrength({ sigAlg: 'md5WithRSAEncryption' });
		expect(md5.band).toBe('weak');
		expect(md5.reasons).toContain('Weak signature algorithm: MD5');

		const sha1 = assessKeyStrength({ keyType: 'rsa', keyBits: 4096, sigAlg: 'sha1WithRSAEncryption' });
		expect(sha1.band).toBe('weak');
	});

	it('does not mistake sha256 for the sha1 pattern', () => {
		expect(assessKeyStrength({ keyType: 'rsa', keyBits: 4096, sigAlg: 'sha256WithRSAEncryption' }).band).toBe('strong');
	});

	it('returns `unknown`, never a guess, when there is nothing to judge', () => {
		expect(assessKeyStrength({}).band).toBe('unknown');
		expect(assessKeyStrength({ keyType: 'rsa', keyBits: null }).band).toBe('unknown');
	});
});

describe('key normalization', () => {
	it('maps runtime key types onto the vocabulary', () => {
		expect(normalizeKeyType('rsa')).toBe('rsa');
		expect(normalizeKeyType('RSA-PSS')).toBe('rsa');
		expect(normalizeKeyType('ec')).toBe('ec');
		expect(normalizeKeyType('ed25519')).toBe('unknown');
		expect(normalizeKeyType(null)).toBe('unknown');
	});

	it('maps EC curves by both OpenSSL and NIST names', () => {
		expect(ecCurveToBits('prime256v1')).toBe(256);
		expect(ecCurveToBits('P-256')).toBe(256);
		expect(ecCurveToBits('secp384r1')).toBe(384);
		expect(ecCurveToBits('brainpoolP256r1')).toBeNull();
		expect(ecCurveToBits(null)).toBeNull();
	});
});

describe('mergeCertSources', () => {
	const ct: CertMetadata = {
		domain: 'example.com',
		issuer: 'CT Issuer',
		notBefore: 1,
		notAfter: 2,
		sans: ['a.example.com'],
		serial: 'ct',
		source: 'ct',
	};

	it('lets the live (actually-served) certificate win field by field', () => {
		const live: CertMetadata = { ...ct, issuer: 'Live Issuer', sans: [], serial: 'live', source: 'live' };
		const merged = mergeCertSources(ct, live)!;
		expect(merged.issuer).toBe('Live Issuer');
		expect(merged.source).toBe('live');
		// CT fills the gap where live has nothing.
		expect(merged.sans).toEqual(['a.example.com']);
	});

	it('returns whichever single source exists, or null for neither', () => {
		expect(mergeCertSources(ct, null)).toBe(ct);
		expect(mergeCertSources(null, null)).toBeNull();
	});
});

describe('buildCertMetadataUrl', () => {
	it('REPEATS the expand param rather than comma-joining it', () => {
		// Certspotter reads one field per param; a comma-joined value returns none.
		const url = new URL(buildCertMetadataUrl('example.com'));
		expect(url.searchParams.getAll('expand').sort()).toEqual(['cert', 'dns_names', 'issuer', 'not_after', 'not_before']);
		expect(url.searchParams.get('domain')).toBe('example.com');
	});
});

describe('parseCertMetadataFromCt', () => {
	it('picks the most recently ISSUED entry, not the first in the array', () => {
		const body = JSON.stringify([
			issuance({ not_before: '2026-01-01T00:00:00Z', serial: 'old' }),
			issuance({ not_before: '2026-06-01T00:00:00Z', serial: 'newest' }),
			issuance({ not_before: '2026-03-01T00:00:00Z', serial: 'middle' }),
		]);
		expect(parseCertMetadataFromCt(body, 'example.com')?.serial).toBe('newest');
	});

	it('still returns the newest issuance when it has already expired', () => {
		// Expiry-filtering here would hide exactly the state a reader needs to see.
		const body = JSON.stringify([issuance({ not_after: '2020-01-01T00:00:00Z', serial: 'expired' })]);
		const meta = parseCertMetadataFromCt(body, 'example.com');
		expect(meta?.serial).toBe('expired');
		expect(assessExpiry(meta!.notAfter, NOW).band).toBe('expired');
	});

	it('returns null on malformed, empty, or non-array bodies rather than throwing', () => {
		expect(parseCertMetadataFromCt('{not json', 'example.com')).toBeNull();
		expect(parseCertMetadataFromCt('[]', 'example.com')).toBeNull();
		expect(parseCertMetadataFromCt('{"error":"rate limited"}', 'example.com')).toBeNull();
	});

	it('tolerates missing optional fields', () => {
		const meta = parseCertMetadataFromCt(JSON.stringify([{ not_before: '2026-05-01T00:00:00Z' }]), 'example.com');
		expect(meta).toMatchObject({ issuer: null, serial: null, sans: [], notAfter: null });
	});
});

describe('parseCertDerFromCt', () => {
	it('returns the DER of the SAME issuance the metadata came from', () => {
		const body = JSON.stringify([
			issuance({ not_before: '2026-01-01T00:00:00Z', cert: { data: 'OLD' } }),
			issuance({ not_before: '2026-06-01T00:00:00Z', cert: { data: 'NEWEST' } }),
		]);
		expect(parseCertDerFromCt(body)).toBe('NEWEST');
	});

	it('returns null when the feed carries no cert expansion', () => {
		expect(parseCertDerFromCt(JSON.stringify([issuance()]))).toBeNull();
	});
});

describe('enrichCertificateIntelligence', () => {
	it('folds a CT hit into metadata plus an expiry band', async () => {
		const fetchFn = vi.fn(async () => okResponse([issuance()]));
		const out = await enrichCertificateIntelligence({ domain: 'example.com', nowSeconds: NOW, fetchFn });
		expect(out.available).toBe(true);
		expect(out.meta?.issuer).toBe("Let's Encrypt");
		expect(out.meta?.source).toBe('ct');
		// not_after 2026-08-01 is 64 days past NOW → `ok`. Asserted against the band
		// helper rather than a hand-computed literal so the two cannot drift apart.
		expect(out.expiry).toEqual(assessExpiry(normalizeCertDate('2026-08-01T00:00:00Z'), NOW));
		expect(out.expiry.band).toBe('ok');
	});

	it('leaves key strength `unknown` when no DER parser is injected', async () => {
		// This is the bv-mcp worker's real configuration: no nodejs_compat, so no
		// node:crypto, so no X.509 decode. `unknown` is the honest answer.
		const fetchFn = vi.fn(async () => okResponse([issuance({ cert: { data: 'BASE64DER' } })]));
		const out = await enrichCertificateIntelligence({ domain: 'example.com', nowSeconds: NOW, fetchFn });
		expect(out.keyStrength.band).toBe('unknown');
		expect(out.meta?.keyBits).toBeUndefined();
	});

	it('uses an injected DER parser when one is available', async () => {
		const derKeyParser: DerKeyParser = vi.fn(() => ({ keyType: 'ec', keyBits: 256, sigAlg: 'sha256WithRSAEncryption' }));
		const fetchFn = vi.fn(async () => okResponse([issuance({ cert: { data: 'BASE64DER' } })]));
		const out = await enrichCertificateIntelligence({ domain: 'example.com', nowSeconds: NOW, fetchFn, derKeyParser });
		expect(derKeyParser).toHaveBeenCalledWith('BASE64DER');
		expect(out.keyStrength.band).toBe('strong');
		expect(out.meta?.keyBits).toBe(256);
	});

	it('degrades to unavailable — never throws — when the upstream fails', async () => {
		for (const fetchFn of [
			vi.fn(async () => {
				throw new Error('network');
			}),
			vi.fn(async () => new Response('rate limited', { status: 429 })),
			vi.fn(async () => okResponse([])),
		]) {
			const out = await enrichCertificateIntelligence({ domain: 'example.com', nowSeconds: NOW, fetchFn });
			expect(out.available).toBe(false);
			expect(out.meta).toBeNull();
			expect(out.expiry.band).toBe('unknown');
		}
	});

	it('survives a DER parser that throws', async () => {
		const derKeyParser: DerKeyParser = () => {
			throw new Error('bad der');
		};
		const fetchFn = vi.fn(async () => okResponse([issuance({ cert: { data: 'BASE64DER' } })]));
		await expect(
			enrichCertificateIntelligence({ domain: 'example.com', nowSeconds: NOW, fetchFn, derKeyParser }),
		).resolves.toMatchObject({ available: false });
	});

	it('refuses an oversized CT body rather than parsing a truncated one', async () => {
		const fetchFn = vi.fn(
			async () =>
				new Response(JSON.stringify([issuance()]), {
					status: 200,
					headers: { 'content-length': String(50 * 1024 * 1024) },
				}),
		);
		const out = await enrichCertificateIntelligence({ domain: 'example.com', nowSeconds: NOW, fetchFn });
		expect(out.available).toBe(false);
	});

	it('lets a live probe override CT, and tolerates one that throws', async () => {
		const fetchFn = vi.fn(async () => okResponse([issuance()]));
		const live = await enrichCertificateIntelligence({
			domain: 'example.com',
			nowSeconds: NOW,
			fetchFn,
			probeLive: async () => ({
				domain: 'example.com',
				issuer: 'Served Issuer',
				notBefore: null,
				notAfter: null,
				sans: [],
				serial: null,
				source: 'live',
			}),
		});
		expect(live.meta?.issuer).toBe('Served Issuer');
		expect(live.meta?.source).toBe('live');

		const broken = await enrichCertificateIntelligence({
			domain: 'example.com',
			nowSeconds: NOW,
			fetchFn,
			probeLive: async () => {
				throw new Error('no raw TLS on workerd');
			},
		});
		expect(broken.meta?.issuer).toBe("Let's Encrypt"); // falls back to CT
	});
});
