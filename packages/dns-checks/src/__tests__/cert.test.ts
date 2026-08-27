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
	assessValidityWindow,
	SC081_MAX_LIFETIME_DAYS,
	SC081_EFFECTIVE_SECONDS,
	type CertMetadata,
	type DerKeyParser,
	type ValidityWindowBand,
} from '../cert';

const NOW = 1_780_000_000; // epoch seconds

const DAY = 86400;
/** 2026-03-15T00:00:00Z — the date the CA/Browser Forum SC-081 200-day maximum took force. */
const SC081 = 1_773_532_800;
/** A `notBefore` comfortably before SC-081 took force (2026-01-01T00:00:00Z). */
const BEFORE_SC081 = 1_767_225_600;
/** A `notBefore` comfortably after SC-081 took force (2026-05-01T00:00:00Z). */
const AFTER_SC081 = 1_777_593_600;

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

	it('refuses a streamed CT body over the cap when Content-Length is missing', async () => {
		const cancelled = vi.fn();
		let pull = 0;
		const fetchFn = vi.fn(
			async () =>
				new Response(
					new ReadableStream<Uint8Array>({
						pull(controller) {
							if (pull++ === 0) controller.enqueue(new Uint8Array(5 * 1024 * 1024));
							else if (pull === 2) controller.enqueue(new Uint8Array([1]));
							else if (pull === 3) controller.enqueue(new Uint8Array([2]));
							else controller.close();
						},
						cancel: cancelled,
					}),
					{ status: 200 },
				),
		);

		const out = await enrichCertificateIntelligence({ domain: 'example.com', nowSeconds: NOW, fetchFn });
		expect(out.available).toBe(false);
		expect(cancelled).toHaveBeenCalledOnce();
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

describe('assessValidityWindow', () => {
	// D1 — the validity window itself, which nothing in this package computed before.
	it('computes the window length in days from notBefore/notAfter', () => {
		expect(assessValidityWindow({ notBefore: AFTER_SC081, notAfter: AFTER_SC081 + 47 * DAY }).days).toBe(47);
		expect(assessValidityWindow({ notBefore: AFTER_SC081, notAfter: AFTER_SC081 + 90 * DAY }).days).toBe(90);
	});

	// D2 — the CA/Browser Forum SC-081 automation-readiness bands.
	it('bands a post-SC-081 certificate by its window length', () => {
		const band = (days: number) => assessValidityWindow({ notBefore: AFTER_SC081, notAfter: AFTER_SC081 + days * DAY }).band;
		expect(band(30)).toBe('exemplary');
		expect(band(47)).toBe('exemplary');
		expect(band(48)).toBe('automated');
		expect(band(100)).toBe('automated');
		expect(band(101)).toBe('compliant');
		expect(band(200)).toBe('compliant');
		expect(band(201)).toBe('anomaly');
	});

	it('pins the SC-081 constants it bands against', () => {
		// The maximum has been IN FORCE since 2026-03-15 — this is a past date, not upcoming.
		expect(SC081_MAX_LIFETIME_DAYS).toBe(200);
		expect(SC081_EFFECTIVE_SECONDS).toBe(SC081);
		expect(new Date(SC081_EFFECTIVE_SECONDS * 1000).toISOString()).toBe('2026-03-15T00:00:00.000Z');
	});

	// D3 — the discriminating test. Without this the assessment flags every older
	// certificate and is worthless: a 398-day window issued under the OLD rules was
	// legitimately issued and is still valid.
	it('does NOT flag a 398-day window issued BEFORE SC-081 took force', () => {
		const legacy = assessValidityWindow({ notBefore: BEFORE_SC081, notAfter: BEFORE_SC081 + 398 * DAY });
		expect(legacy.days).toBe(398);
		expect(legacy.band).toBe('legacy');
		expect(legacy.band).not.toBe('anomaly');
	});

	it('DOES flag the same 398-day window issued AFTER SC-081 took force', () => {
		const anomalous = assessValidityWindow({ notBefore: AFTER_SC081, notAfter: AFTER_SC081 + 398 * DAY });
		expect(anomalous.days).toBe(398);
		expect(anomalous.band).toBe('anomaly');
	});

	it('treats the effective date itself as in force (issued ON 2026-03-15 is bound by it)', () => {
		expect(assessValidityWindow({ notBefore: SC081, notAfter: SC081 + 398 * DAY }).band).toBe('anomaly');
		expect(assessValidityWindow({ notBefore: SC081 - 1, notAfter: SC081 - 1 + 398 * DAY }).band).toBe('legacy');
	});

	// D4 — unknown is not compliant.
	it('returns an explicit `unknown` band, never a default pass, when a date is missing', () => {
		// A null date means we did not MEASURE the window. Banding it as compliant would
		// be an affirmative safety claim from zero evidence.
		expect(assessValidityWindow({ notBefore: null, notAfter: AFTER_SC081 + 47 * DAY })).toEqual({
			band: 'unknown',
			days: null,
		});
		expect(assessValidityWindow({ notBefore: AFTER_SC081, notAfter: null })).toEqual({ band: 'unknown', days: null });
		expect(assessValidityWindow({ notBefore: null, notAfter: null })).toEqual({ band: 'unknown', days: null });
	});

	it('carries no boolean anywhere in the result, so UNKNOWN cannot compile into `false`', () => {
		const results = [
			assessValidityWindow({ notBefore: null, notAfter: null }),
			assessValidityWindow({ notBefore: AFTER_SC081, notAfter: AFTER_SC081 + 47 * DAY }),
			assessValidityWindow({ notBefore: AFTER_SC081, notAfter: AFTER_SC081 + 398 * DAY }),
		];
		for (const r of results) {
			for (const value of Object.values(r)) {
				expect(typeof value).not.toBe('boolean');
			}
		}
	});

	it('keeps `unknown` outside every band a consumer could read as a pass', () => {
		const passBands: ValidityWindowBand[] = ['exemplary', 'automated', 'compliant', 'legacy'];
		const unknown = assessValidityWindow({ notBefore: null, notAfter: null }).band;
		expect(passBands).not.toContain(unknown);
	});

	// Degenerate input — explicit, never a silent negative day count.
	it('bands a non-positive window `invalid` rather than returning negative days', () => {
		expect(assessValidityWindow({ notBefore: AFTER_SC081, notAfter: AFTER_SC081 - 10 * DAY }).band).toBe('invalid');
		expect(assessValidityWindow({ notBefore: AFTER_SC081, notAfter: AFTER_SC081 }).band).toBe('invalid');
		expect(assessValidityWindow({ notBefore: AFTER_SC081, notAfter: AFTER_SC081 - 10 * DAY }).days).not.toBeLessThan(0);
	});

	// D5 — no wall-clock branch. The comparison is a certificate PROPERTY against a
	// FIXED standards date, both passed in; parity fixtures must stay deterministic.
	it('never reads the wall clock', () => {
		const nowSpy = vi.spyOn(Date, 'now');
		assessValidityWindow({ notBefore: AFTER_SC081, notAfter: AFTER_SC081 + 398 * DAY });
		assessValidityWindow({ notBefore: null, notAfter: null });
		expect(nowSpy).not.toHaveBeenCalled();
		nowSpy.mockRestore();
	});

	it('is deterministic — the same inputs give the same output under any system time', () => {
		const input = { notBefore: BEFORE_SC081, notAfter: BEFORE_SC081 + 398 * DAY };
		vi.useFakeTimers();
		try {
			vi.setSystemTime(new Date('2020-01-01T00:00:00Z'));
			const early = assessValidityWindow(input);
			vi.setSystemTime(new Date('2099-12-31T00:00:00Z'));
			const late = assessValidityWindow(input);
			expect(early).toEqual(late);
			expect(early).toEqual({ band: 'legacy', days: 398 });
		} finally {
			vi.useRealTimers();
		}
	});

	it('accepts an injected effective date, following the `nowSeconds` parameter convention', () => {
		// Same certificate, judged against a different standards date — no hidden clock.
		const cert = { notBefore: BEFORE_SC081, notAfter: BEFORE_SC081 + 398 * DAY };
		expect(assessValidityWindow(cert, SC081).band).toBe('legacy');
		expect(assessValidityWindow(cert, BEFORE_SC081 - DAY).band).toBe('anomaly');
	});
});
