// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { enrichWithCertificateMetadata } from '../../src/lib/cert-metadata-enrich';
import type { CheckResult } from '../../src/lib/scoring';

const NOW = 1_780_000_000;

const BASE: CheckResult = {
	category: 'ssl',
	passed: true,
	score: 100,
	findings: [],
	controlPresent: true,
};

function ctResponse(over: Record<string, unknown> = {}) {
	return vi.fn(
		async () =>
			new Response(
				JSON.stringify([
					{
						not_before: '2026-05-01T00:00:00Z',
						not_after: '2026-08-01T00:00:00Z',
						dns_names: ['example.com', 'www.example.com'],
						issuer: { name: "Let's Encrypt" },
						serial: 'abc123',
						...over,
					},
				]),
				{ status: 200 },
			),
	);
}

describe('enrichWithCertificateMetadata', () => {
	it('attaches issuer/expiry/SAN metadata without touching score or findings', async () => {
		// THE INVARIANT: this enrichment must never move a domain's grade, so a CT
		// outage or a Certspotter rate-limit can never be mistaken for a posture change.
		const out = await enrichWithCertificateMetadata(BASE, 'example.com', ctResponse() as never, NOW);

		expect(out.metadata?.certificate).toMatchObject({
			issuer: "Let's Encrypt",
			expiryBand: 'ok',
			sanCount: 2,
			serial: 'abc123',
			source: 'ct',
		});
		expect(out.score).toBe(BASE.score);
		expect(out.passed).toBe(BASE.passed);
		expect(out.findings).toEqual([]);
		expect(out.controlPresent).toBe(true);
	});

	it('emits ISO dates, not raw epochs', async () => {
		const out = await enrichWithCertificateMetadata(BASE, 'example.com', ctResponse() as never, NOW);
		const cert = out.metadata?.certificate as { notBefore: string; notAfter: string };
		expect(cert.notBefore).toBe('2026-05-01T00:00:00.000Z');
		expect(cert.notAfter).toBe('2026-08-01T00:00:00.000Z');
	});

	it('reports an expired certificate honestly rather than hiding it', async () => {
		const out = await enrichWithCertificateMetadata(
			BASE,
			'example.com',
			ctResponse({ not_after: '2020-01-01T00:00:00Z' }) as never,
			NOW,
		);
		const cert = out.metadata?.certificate as { expiryBand: string; daysRemaining: number };
		expect(cert.expiryBand).toBe('expired');
		expect(cert.daysRemaining).toBeLessThan(0);
		// …and STILL does not change the score.
		expect(out.score).toBe(100);
		expect(out.findings).toEqual([]);
	});

	it('returns the result unchanged when nothing was found', async () => {
		// An absent CT record is not evidence about TLS posture — an empty
		// `certificate` block would read as "we looked and there is no certificate".
		const empty = vi.fn(async () => new Response('[]', { status: 200 }));
		const out = await enrichWithCertificateMetadata(BASE, 'nocert.com', empty as never, NOW);
		expect(out).toEqual(BASE);
		expect(out.metadata?.certificate).toBeUndefined();
	});

	it('is fail-soft against every upstream failure mode', async () => {
		const failures = [
			vi.fn(async () => {
				throw new Error('network');
			}),
			vi.fn(async () => new Response('rate limited', { status: 429 })),
			vi.fn(async () => new Response('{not json', { status: 200 })),
		];
		for (const fetchFn of failures) {
			await expect(enrichWithCertificateMetadata(BASE, 'example.com', fetchFn as never, NOW)).resolves.toEqual(BASE);
		}
	});

	it('preserves metadata a sibling enricher already attached', async () => {
		const withSibling: CheckResult = { ...BASE, metadata: { tlsProbeEnriched: true } };
		const out = await enrichWithCertificateMetadata(withSibling, 'example.com', ctResponse() as never, NOW);
		expect(out.metadata?.tlsProbeEnriched).toBe(true);
		expect(out.metadata?.certificate).toBeDefined();
	});

	it('leaves key strength out entirely — this Worker cannot decode a DER', async () => {
		// No nodejs_compat → no node:crypto → no X.509 decode. Reporting a guessed
		// band would be worse than omitting the field.
		const out = await enrichWithCertificateMetadata(BASE, 'example.com', ctResponse() as never, NOW);
		expect(out.metadata?.certificate).not.toHaveProperty('keyBits');
		expect(out.metadata?.certificate).not.toHaveProperty('keyStrength');
	});
});

describe('checkSsl certMetadata gating', () => {
	it('makes NO Certspotter request unless the caller opts in', async () => {
		// THE SPEND GUARD: Certspotter's free tier is ~100 req/hour/egress-IP, shared
		// across this Worker. `scan_domain` fans out 17 checks per call and does not
		// surface this field, so enriching there would burn the quota for nothing —
		// and an exhausted quota means no metadata for anyone.
		const { checkSsl } = await import('../../src/tools/check-ssl');
		const seen: string[] = [];
		const originalFetch = globalThis.fetch;
		globalThis.fetch = (async (url: string | URL | Request) => {
			seen.push(String(url instanceof Request ? url.url : url));
			return new Response('', { status: 200, headers: { 'strict-transport-security': 'max-age=63072000' } });
		}) as typeof fetch;

		try {
			await checkSsl('example.com');
			expect(seen.some((u) => u.includes('certspotter'))).toBe(false);

			seen.length = 0;
			await checkSsl('example.com', { certMetadata: true });
			expect(seen.some((u) => u.includes('certspotter'))).toBe(true);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
});
