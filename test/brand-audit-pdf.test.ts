// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the Worker-side PDF renderer (`src/lib/brand-audit-pdf.ts`).
 *
 * The renderer composes HTML via the shared template and POSTs to the
 * `BV_BROWSER_RENDERER` service binding (a Fetcher to the bv-browser-renderer
 * Worker, which wraps Cloudflare Browser Rendering). All I/O is injected so
 * tests stay offline.
 *
 * Contract with bv-browser-renderer:
 *   POST /pdf
 *   Content-Type: application/json
 *   Body: { html: string }
 *   Response: application/pdf bytes on success; non-200 on failure.
 */

import { describe, it, expect, vi } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';

function makeBrandAuditResult(): CheckResult {
	return {
		category: 'brand_discovery',
		score: 100,
		findings: [
			{
				category: 'brand_discovery',
				title: 'Brand audit summary',
				severity: 'info',
				detail: '',
				metadata: { summary: true, target: 'apple.com', consolidated: 1, shadowIt: 0, indeterminate: 0, impersonation: 0 },
			},
			{
				category: 'brand_discovery',
				title: 'apple.net',
				severity: 'info',
				detail: '',
				metadata: {
					candidate: 'apple.net',
					bucket: 'consolidated',
					registrar: 'MarkMonitor Inc.',
					registrarSource: 'rdap',
					reasons: ['NS overlap'],
					signals: ['ns'],
					combinedConfidence: 0.95,
				},
			},
		],
	};
}

function fakePdfBytes(): Uint8Array {
	return new TextEncoder().encode('%PDF-1.4\n%fake pdf body\n%%EOF\n');
}

describe('renderBrandAuditPdf', () => {
	it('POSTs HTML to the renderer service binding and returns PDF bytes', async () => {
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf');
		const renderer = {
			fetch: vi.fn().mockResolvedValue(
				new Response(fakePdfBytes(), { status: 200, headers: { 'Content-Type': 'application/pdf' } }),
			),
		};

		const bytes = await renderBrandAuditPdf(makeBrandAuditResult(), 'apple.com', {
			renderer,
			now: () => new Date('2026-05-15T00:00:00Z').getTime(),
			serverVersion: '2.20.0',
		});

		expect(bytes).toBeInstanceOf(Uint8Array);
		expect(bytes.byteLength).toBeGreaterThan(0);
		expect(renderer.fetch).toHaveBeenCalledTimes(1);

		const callArgs = renderer.fetch.mock.calls[0];
		const url = typeof callArgs[0] === 'string' ? callArgs[0] : (callArgs[0] as Request).url;
		expect(url).toMatch(/\/pdf$/);
		const init = (callArgs[1] ?? {}) as { method?: string; headers?: Record<string, string>; body?: string };
		expect(init.method).toBe('POST');
		const body = JSON.parse(init.body ?? '{}') as { html: string };
		expect(body.html).toContain('Discovery Intel Report');
		expect(body.html).toContain('apple.com');
		expect(body.html).toContain('apple.net');
		expect(body.html).toContain('MarkMonitor');
	});

	it('throws a structured error when renderer responds non-2xx', async () => {
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf');
		const renderer = {
			fetch: vi.fn().mockResolvedValue(new Response('rate limited', { status: 429 })),
		};

		await expect(
			renderBrandAuditPdf(makeBrandAuditResult(), 'apple.com', { renderer, now: () => 0, serverVersion: '2.20.0' }),
		).rejects.toThrow(/browser_renderer_failed: 429/);
	});

	it('escapes user-controlled domain values in the HTML body', async () => {
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf');
		const renderer = {
			fetch: vi.fn().mockResolvedValue(new Response(fakePdfBytes(), { status: 200 })),
		};

		const malicious: CheckResult = {
			category: 'brand_discovery',
			score: 100,
			findings: [
				{
					category: 'brand_discovery',
					title: 'apple-<script>.com',
					severity: 'info',
					detail: '',
					metadata: {
						candidate: 'apple-<script>alert(1)</script>.com',
						bucket: 'impersonation',
						registrar: 'Evil & Co',
						registrarSource: 'rdap',
						reasons: ['markov'],
						signals: ['markov_gen'],
						combinedConfidence: 0.1,
					},
				},
			],
		};

		await renderBrandAuditPdf(malicious, 'apple.com', { renderer, now: () => 0, serverVersion: '2.20.0' });

		const body = JSON.parse(((renderer.fetch.mock.calls[0][1] ?? {}) as { body?: string }).body ?? '{}') as { html: string };
		expect(body.html).not.toContain('<script>alert(1)</script>');
		expect(body.html).toContain('&lt;script&gt;');
		expect(body.html).toContain('Evil &amp; Co');
	});
});
