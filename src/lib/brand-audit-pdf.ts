// SPDX-License-Identifier: BUSL-1.1

/**
 * Worker-side PDF renderer for brand-audit reports.
 *
 * Composes HTML via the shared template module, POSTs to the BV_BROWSER_RENDERER
 * service binding (a Fetcher to the bv-browser-renderer Worker that wraps the
 * Cloudflare Browser Rendering REST API), and returns PDF bytes. The renderer
 * Worker is single-request (Browser Rendering doesn't batch), so callers
 * orchestrate one PDF per queue message.
 *
 * Contract with bv-browser-renderer (synced 2026-05-19 with the post-evidence-storage
 * renderer API):
 *   POST {origin}/pdf/html
 *   Content-Type: application/json
 *   Body: { html: string, callerId: string }
 *   Response (success): 200 application/json { success: true, url, r2Key, metadata }
 *     — the renderer stored PDF bytes in its own R2 bucket and returned a signed
 *     URL. We then `fetch(url)` to obtain the bytes.
 *   Response (failure): non-2xx; body discarded
 *
 * Production note: the renderer dies on Cloudflare-runtime timeouts after ~30s.
 * The PDF queue consumer wraps this call in its own Promise.race; this module
 * does not impose a separate timeout.
 */

import type { CheckResult } from './scoring';
import { renderBrandAuditHtml, candidatesFromCheckResult } from './brand-audit-html-template';

/** Minimal Fetcher-shaped interface for the renderer service binding. */
export interface BrandAuditRendererBinding {
	fetch(input: RequestInfo, init?: RequestInit): Promise<Response>;
}

export interface RenderBrandAuditPdfOptions {
	renderer: BrandAuditRendererBinding;
	/** Server version for the PDF footer. Threaded from SERVER_VERSION at call time. */
	serverVersion: string;
	/**
	 * Admin API key for the renderer. The renderer's POST /pdf/html requires
	 * `Authorization: Bearer <ADMIN_API_KEY>` (validateAuth in
	 * bv-web/cloudflare/browser-renderer/src/router.ts). Threaded from the
	 * `BV_BROWSER_RENDERER_KEY` wrangler secret. When absent, the renderer
	 * returns 401 and the consumer retry-loops to exhaustion.
	 */
	rendererApiKey?: string;
	/** Clock override for tests (returns ms since epoch). Defaults to Date.now(). */
	now?: () => number;
	/** Optional inline logo. Worker-deployed renderer may instead inject this at fetch time. */
	logoBase64?: string;
	logoMimeType?: 'image/png' | 'image/svg+xml';
}

/** Render a brand-audit CheckResult to PDF bytes via the BV_BROWSER_RENDERER binding. */
export async function renderBrandAuditPdf(
	result: CheckResult,
	target: string,
	options: RenderBrandAuditPdfOptions,
): Promise<Uint8Array> {
	const now = options.now ?? Date.now;
	const dateIso = new Date(now()).toISOString();
	const candidates = candidatesFromCheckResult(result);

	const html = renderBrandAuditHtml({
		target,
		dateIso,
		serverVersion: options.serverVersion,
		candidates,
		logoBase64: options.logoBase64,
		logoMimeType: options.logoMimeType,
	});

	// Use a relative-ish URL — bv-browser-renderer is a service binding, not a public host.
	// The URL's origin is ignored when calling a binding's Fetcher; only the path matters.
	// callerId must be one of the renderer's KNOWN_CALLERS (see bv-web's
	// browser-renderer/src/utils/validation.ts). `intel-gateway` is the best
	// semantic fit — brand-audit is an intelligence-gathering surface and shares
	// the rate-limit bucket with other intel callers. If/when bv-web adds an
	// explicit `brand-audit` entry to KNOWN_CALLERS, switch to that.
	const headers: Record<string, string> = { 'Content-Type': 'application/json' };
	if (options.rendererApiKey) headers.Authorization = `Bearer ${options.rendererApiKey}`;
	const response = await options.renderer.fetch('https://renderer.internal/pdf/html', {
		method: 'POST',
		headers,
		body: JSON.stringify({ html, callerId: 'intel-gateway' }),
	});

	if (!response.ok) {
		throw new Error(`browser_renderer_failed: ${response.status}`);
	}

	// The renderer returns a JSON envelope with a signed R2 URL — fetch the bytes from there.
	const envelope = (await response.json()) as { success?: boolean; url?: string; error?: { message?: string } };
	if (!envelope.success || typeof envelope.url !== 'string') {
		throw new Error(`browser_renderer_no_url: ${envelope.error?.message ?? 'unknown'}`);
	}
	const pdfResp = await fetch(envelope.url);
	if (!pdfResp.ok) {
		throw new Error(`browser_renderer_pdf_fetch_failed: ${pdfResp.status}`);
	}
	const buffer = await pdfResp.arrayBuffer();
	return new Uint8Array(buffer);
}
