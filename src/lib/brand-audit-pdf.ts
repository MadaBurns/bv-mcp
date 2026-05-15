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
 * Contract with bv-browser-renderer:
 *   POST {origin}/pdf
 *   Content-Type: application/json
 *   Body: { html: string }
 *   Response (success): 200 application/pdf; body = PDF bytes
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
	const response = await options.renderer.fetch('https://renderer.internal/pdf', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ html }),
	});

	if (!response.ok) {
		throw new Error(`browser_renderer_failed: ${response.status}`);
	}

	const buffer = await response.arrayBuffer();
	return new Uint8Array(buffer);
}
