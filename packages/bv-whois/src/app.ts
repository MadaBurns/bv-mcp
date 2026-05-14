// SPDX-License-Identifier: BUSL-1.1
/**
 * Hono app for the bv-whois shim Worker.
 *
 * Routes:
 *   POST /lookup   — body { domain }, returns { registrar, source }
 *   GET  /health   — liveness probe
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { lookupRegistrar } from './lookup';
import type { LookupDeps } from './lookup';

const MAX_BODY_BYTES = 1024;

const LookupRequestSchema = z.object({
	domain: z.string().min(3).max(253),
});

/**
 * Build the app. Deps are passed in so route handlers can be exercised in
 * tests without a Worker runtime.
 */
export function buildApp(deps: LookupDeps): Hono {
	const app = new Hono();

	app.get('/health', c => c.json({ status: 'ok' }));

	app.post('/lookup', async c => {
		const contentType = c.req.header('content-type') ?? '';
		if (!contentType.toLowerCase().includes('application/json')) {
			return c.json({ error: 'Content-Type must be application/json' }, 415);
		}

		const lengthHeader = c.req.header('content-length');
		if (lengthHeader && parseInt(lengthHeader, 10) > MAX_BODY_BYTES) {
			return c.json({ error: 'Request body too large' }, 413);
		}

		let raw: unknown;
		try {
			raw = await c.req.json();
		} catch {
			return c.json({ error: 'Invalid JSON' }, 400);
		}

		const parsed = LookupRequestSchema.safeParse(raw);
		if (!parsed.success) {
			return c.json({ error: 'Invalid request: domain (string) required' }, 400);
		}

		const result = await lookupRegistrar(parsed.data.domain, deps);
		return c.json(result, 200);
	});

	// GET /lookup → 405 (only POST is supported)
	app.get('/lookup', c => c.json({ error: 'Method not allowed' }, 405));

	return app;
}
