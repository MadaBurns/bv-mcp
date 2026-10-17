// SPDX-License-Identifier: BUSL-1.1
/**
 * The wave-1 stub Worker: GET /health answers, every other route is 501 until wave 2 lands.
 */

import { describe, expect, it } from 'vitest';
import worker from '../index';

describe('bv-ct-index stub Worker', () => {
	it('answers GET /health with its name', async () => {
		const res = await worker.fetch(new Request('https://bv-ct-index/health'));
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true, worker: 'bv-ct-index' });
	});

	it.each([
		['GET', '/enumerate?domain=example.com'],
		['GET', '/sans?domain=example.com'],
		['GET', '/cert-meta?domain=example.com'],
		['POST', '/health'],
	])('returns 501 for %s %s', async (method, path) => {
		const res = await worker.fetch(new Request(`https://bv-ct-index${path}`, { method }));
		expect(res.status).toBe(501);
	});

	it('exports scheduled and queue handlers for wave 2 to fill', () => {
		expect(typeof worker.scheduled).toBe('function');
		expect(typeof worker.queue).toBe('function');
	});
});
