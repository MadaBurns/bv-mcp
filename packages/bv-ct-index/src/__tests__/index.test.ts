// SPDX-License-Identifier: BUSL-1.1
/**
 * The Worker entrypoint: GET /health is open; every other route is the authenticated query API (api.test.ts,
 * api-worker.test.ts); scheduled and queue are wired.
 */

import { describe, expect, it } from 'vitest';
import worker from '../index';
import { testEnv } from './indexer-harness';

describe('bv-ct-index Worker', () => {
	it('answers GET /health with its name, without a key', async () => {
		const res = await worker.fetch(new Request('https://bv-ct-index/health'), { ...testEnv(), CT_INDEX_ADMIN_KEY: '' });
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true, worker: 'bv-ct-index' });
	});

	it('exports scheduled and queue handlers', () => {
		expect(typeof worker.scheduled).toBe('function');
		expect(typeof worker.queue).toBe('function');
	});
});
