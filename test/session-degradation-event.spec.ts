// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';

describe('createSession degradation event on KV failure', () => {
	it('emits kv_fallback degradation event when KV put throws', async () => {
		const degradationEvents: Array<{ degradationType: string; component: string }> = [];
		const fakeAnalytics = {
			enabled: true,
			emitRequestEvent: vi.fn(),
			emitToolEvent: vi.fn(),
			emitRateLimitEvent: vi.fn(),
			emitSessionEvent: vi.fn(),
			emitDegradationEvent: (e: { degradationType: string; component: string }) => {
				degradationEvents.push({ degradationType: e.degradationType, component: e.component });
			},
		};
		const kv = {
			async get() { return null; },
			async put() { throw new Error('KV down'); },
			async delete() { /* noop */ },
			async list() { return { keys: [] }; },
		} as unknown as KVNamespace;

		const { createSession } = await import('../src/lib/session');
		const id = await createSession(kv, fakeAnalytics as never);
		expect(typeof id).toBe('string');
		expect(id.length).toBe(64);
		expect(degradationEvents).toEqual([{ degradationType: 'kv_fallback', component: 'session' }]);
	});

	it('does NOT emit degradation event when KV put succeeds', async () => {
		const degradationEvents: Array<unknown> = [];
		const fakeAnalytics = {
			enabled: true,
			emitRequestEvent: vi.fn(),
			emitToolEvent: vi.fn(),
			emitRateLimitEvent: vi.fn(),
			emitSessionEvent: vi.fn(),
			emitDegradationEvent: (e: unknown) => { degradationEvents.push(e); },
		};
		const store = new Map<string, string>();
		const kv = {
			async get(k: string) { return store.get(k) ?? null; },
			async put(k: string, v: string) { store.set(k, v); },
			async delete(k: string) { store.delete(k); },
			async list() { return { keys: [] }; },
		} as unknown as KVNamespace;

		const { createSession } = await import('../src/lib/session');
		await createSession(kv, fakeAnalytics as never);
		expect(degradationEvents).toEqual([]);
	});

	it('createSession without analytics still works (backward-compat)', async () => {
		const kv = {
			async get() { return null; },
			async put() { throw new Error('KV down'); },
			async delete() { /* noop */ },
			async list() { return { keys: [] }; },
		} as unknown as KVNamespace;
		const { createSession } = await import('../src/lib/session');
		const id = await createSession(kv);
		expect(typeof id).toBe('string');
	});
});
