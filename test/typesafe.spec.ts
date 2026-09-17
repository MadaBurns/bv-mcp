// SPDX-License-Identifier: BUSL-1.1

/**
 * Fail-soft contract for the TypeSafe client wrapper.
 *
 * The whole point of these cases is the NEGATIVE path: unprovisioned, spent
 * budget, network fault, malformed body. Every one must return `null` rather than
 * throw, because callers treat a judgment as enrichment and fall back to their
 * deterministic path. If any of these ever starts throwing, a third-party outage
 * becomes a scanner outage.
 */

import { describe, expect, it, vi } from 'vitest';

/** Minimal stand-in for the SDK client; `askTypesafe` only ever calls `systemOne`. */
function stubClient(impl: () => unknown) {
	return { systemOne: vi.fn(impl) } as never;
}

describe('createTypesafeClient', () => {
	it('returns null when the key is absent — the normal BUSL self-host state', async () => {
		const { createTypesafeClient } = await import('../src/lib/typesafe');
		expect(createTypesafeClient(undefined)).toBeNull();
		expect(createTypesafeClient('')).toBeNull();
	});

	it('builds a client when a key is present', async () => {
		const { createTypesafeClient } = await import('../src/lib/typesafe');
		expect(createTypesafeClient('ts-test-key')).not.toBeNull();
	});
});

describe('askTypesafe', () => {
	it('returns null for a null client without touching the network', async () => {
		const { askTypesafe } = await import('../src/lib/typesafe');
		expect(await askTypesafe(null, { a: 1 }, { q: {} })).toBeNull();
	});

	it('returns null for an empty question set rather than burning a request', async () => {
		const { askTypesafe } = await import('../src/lib/typesafe');
		const client = stubClient(() => ({ answers: {} }));
		expect(await askTypesafe(client, { a: 1 }, {})).toBeNull();
		expect((client as unknown as { systemOne: { mock: { calls: unknown[] } } }).systemOne.mock.calls).toHaveLength(0);
	});

	it('returns the answers map on success', async () => {
		const { askTypesafe, TYPESAFE_MODEL } = await import('../src/lib/typesafe');
		const client = stubClient(() => ({ answers: { confusability: { type: 'score', score: 1.6 } } }));
		const answers = await askTypesafe(client, { seed: 'example.com' }, { confusability: {} });
		expect(answers).toEqual({ confusability: { type: 'score', score: 1.6 } });
		// The model is pinned; an unpinned model silently re-calibrates every threshold.
		const [request] = (client as unknown as { systemOne: { mock: { calls: [{ model: string }][] } } }).systemOne.mock.calls[0];
		expect(request.model).toBe(TYPESAFE_MODEL);
	});

	it('swallows an SDK rejection and returns null', async () => {
		const { askTypesafe } = await import('../src/lib/typesafe');
		const client = stubClient(() => {
			throw new Error('429 rate limited');
		});
		await expect(askTypesafe(client, {}, { q: {} })).resolves.toBeNull();
	});

	it('returns null when the body carries no answers map', async () => {
		const { askTypesafe } = await import('../src/lib/typesafe');
		expect(await askTypesafe(stubClient(() => ({})), {}, { q: {} })).toBeNull();
		expect(await askTypesafe(stubClient(() => ({ answers: 'nope' })), {}, { q: {} })).toBeNull();
	});

	it('refuses to issue a request when the caller budget is already spent', async () => {
		const { askTypesafe } = await import('../src/lib/typesafe');
		const { createFetchBudget } = await import('../src/lib/fetch-budget');
		const client = stubClient(() => ({ answers: { q: 1 } }));
		// 0ms budget → canIssueRequest() is false (MIN_USEFUL_FETCH_MS guard).
		const budget = createFetchBudget(0);
		expect(await askTypesafe(client, {}, { q: {} }, { budget })).toBeNull();
		expect((client as unknown as { systemOne: { mock: { calls: unknown[] } } }).systemOne.mock.calls).toHaveLength(0);
	});

	it('clamps its timeout to the caller budget rather than outliving it', async () => {
		const { askTypesafe, TYPESAFE_DEFAULT_TIMEOUT_MS } = await import('../src/lib/typesafe');
		const { createFetchBudget } = await import('../src/lib/fetch-budget');
		const client = stubClient(() => ({ answers: { q: 1 } }));
		const budget = createFetchBudget(1_000);
		await askTypesafe(client, {}, { q: {} }, { budget });
		const [, options] = (client as unknown as { systemOne: { mock: { calls: [unknown, { timeout: number }][] } } }).systemOne.mock.calls[0];
		expect(options.timeout).toBeLessThanOrEqual(1_000);
		expect(options.timeout).toBeLessThan(TYPESAFE_DEFAULT_TIMEOUT_MS);
	});
});
