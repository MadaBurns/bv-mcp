// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';

// createSession must not hand out the ID before the KV put is visible: a deferred put let the
// client's next request hit another isolate and 404 (recorded in production 2026-10-25).
describe('createSession awaits the KV session write', () => {
	it('does not resolve before a pending KV put resolves', async () => {
		let releasePut!: () => void;
		const putGate = new Promise<void>((resolve) => {
			releasePut = resolve;
		});
		let putStarted = false;
		const kv = {
			async get() {
				return null;
			},
			async put() {
				putStarted = true;
				await putGate;
			},
			async delete() {},
			async list() {
				return { keys: [] };
			},
		} as unknown as KVNamespace;

		const { createSession } = await import('../src/lib/session');
		let resolved = false;
		// A caller with an execution context (extra arg kept to prove it can no longer defer the write).
		const waitUntil = (_p: Promise<unknown>) => {};
		const pending = (createSession as (...a: unknown[]) => Promise<string>)(kv, undefined, waitUntil).then((id) => {
			resolved = true;
			return id;
		});

		await new Promise((r) => setTimeout(r, 20));
		expect(putStarted).toBe(true);
		expect(resolved).toBe(false);

		releasePut();
		const id = await pending;
		expect(resolved).toBe(true);
		expect(id).toHaveLength(64);
	});

	it('still returns a usable in-memory session when the KV put rejects', async () => {
		const kv = {
			async get() {
				return null;
			},
			async put() {
				throw new Error('KV down');
			},
			async delete() {},
			async list() {
				return { keys: [] };
			},
		} as unknown as KVNamespace;

		const { createSession, validateSession } = await import('../src/lib/session');
		const id = await createSession(kv);
		expect(id).toHaveLength(64);
		expect(await validateSession(id)).toBe(true);
	});
});
