// SPDX-License-Identifier: BUSL-1.1
//
// Handler-body coverage for GET/DELETE /internal/trial-keys/:hash and GET /internal/trial-keys.
// The auth contract is owned by test/internal-trial-keys-auth.spec.ts; this file drives the
// authorised path (BV_MCP_OAUTH_MINT_KEY bearer, the capability trialKeysAuthGate wants) through
// every early return and the success body of each handler.

import { env as workerEnv } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { resetQuotaCoordinatorState } from '../src/lib/quota-coordinator';

const MINT_KEY = 'trial-mint-capability-test-key-32-bytes';
const AUTH = { authorization: `Bearer ${MINT_KEY}` };
const HASH = 'a'.repeat(64);
const DAY_MS = 24 * 60 * 60 * 1000;

afterEach(async () => {
	vi.restoreAllMocks();
	await resetQuotaCoordinatorState(workerEnv.QUOTA_COORDINATOR);
});

function createMockKv(store: Map<string, string> = new Map()) {
	return {
		get: vi.fn(async (key: string) => store.get(key) ?? null),
		put: vi.fn(async (key: string, value: string) => {
			store.set(key, value);
		}),
		delete: vi.fn(async (key: string) => {
			store.delete(key);
		}),
		list: vi.fn(async (opts?: { prefix?: string; limit?: number }) => ({
			keys: Array.from(store.keys())
				.filter((k) => k.startsWith(opts?.prefix ?? ''))
				.slice(0, opts?.limit ?? 100)
				.map((name) => ({ name })),
		})),
	} as unknown as KVNamespace;
}

function record(overrides: Partial<Record<string, unknown>> = {}) {
	return JSON.stringify({
		tier: 'developer',
		expiresAt: Date.now() + 10 * DAY_MS,
		maxUses: 100,
		currentUses: 25,
		label: 'Acme trial',
		createdAt: Date.now() - DAY_MS,
		...overrides,
	});
}

describe('GET /internal/trial-keys/:hash handler', () => {
	it('500s when the RATE_LIMIT KV namespace is not bound', async () => {
		const { internalRoutes } = await import('../src/internal');
		const res = await internalRoutes.request(`/trial-keys/${HASH}`, { headers: AUTH }, { BV_MCP_OAUTH_MINT_KEY: MINT_KEY });
		expect(res.status).toBe(500);
		expect(await res.json()).toEqual({ error: 'RATE_LIMIT KV namespace not configured' });
	});

	it('400s on a hash that is not 64 lowercase hex chars (no KV read)', async () => {
		const { internalRoutes } = await import('../src/internal');
		const kv = createMockKv();
		const res = await internalRoutes.request('/trial-keys/not-a-hash', { headers: AUTH }, { BV_MCP_OAUTH_MINT_KEY: MINT_KEY, RATE_LIMIT: kv });
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({ error: 'Invalid hash format' });
		expect(kv.get).not.toHaveBeenCalled();
	});

	it('404s when no trial record exists for the hash', async () => {
		const { internalRoutes } = await import('../src/internal');
		const res = await internalRoutes.request(
			`/trial-keys/${HASH}`,
			{ headers: AUTH },
			{ BV_MCP_OAUTH_MINT_KEY: MINT_KEY, RATE_LIMIT: createMockKv() },
		);
		expect(res.status).toBe(404);
		expect(await res.json()).toEqual({ error: 'Trial key not found' });
	});

	it('returns the record with live expiry, exhaustion and remaining-use fields', async () => {
		const { internalRoutes } = await import('../src/internal');
		const kv = createMockKv(new Map([[`trial:${HASH}`, record()]]));
		const res = await internalRoutes.request(`/trial-keys/${HASH}`, { headers: AUTH }, { BV_MCP_OAUTH_MINT_KEY: MINT_KEY, RATE_LIMIT: kv });
		expect(res.status).toBe(200);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body).toMatchObject({
			label: 'Acme trial',
			tier: 'developer',
			expired: false,
			exhausted: false,
			usesRemaining: 75,
			daysRemaining: 10,
		});
	});

	it('flags an expired, exhausted record and floors remaining counters at zero', async () => {
		const { internalRoutes } = await import('../src/internal');
		const kv = createMockKv(new Map([[`trial:${HASH}`, record({ expiresAt: Date.now() - 2 * DAY_MS, currentUses: 130 })]]));
		const res = await internalRoutes.request(`/trial-keys/${HASH}`, { headers: AUTH }, { BV_MCP_OAUTH_MINT_KEY: MINT_KEY, RATE_LIMIT: kv });
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ expired: true, exhausted: true, usesRemaining: 0, daysRemaining: 0 });
	});
});

describe('DELETE /internal/trial-keys/:hash handler', () => {
	it('500s when the RATE_LIMIT KV namespace is not bound', async () => {
		const { internalRoutes } = await import('../src/internal');
		const res = await internalRoutes.request(`/trial-keys/${HASH}`, { method: 'DELETE', headers: AUTH }, { BV_MCP_OAUTH_MINT_KEY: MINT_KEY });
		expect(res.status).toBe(500);
	});

	it('400s on an invalid hash without touching KV', async () => {
		const { internalRoutes } = await import('../src/internal');
		const kv = createMockKv();
		const res = await internalRoutes.request(
			'/trial-keys/XYZ',
			{ method: 'DELETE', headers: AUTH },
			{ BV_MCP_OAUTH_MINT_KEY: MINT_KEY, RATE_LIMIT: kv, QUOTA_COORDINATOR: workerEnv.QUOTA_COORDINATOR },
		);
		expect(res.status).toBe(400);
		expect(kv.delete).not.toHaveBeenCalled();
	});

	it('revokes an existing key: commits the deny marker, deletes the KV record, returns deleted:true', async () => {
		const { internalRoutes } = await import('../src/internal');
		const store = new Map([[`trial:${HASH}`, record()]]);
		const kv = createMockKv(store);
		const res = await internalRoutes.request(
			`/trial-keys/${HASH}`,
			{ method: 'DELETE', headers: AUTH },
			{ BV_MCP_OAUTH_MINT_KEY: MINT_KEY, RATE_LIMIT: kv, QUOTA_COORDINATOR: workerEnv.QUOTA_COORDINATOR },
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ deleted: true });
		expect(store.has(`trial:${HASH}`)).toBe(false);
	});

	it('returns deleted:false (still revoking) when the key was already absent', async () => {
		const { internalRoutes } = await import('../src/internal');
		const kv = createMockKv();
		const res = await internalRoutes.request(
			`/trial-keys/${HASH}`,
			{ method: 'DELETE', headers: AUTH },
			{ BV_MCP_OAUTH_MINT_KEY: MINT_KEY, RATE_LIMIT: kv, QUOTA_COORDINATOR: workerEnv.QUOTA_COORDINATOR },
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ deleted: false });
	});

	it('fails closed with 503 + Retry-After when strong revocation state is unavailable (no QUOTA_COORDINATOR)', async () => {
		const { internalRoutes } = await import('../src/internal');
		const store = new Map([[`trial:${HASH}`, record()]]);
		const kv = createMockKv(store);
		const res = await internalRoutes.request(
			`/trial-keys/${HASH}`,
			{ method: 'DELETE', headers: AUTH },
			{ BV_MCP_OAUTH_MINT_KEY: MINT_KEY, RATE_LIMIT: kv },
		);
		expect(res.status).toBe(503);
		expect(await res.json()).toEqual({ error: 'trial_revocation_state_unavailable' });
		expect(res.headers.get('Retry-After')).toBe('30');
		expect(res.headers.get('Cache-Control')).toBe('no-store');
		// The KV mirror must NOT be deleted when the authoritative marker could not be committed.
		expect(store.has(`trial:${HASH}`)).toBe(true);
	});
});

describe('GET /internal/trial-keys (list) handler', () => {
	it('500s when the RATE_LIMIT KV namespace is not bound', async () => {
		const { internalRoutes } = await import('../src/internal');
		const res = await internalRoutes.request('/trial-keys', { headers: AUTH }, { BV_MCP_OAUTH_MINT_KEY: MINT_KEY });
		expect(res.status).toBe(500);
	});

	it('lists every readable trial key with derived status fields and skips unreadable records', async () => {
		const { internalRoutes } = await import('../src/internal');
		const other = 'b'.repeat(64);
		const broken = 'c'.repeat(64);
		const kv = createMockKv(
			new Map([
				[`trial:${HASH}`, record()],
				[`trial:${other}`, record({ currentUses: 100, expiresAt: Date.now() - DAY_MS })],
				[`trial:${broken}`, 'not json'],
			]),
		);
		const res = await internalRoutes.request('/trial-keys', { headers: AUTH }, { BV_MCP_OAUTH_MINT_KEY: MINT_KEY, RATE_LIMIT: kv });
		expect(res.status).toBe(200);
		const body = (await res.json()) as { total: number; keys: Array<Record<string, unknown>> };
		expect(body.total).toBe(2);
		const byHash = Object.fromEntries(body.keys.map((k) => [k.hash as string, k]));
		expect(byHash[HASH]).toMatchObject({ expired: false, exhausted: false, usesRemaining: 75 });
		expect(byHash[other]).toMatchObject({ expired: true, exhausted: true, usesRemaining: 0 });
		expect(byHash[broken]).toBeUndefined();
	});

	it('passes ?limit to KV list, capped at 1000 (default 100)', async () => {
		const { internalRoutes } = await import('../src/internal');
		const kv = createMockKv();
		await internalRoutes.request('/trial-keys?limit=5000', { headers: AUTH }, { BV_MCP_OAUTH_MINT_KEY: MINT_KEY, RATE_LIMIT: kv });
		expect(kv.list).toHaveBeenLastCalledWith({ prefix: 'trial:', limit: 1000 });
		await internalRoutes.request('/trial-keys', { headers: AUTH }, { BV_MCP_OAUTH_MINT_KEY: MINT_KEY, RATE_LIMIT: kv });
		expect(kv.list).toHaveBeenLastCalledWith({ prefix: 'trial:', limit: 100 });
	});
});
