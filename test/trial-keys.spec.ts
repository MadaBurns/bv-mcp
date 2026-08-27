// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi, afterEach } from 'vitest';
// @ts-expect-error cloudflare:test exports are injected by the Workers Vitest pool at runtime.
import { env } from 'cloudflare:test';

afterEach(() => {
	vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Helper: build a mock KV namespace
// ---------------------------------------------------------------------------

function createMockKv(store: Map<string, { value: string; expiration?: number }> = new Map()) {
	return {
		get: vi.fn(async (key: string) => store.get(key)?.value ?? null),
		put: vi.fn(async (key: string, value: string, opts?: { expirationTtl?: number }) => {
			store.set(key, { value, expiration: opts?.expirationTtl });
		}),
		delete: vi.fn(async (key: string) => {
			store.delete(key);
		}),
		list: vi.fn(async (opts?: { prefix?: string; limit?: number }) => {
			const prefix = opts?.prefix ?? '';
			const limit = opts?.limit ?? 100;
			const keys = Array.from(store.keys())
				.filter((k) => k.startsWith(prefix))
				.slice(0, limit)
				.map((name) => ({ name }));
			return { keys };
		}),
	} as unknown as KVNamespace;
}

// ---------------------------------------------------------------------------
// createTrialKey
// ---------------------------------------------------------------------------

describe('trial-keys', () => {
	describe('createTrialKey', () => {
		it('generates a 64-char hex key and stores record in KV', async () => {
			const { createTrialKey } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			const result = await createTrialKey(kv, { label: 'Test Customer' });

			expect(result.rawKey).toMatch(/^[0-9a-f]{64}$/);
			expect(result.hash).toMatch(/^[0-9a-f]{64}$/);
			expect(result.hash).not.toBe(result.rawKey);
			expect(result.record.tier).toBe('developer');
			expect(result.record.maxUses).toBe(1000);
			expect(result.record.currentUses).toBe(0);
			expect(result.record.label).toBe('Test Customer');
			expect(kv.put).toHaveBeenCalledOnce();
		});

		it('uses custom options when provided', async () => {
			const { createTrialKey } = await import('../src/lib/trial-keys');
			const kv = createMockKv();

			const result = await createTrialKey(kv, {
				label: 'Enterprise Demo',
				tier: 'enterprise',
				expiresInDays: 30,
				maxUses: 5000,
			});

			expect(result.record.tier).toBe('enterprise');
			expect(result.record.maxUses).toBe(5000);
			expect(result.record.label).toBe('Enterprise Demo');
			// Verify expiry is approximately 30 days in the future
			const expectedExpiry = Date.now() + 30 * 24 * 60 * 60 * 1000;
			expect(result.record.expiresAt).toBeGreaterThan(expectedExpiry - 5000);
			expect(result.record.expiresAt).toBeLessThan(expectedExpiry + 5000);
		});

		it('truncates long labels to 200 chars', async () => {
			const { createTrialKey } = await import('../src/lib/trial-keys');
			const kv = createMockKv();

			const result = await createTrialKey(kv, { label: 'A'.repeat(300) });
			expect(result.record.label.length).toBe(200);
		});

		it('rejects owner-tier trial keys', async () => {
			const { createTrialKey } = await import('../src/lib/trial-keys');
			const kv = createMockKv();

			await expect(createTrialKey(kv, { label: 'Owner Trial', tier: 'owner' })).rejects.toThrow(
				'Trial keys cannot use owner tier',
			);
		});
	});

	// ---------------------------------------------------------------------------
	// resolveTrialKey
	// ---------------------------------------------------------------------------

	describe('resolveTrialKey', () => {
		it('returns tier for a valid trial key', async () => {
			const { createTrialKey, resolveTrialKey } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			const { hash } = await createTrialKey(kv, { label: 'Test' });
			const result = await resolveTrialKey(kv, hash, undefined, env.QUOTA_COORDINATOR);

			expect(result).not.toBeNull();
			expect(result!.authenticated).toBe(true);
			if (result!.authenticated) {
				expect(result!.tier).toBe('developer');
				expect(result!.trialInfo.usesRemaining).toBe(999);
				expect(result!.trialInfo.label).toBe('Test');
			}
		});

		it('increments currentUses on each resolution', async () => {
			const { createTrialKey, resolveTrialKey } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			const { hash } = await createTrialKey(kv, { label: 'Test', maxUses: 5 });

			// Call 3 times
			await resolveTrialKey(kv, hash, undefined, env.QUOTA_COORDINATOR);
			await resolveTrialKey(kv, hash, undefined, env.QUOTA_COORDINATOR);
			const third = await resolveTrialKey(kv, hash, undefined, env.QUOTA_COORDINATOR);

			expect(third).not.toBeNull();
			expect(third!.authenticated).toBe(true);
			if (third!.authenticated) {
				expect(third!.trialInfo.usesRemaining).toBe(2);
			}
		});

		it('returns exhausted when usage limit reached', async () => {
			const { createTrialKey, resolveTrialKey } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			const { hash } = await createTrialKey(kv, { label: 'Test', maxUses: 2 });

			await resolveTrialKey(kv, hash, undefined, env.QUOTA_COORDINATOR); // use 1
			await resolveTrialKey(kv, hash, undefined, env.QUOTA_COORDINATOR); // use 2
			const third = await resolveTrialKey(kv, hash, undefined, env.QUOTA_COORDINATOR); // exhausted

			expect(third).not.toBeNull();
			expect(third!.authenticated).toBe(false);
			if (!third!.authenticated) {
				expect(third!.reason).toBe('exhausted');
			}
		});

		it('enforces maxUses atomically under concurrent resolution', async () => {
			const { createTrialKey, resolveTrialKey } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);
			const { hash } = await createTrialKey(kv, { label: 'Concurrent', maxUses: 5 });

			const results = await Promise.all(
				Array.from({ length: 20 }, () => resolveTrialKey(kv, hash, undefined, env.QUOTA_COORDINATOR)),
			);
			expect(results.filter((result) => result?.authenticated)).toHaveLength(5);
			expect(results.filter((result) => result && !result.authenticated && result.reason === 'exhausted')).toHaveLength(15);
		});

		it('returns expired when time limit passed', async () => {
			const { resolveTrialKey } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			// Manually insert an expired record
			const expiredRecord = {
				tier: 'developer',
				expiresAt: Date.now() - 1000, // 1 second ago
				maxUses: 1000,
				currentUses: 0,
				label: 'Expired Test',
				createdAt: Date.now() - 86400000,
			};
			store.set('trial:abc123', { value: JSON.stringify(expiredRecord) });

			const result = await resolveTrialKey(kv, 'abc123', undefined, env.QUOTA_COORDINATOR);
			expect(result).not.toBeNull();
			expect(result!.authenticated).toBe(false);
			if (!result!.authenticated) {
				expect(result!.reason).toBe('expired');
			}
		});

		it('returns null for unknown hash', async () => {
			const { resolveTrialKey } = await import('../src/lib/trial-keys');
			const kv = createMockKv();

			const result = await resolveTrialKey(kv, 'nonexistent', undefined, env.QUOTA_COORDINATOR);
			expect(result).toBeNull();
		});

		it('returns null for malformed KV data', async () => {
			const { resolveTrialKey } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			store.set('trial:badhash', { value: 'not-json' });
			const result = await resolveTrialKey(kv, 'badhash', undefined, env.QUOTA_COORDINATOR);
			expect(result).toBeNull();
		});

		it('returns null when KV.get throws', async () => {
			const { resolveTrialKey } = await import('../src/lib/trial-keys');
			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV failure')),
				put: vi.fn(),
				delete: vi.fn(),
				list: vi.fn(),
			} as unknown as KVNamespace;

			const result = await resolveTrialKey(kv, 'somehash', undefined, env.QUOTA_COORDINATOR);
			expect(result).toBeNull();
		});
	});

	// ---------------------------------------------------------------------------
	// getTrialKeyStatus
	// ---------------------------------------------------------------------------

	describe('getTrialKeyStatus', () => {
		it('returns the record for an existing key', async () => {
			const { createTrialKey, getTrialKeyStatus } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			const { hash, record } = await createTrialKey(kv, { label: 'Status Test' });
			const status = await getTrialKeyStatus(kv, hash);

			expect(status).not.toBeNull();
			expect(status!.label).toBe('Status Test');
			expect(status!.tier).toBe(record.tier);
		});

		it('returns null for nonexistent key', async () => {
			const { getTrialKeyStatus } = await import('../src/lib/trial-keys');
			const kv = createMockKv();

			const status = await getTrialKeyStatus(kv, 'nonexistent');
			expect(status).toBeNull();
		});
	});

	// ---------------------------------------------------------------------------
	// revokeTrialKey
	// ---------------------------------------------------------------------------

	describe('revokeTrialKey', () => {
		it('deletes an existing key and returns true', async () => {
			const { createTrialKey, revokeTrialKey, resolveTrialKey } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			const { hash } = await createTrialKey(kv, { label: 'Revoke Test' });
			const revoked = await revokeTrialKey(kv, hash, env.QUOTA_COORDINATOR);

			expect(revoked).toBe(true);

			// Should no longer resolve
			const result = await resolveTrialKey(kv, hash, undefined, env.QUOTA_COORDINATOR);
			expect(result).toBeNull();
		});

		it('keeps a revoked key denied when a stale KV replica serves and rewrites its old record', async () => {
			const { createTrialKey, revokeTrialKey, resolveTrialKey } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			const { hash } = await createTrialKey(kv, { label: 'Stale Replica Test' });
			const staleRecord = store.get(`trial:${hash}`);
			expect(staleRecord).toBeDefined();

			await revokeTrialKey(kv, hash, env.QUOTA_COORDINATOR);
			store.set(`trial:${hash}`, staleRecord!);

			const result = await resolveTrialKey(kv, hash, undefined, env.QUOTA_COORDINATOR);
			expect(result).toEqual({ authenticated: false, reason: 'revoked' });
			expect(store.get(`trial:${hash}`)).toEqual(staleRecord);
		});

		it('commits the strong deny when the revocation-side KV replica reports the key missing', async () => {
			const { createTrialKey, revokeTrialKey, resolveTrialKey } = await import('../src/lib/trial-keys');
			const staleReplicaStore = new Map<string, { value: string; expiration?: number }>();
			const staleReplica = createMockKv(staleReplicaStore);
			const { hash } = await createTrialKey(staleReplica, { label: 'Revocation Read Miss' });

			// Model eventual consistency: the revocation colo has not observed the
			// create, while another replica can still serve the live record.
			const revocationReplica = createMockKv();
			await expect(revokeTrialKey(revocationReplica, hash, env.QUOTA_COORDINATOR)).resolves.toBe(false);
			expect(revocationReplica.delete).toHaveBeenCalledWith(`trial:${hash}`);

			await expect(resolveTrialKey(staleReplica, hash, undefined, env.QUOTA_COORDINATOR)).resolves.toEqual({
				authenticated: false,
				reason: 'revoked',
			});
		});

		it('fails closed without deleting KV when strong revocation state is unavailable', async () => {
			const { createTrialKey, revokeTrialKey } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);
			const { hash } = await createTrialKey(kv, { label: 'Unavailable Revocation Test' });

			await expect(revokeTrialKey(kv, hash)).rejects.toThrow('revocation state is unavailable');
			expect(store.has(`trial:${hash}`)).toBe(true);
		});

		it('returns false for nonexistent key', async () => {
			const { revokeTrialKey } = await import('../src/lib/trial-keys');
			const kv = createMockKv();

			const revoked = await revokeTrialKey(kv, 'nonexistent', env.QUOTA_COORDINATOR);
			expect(revoked).toBe(false);
		});
	});

	// ---------------------------------------------------------------------------
	// listTrialKeys
	// ---------------------------------------------------------------------------

	describe('listTrialKeys', () => {
		it('lists all trial keys', async () => {
			const { createTrialKey, listTrialKeys } = await import('../src/lib/trial-keys');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			await createTrialKey(kv, { label: 'Key 1' });
			await createTrialKey(kv, { label: 'Key 2' });
			await createTrialKey(kv, { label: 'Key 3' });

			const keys = await listTrialKeys(kv);
			expect(keys).toHaveLength(3);
			expect(keys.every((k) => k.hash.length === 64)).toBe(true);
		});

		it('returns empty array when no trial keys exist', async () => {
			const { listTrialKeys } = await import('../src/lib/trial-keys');
			const kv = createMockKv();

			const keys = await listTrialKeys(kv);
			expect(keys).toHaveLength(0);
		});
	});

	// ---------------------------------------------------------------------------
	// resolveTier integration (trial key in cascade)
	// ---------------------------------------------------------------------------

	describe('resolveTier integration', () => {
		it('resolves trial key when KV tier cache misses', async () => {
			const { resolveTier } = await import('../src/lib/tier-auth');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			// Create a trial key directly in the store
			const { createTrialKey } = await import('../src/lib/trial-keys');
			const { rawKey, hash } = await createTrialKey(kv, { label: 'Cascade Test' });

			// resolveTier should find the trial key (step 2) after cache miss (step 1)
			const result = await resolveTier(rawKey, { RATE_LIMIT: kv, QUOTA_COORDINATOR: env.QUOTA_COORDINATOR }, undefined, 'https://example.com/mcp');
			expect(result.authenticated).toBe(true);
			expect(result.tier).toBe('developer');
			expect(result.keyHash).toBe(hash);
		});

		it('does not positive-cache a trial authorization', async () => {
			const { resolveTier } = await import('../src/lib/tier-auth');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			const { createTrialKey } = await import('../src/lib/trial-keys');
			const { rawKey, hash } = await createTrialKey(kv, { label: 'Cache TTL Test' });

			await resolveTier(rawKey, { RATE_LIMIT: kv, QUOTA_COORDINATOR: env.QUOTA_COORDINATOR }, undefined, 'https://example.com/mcp');

			// Every request must consume one atomic use; a tier cache hit would bypass it.
			const cached = store.get(`tier:${hash}`);
			expect(cached).toBeUndefined();
		});

		it('returns unauthenticated for expired trial key', async () => {
			const { resolveTier } = await import('../src/lib/tier-auth');
			const store = new Map<string, { value: string; expiration?: number }>();
			const kv = createMockKv(store);

			// Insert an expired trial key
			const expiredRecord = {
				tier: 'developer',
				expiresAt: Date.now() - 1000,
				maxUses: 1000,
				currentUses: 0,
				label: 'Expired',
				createdAt: Date.now() - 86400000,
			};

			// We need to know the hash for the token. Hash it.
			const tokenHash = Array.from(
				new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('expired-token'))),
			)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');

			store.set(`trial:${tokenHash}`, { value: JSON.stringify(expiredRecord) });

			const result = await resolveTier('expired-token', { RATE_LIMIT: kv }, undefined, 'https://example.com/mcp');
			expect(result.authenticated).toBe(false);
		});

		it('falls through to BV_API_KEY when no trial key exists', async () => {
			const { resolveTier } = await import('../src/lib/tier-auth');
			const kv = createMockKv();

			const result = await resolveTier(
				'my-static-key',
				{
					RATE_LIMIT: kv,
					BV_API_KEY: 'my-static-key',
				},
				undefined,
				'https://example.com/mcp',
			);
			expect(result.authenticated).toBe(true);
			expect(result.tier).toBe('owner');
		});
	});
});
