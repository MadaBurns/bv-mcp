// SPDX-License-Identifier: BUSL-1.1

import { afterEach, describe, expect, it } from 'vitest';
// @ts-expect-error cloudflare:test exports are injected by the Workers Vitest pool at runtime.
import { env } from 'cloudflare:test';
import {
	beginIdempotentRequestWithCoordinator,
	bumpVersionIdempotentlyWithCoordinator,
	bumpVersionWithCoordinator,
	claimOnceWithCoordinator,
	checkOAuthDcrBudgetWithCoordinator,
	completeIdempotentRequestWithCoordinator,
	getVersionWithCoordinator,
	hasMarkerWithCoordinator,
	reserveBudgetWithCoordinator,
	resetQuotaCoordinatorState,
	securityStateShardNameForKey,
	setMarkerWithCoordinator,
	setMaxVersionWithCoordinator,
} from '../src/lib/quota-coordinator';

afterEach(async () => {
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

describe('QuotaCoordinator strong-state operations', () => {
	it('atomically enforces the OAuth DCR per-source daily write ceiling', async () => {
		const source = 'a'.repeat(64);
		const limits = { sourceDailyLimit: 2, globalHourlyLimit: 10, globalDailyLimit: 10 };
		expect(await checkOAuthDcrBudgetWithCoordinator(source, limits, env.QUOTA_COORDINATOR)).toEqual({ allowed: true });
		expect(await checkOAuthDcrBudgetWithCoordinator(source, limits, env.QUOTA_COORDINATOR)).toEqual({ allowed: true });
		expect(await checkOAuthDcrBudgetWithCoordinator(source, limits, env.QUOTA_COORDINATOR)).toMatchObject({
			allowed: false,
			retryAfterMs: expect.any(Number),
		});
		// A different source remains usable until the global ceiling is reached.
		expect(await checkOAuthDcrBudgetWithCoordinator('b'.repeat(64), limits, env.QUOTA_COORDINATOR)).toEqual({ allowed: true });
	});

	it('caps distributed source rotation at one atomic global OAuth DCR hourly budget', async () => {
		const limits = { sourceDailyLimit: 10, globalHourlyLimit: 5, globalDailyLimit: 20 };
		const results = await Promise.all(
			Array.from({ length: 20 }, (_, index) =>
				checkOAuthDcrBudgetWithCoordinator(index.toString(16).padStart(64, '0'), limits, env.QUOTA_COORDINATOR),
			),
		);
		expect(results.filter((result) => result?.allowed)).toHaveLength(5);
		expect(results.filter((result) => result && !result.allowed)).toHaveLength(15);
	});

	it('fails closed at the OAuth DCR global daily ceiling even when the hourly allowance is larger', async () => {
		const limits = { sourceDailyLimit: 10, globalHourlyLimit: 20, globalDailyLimit: 3 };
		for (let index = 0; index < 3; index += 1) {
			expect(
				(await checkOAuthDcrBudgetWithCoordinator((index + 100).toString(16).padStart(64, '0'), limits, env.QUOTA_COORDINATOR))?.allowed,
			).toBe(true);
		}
		expect(await checkOAuthDcrBudgetWithCoordinator('f'.repeat(64), limits, env.QUOTA_COORDINATOR)).toMatchObject({
			allowed: false,
			retryAfterMs: expect.any(Number),
		});
	});

	it('atomically enforces a budget under concurrent reservations', async () => {
		const expiresAt = Date.now() + 60_000;
		const results = await Promise.all(
			Array.from({ length: 10 }, () => reserveBudgetWithCoordinator('brand:principal:month', 10, 50, expiresAt, env.QUOTA_COORDINATOR)),
		);

		expect(results.filter((result) => result?.allowed)).toHaveLength(5);
		expect(results.filter((result) => result && !result.allowed)).toHaveLength(5);
		expect(Math.max(...results.map((result) => result?.used ?? 0))).toBe(50);
	});

	it('allows exactly one concurrent claimant', async () => {
		const expiresAt = Date.now() + 60_000;
		const results = await Promise.all(
			Array.from({ length: 20 }, () => claimOnceWithCoordinator('oauth-code:abc', expiresAt, env.QUOTA_COORDINATOR)),
		);
		expect(results.filter((result) => result?.claimed)).toHaveLength(1);
	});

	it('stores expiring deny markers', async () => {
		expect((await hasMarkerWithCoordinator('oauth-jti:abc', env.QUOTA_COORDINATOR))?.present).toBe(false);
		expect((await setMarkerWithCoordinator('oauth-jti:abc', Date.now() + 60_000, env.QUOTA_COORDINATOR))?.present).toBe(true);
		expect((await hasMarkerWithCoordinator('oauth-jti:abc', env.QUOTA_COORDINATOR))?.present).toBe(true);
	});

	it('atomically increments persistent versions', async () => {
		const bumped = await Promise.all(
			Array.from({ length: 20 }, () => bumpVersionWithCoordinator('oauth-subject:abc', 1, env.QUOTA_COORDINATOR)),
		);
		expect(new Set(bumped.map((result) => result?.value)).size).toBe(20);
		expect((await getVersionWithCoordinator('oauth-subject:abc', 1, env.QUOTA_COORDINATOR))?.value).toBe(21);
	});

	it('monotonically raises a persistent version without rolling back on delayed delivery', async () => {
		const key = 'oauth-entitlement-generation:abc';
		expect((await setMaxVersionWithCoordinator(key, 1, 3, env.QUOTA_COORDINATOR))?.value).toBe(3);
		expect((await setMaxVersionWithCoordinator(key, 1, 2, env.QUOTA_COORDINATOR))?.value).toBe(3);
		expect((await setMaxVersionWithCoordinator(key, 1, 5, env.QUOTA_COORDINATOR))?.value).toBe(5);
		expect((await getVersionWithCoordinator(key, 1, env.QUOTA_COORDINATOR))?.value).toBe(5);
	});

	it('atomically bumps and replays a subject version without a poisonable in-progress state', async () => {
		const subjectKey = 'oauth-subject:idempotent-revoke';
		const idempotencyKey = 'request-idempotency:outbox-row-1';
		const requestHash = 'd'.repeat(64);
		const expiresAt = Date.now() + 60_000;
		const calls = await Promise.all(
			Array.from({ length: 20 }, () =>
				bumpVersionIdempotentlyWithCoordinator(subjectKey, idempotencyKey, requestHash, 1, expiresAt, env.QUOTA_COORDINATOR),
			),
		);
		expect(calls).toEqual(Array.from({ length: 20 }, () => ({ state: 'complete', value: 2 })));
		expect((await getVersionWithCoordinator(subjectKey, 1, env.QUOTA_COORDINATOR))?.value).toBe(2);
		expect(
			await bumpVersionIdempotentlyWithCoordinator(subjectKey, idempotencyKey, 'e'.repeat(64), 1, expiresAt, env.QUOTA_COORDINATOR),
		).toEqual({ state: 'conflict' });
		expect((await getVersionWithCoordinator(subjectKey, 1, env.QUOTA_COORDINATOR))?.value).toBe(2);
	});

	it('namespaces identical idempotency keys for different subjects that share one security shard', async () => {
		const firstByShard = new Map<string, string>();
		let pair: [string, string] | undefined;
		for (let i = 0; i < 100 && !pair; i += 1) {
			const key = `oauth-subject:collision-${i}`;
			const shard = securityStateShardNameForKey(key);
			const first = firstByShard.get(shard);
			if (first) pair = [first, key];
			else firstByShard.set(shard, key);
		}
		expect(pair).toBeDefined();
		const [subjectA, subjectB] = pair as [string, string];
		const expiresAt = Date.now() + 60_000;
		const idempotencyKey = 'request-idempotency:same-outbox-key';
		expect(
			await bumpVersionIdempotentlyWithCoordinator(subjectA, idempotencyKey, 'f'.repeat(64), 1, expiresAt, env.QUOTA_COORDINATOR),
		).toEqual({ state: 'complete', value: 2 });
		expect(
			await bumpVersionIdempotentlyWithCoordinator(subjectB, idempotencyKey, 'a'.repeat(64), 1, expiresAt, env.QUOTA_COORDINATOR),
		).toEqual({ state: 'complete', value: 2 });
	});

	it('allows exactly one idempotency execution and replays its terminal result', async () => {
		const coordinationKey = 'request-idempotency:test';
		const requestHash = 'a'.repeat(64);
		const expiresAt = Date.now() + 60_000;
		const starts = await Promise.all(
			Array.from({ length: 20 }, () =>
				beginIdempotentRequestWithCoordinator(coordinationKey, requestHash, expiresAt, env.QUOTA_COORDINATOR),
			),
		);
		expect(starts.filter((result) => result?.state === 'started')).toHaveLength(1);
		expect(starts.filter((result) => result?.state === 'in_progress')).toHaveLength(19);

		expect(
			await completeIdempotentRequestWithCoordinator(
				coordinationKey,
				requestHash,
				JSON.stringify({ ok: true, operationId: 'op-1' }),
				env.QUOTA_COORDINATOR,
			),
		).toEqual({ completed: true });
		expect(await beginIdempotentRequestWithCoordinator(coordinationKey, requestHash, expiresAt, env.QUOTA_COORDINATOR)).toEqual({
			state: 'complete',
			result: JSON.stringify({ ok: true, operationId: 'op-1' }),
		});
	});

	it('rejects reuse of one idempotency key for a different request hash', async () => {
		const coordinationKey = 'request-idempotency:conflict';
		const expiresAt = Date.now() + 60_000;
		expect(await beginIdempotentRequestWithCoordinator(coordinationKey, 'b'.repeat(64), expiresAt, env.QUOTA_COORDINATOR)).toEqual({
			state: 'started',
		});
		expect(await beginIdempotentRequestWithCoordinator(coordinationKey, 'c'.repeat(64), expiresAt, env.QUOTA_COORDINATOR)).toEqual({
			state: 'conflict',
		});
	});

	it('uses frozen security shards independent of quota routing', () => {
		const name = securityStateShardNameForKey('oauth-code:abc');
		expect(name).toMatch(/^security-state-shard-\d+$/);
		expect(name).toBe(securityStateShardNameForKey('oauth-code:abc'));
	});

	it('routes strong operations to a security shard while quota sharding is disabled', async () => {
		const names: string[] = [];
		const namespace = {
			getByName(name: string) {
				names.push(name);
				return { dispatch: async () => ({ claimed: true }) };
			},
		} as unknown as DurableObjectNamespace<import('../src/lib/quota-coordinator').QuotaCoordinator>;
		await claimOnceWithCoordinator('oauth-code:routing-test', Date.now() + 60_000, namespace);
		expect(names).toEqual([securityStateShardNameForKey('oauth-code:routing-test')]);
	});
});
