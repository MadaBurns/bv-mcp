// SPDX-License-Identifier: BUSL-1.1

import { afterEach, describe, expect, it, vi } from 'vitest';
// @ts-expect-error cloudflare:test exports are injected by the Workers Vitest pool at runtime.
import { env } from 'cloudflare:test';
import { enforceBrandAuditQuota } from '../src/lib/brand-audit-quota';
import { resetQuotaCoordinatorState } from '../src/lib/quota-coordinator';

afterEach(async () => {
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

describe('brand-audit monthly quota atomicity', () => {
	it('does not exceed the tier budget under concurrency', async () => {
		const kv = { get: vi.fn().mockResolvedValue(null), put: vi.fn().mockResolvedValue(undefined) };
		const results = await Promise.all(
			Array.from({ length: 10 }, () =>
				enforceBrandAuditQuota({
					kv,
					quotaCoordinator: env.QUOTA_COORDINATOR,
					principalId: 'paid-principal',
					tier: 'developer',
					count: 10,
				}),
			),
		);
		expect(results.filter((result) => result.allowed)).toHaveLength(5);
		expect(results.filter((result) => !result.allowed)).toHaveLength(5);
	});

	it('fails closed when strong state is unavailable', async () => {
		const result = await enforceBrandAuditQuota({
			principalId: 'paid-principal',
			tier: 'developer',
			count: 1,
		});
		expect(result.allowed).toBe(false);
		expect(result.remaining).toBe(0);
	});

	it('keeps KV as a non-authoritative mirror', async () => {
		const kv = { get: vi.fn().mockResolvedValue(null), put: vi.fn().mockRejectedValue(new Error('KV unavailable')) };
		const result = await enforceBrandAuditQuota({
			kv,
			quotaCoordinator: env.QUOTA_COORDINATOR,
			principalId: 'paid-principal',
			tier: 'developer',
			count: 1,
		});
		expect(result.allowed).toBe(true);
		expect(kv.get).toHaveBeenCalled();
	});
});
