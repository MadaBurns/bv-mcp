// SPDX-License-Identifier: BUSL-1.1

/**
 * Pins which Durable Object NAME every request kind routes to. The name decides quota sharding, so a
 * change here silently splits counters across instances. Routing is observed through the public
 * `*WithCoordinator` wrappers against a recording namespace stub.
 */
import { describe, expect, it } from 'vitest';
import {
	SINGLETON_ROUTING,
	bumpVersionIdempotentlyWithCoordinator,
	bumpVersionWithCoordinator,
	beginIdempotentRequestWithCoordinator,
	checkDistinctDomainDailyLimitWithCoordinator,
	checkGlobalDailyLimitWithCoordinator,
	checkOAuthDcrBudgetWithCoordinator,
	checkScopedRateLimitWithCoordinator,
	checkSessionCreateRateLimitWithCoordinator,
	checkToolDailyRateLimitWithCoordinator,
	claimOnceWithCoordinator,
	completeIdempotentRequestWithCoordinator,
	evaluateQuotaWithCoordinator,
	getVersionWithCoordinator,
	hasMarkerWithCoordinator,
	releaseIdempotentRequestWithCoordinator,
	reserveBudgetWithCoordinator,
	resetQuotaCoordinatorState,
	securityStateShardNameForKey,
	setMarkerWithCoordinator,
	setMaxVersionWithCoordinator,
	shardNameForKey,
	type QuotaCoordinator,
	type ShardRouting,
} from '../src/lib/quota-coordinator';

const SINGLETON = 'global-quota-coordinator';
const SALT = 'pepper';
const HASH = 'b'.repeat(64);
const ON: ShardRouting = { enabled: true, salt: SALT };
const OFF: ShardRouting = { enabled: false, salt: SALT };

/** Namespace stub that records the DO name asked for; each stub echoes an RPC `dispatch`. */
function recordingNamespace(): { namespace: DurableObjectNamespace<QuotaCoordinator>; names: string[] } {
	const names: string[] = [];
	const namespace = {
		getByName(name: string) {
			names.push(name);
			return { dispatch: async () => undefined };
		},
	} as unknown as DurableObjectNamespace<QuotaCoordinator>;
	return { namespace, names };
}

type Call = (namespace: DurableObjectNamespace<QuotaCoordinator>, routing: ShardRouting) => Promise<unknown>;

/** Security-state kinds route by coordinationKey on the frozen security sharding scheme. */
const SECURITY_CALLS: Array<[string, Call]> = [
	['reserve-budget', (ns) => reserveBudgetWithCoordinator('sec-key', 1, 10, 9_999_999_999_999, ns)],
	['claim-once', (ns) => claimOnceWithCoordinator('sec-key', 9_999_999_999_999, ns)],
	['marker-set', (ns) => setMarkerWithCoordinator('sec-key', 9_999_999_999_999, ns)],
	['marker-has', (ns) => hasMarkerWithCoordinator('sec-key', ns)],
	['version-get', (ns) => getVersionWithCoordinator('sec-key', 1, ns)],
	['version-bump', (ns) => bumpVersionWithCoordinator('sec-key', 1, ns)],
	['version-set-max', (ns) => setMaxVersionWithCoordinator('sec-key', 1, 2, ns)],
	['version-bump-idempotent', (ns) => bumpVersionIdempotentlyWithCoordinator('sec-key', 'idem-key', HASH, 1, 9_999_999_999_999, ns)],
	['idempotency-begin', (ns) => beginIdempotentRequestWithCoordinator('sec-key', HASH, 9_999_999_999_999, ns)],
	['idempotency-complete', (ns) => completeIdempotentRequestWithCoordinator('sec-key', HASH, 'ok', ns)],
	['idempotency-release', (ns) => releaseIdempotentRequestWithCoordinator('sec-key', HASH, ns)],
];

/** Quota kinds: [label, call, key the shard is derived from, or null when pinned to the singleton]. */
const QUOTA_CALLS: Array<[string, Call, string | null]> = [
	['scoped-rate', (ns, r) => checkScopedRateLimitWithCoordinator('203.0.113.5', 'tools', 5, 50, ns, r), '203.0.113.5'],
	['session-create', (ns, r) => checkSessionCreateRateLimitWithCoordinator('203.0.113.6', 5, 60_000, ns, r), '203.0.113.6'],
	['tool-daily', (ns, r) => checkToolDailyRateLimitWithCoordinator('principal-a', 'check_spf', 5, ns, r), 'principal-a'],
	['distinct-domain-daily', (ns, r) => checkDistinctDomainDailyLimitWithCoordinator('principal-b', 'fp', 5, ns, r), 'principal-b'],
	[
		'evaluate',
		(ns, r) => evaluateQuotaWithCoordinator('shard-key-c', [{ kind: 'tool-daily', principalId: 'p', toolName: 't', limit: 1 }], ns, r),
		'shard-key-c',
	],
	// Global counters are pinned to the singleton even with sharding on: the cost ceiling is never approximated.
	['global-daily', (ns) => checkGlobalDailyLimitWithCoordinator(100, ns), null],
	[
		'oauth-dcr-write',
		(ns) => checkOAuthDcrBudgetWithCoordinator('c'.repeat(64), { sourceDailyLimit: 1, globalHourlyLimit: 1, globalDailyLimit: 1 }, ns),
		null,
	],
];

describe('routingNameForPayload: security-state kinds', () => {
	for (const [label, call] of SECURITY_CALLS) {
		it(`${label} routes by coordinationKey on the frozen security shard, regardless of quota flags`, async () => {
			const expected = securityStateShardNameForKey('sec-key');
			for (const routing of [SINGLETON_ROUTING, OFF, ON]) {
				const { namespace, names } = recordingNamespace();
				await call(namespace, routing);
				expect(names).toEqual([expected]);
			}
		});
	}

	it('the idempotent version bump routes by the subject key, not the idempotency key', async () => {
		const { namespace, names } = recordingNamespace();
		await bumpVersionIdempotentlyWithCoordinator('subject-key', 'other-idem-key', HASH, 1, 9_999_999_999_999, namespace);
		expect(names).toEqual([securityStateShardNameForKey('subject-key')]);
		expect(names[0]).not.toBe(SINGLETON);
	});
});

describe('routingNameForPayload: quota kinds', () => {
	for (const [label, call, key] of QUOTA_CALLS) {
		it(`${label} stays on the singleton when quota sharding is off`, async () => {
			for (const routing of [SINGLETON_ROUTING, OFF]) {
				const { namespace, names } = recordingNamespace();
				await call(namespace, routing);
				expect(names).toEqual([SINGLETON]);
			}
		});

		it(`${label} routes ${key === null ? 'to the singleton' : 'by its scoping key onto a salted shard'} when sharding is on`, async () => {
			const { namespace, names } = recordingNamespace();
			await call(namespace, ON);
			expect(names).toEqual([key === null ? SINGLETON : shardNameForKey(key, SALT)]);
		});
	}

	// A null shard field is not "pinned to the singleton": the base routed it through shardNameForKey, so must we.
	const NULL_FIELD_CALLS: Array<[string, Call]> = [
		['scoped-rate', (ns, r) => checkScopedRateLimitWithCoordinator(null as never, 'tools', 5, 50, ns, r)],
		['session-create', (ns, r) => checkSessionCreateRateLimitWithCoordinator(null as never, 5, 60_000, ns, r)],
		['tool-daily', (ns, r) => checkToolDailyRateLimitWithCoordinator(null as never, 'check_spf', 5, ns, r)],
		['distinct-domain-daily', (ns, r) => checkDistinctDomainDailyLimitWithCoordinator(null as never, 'fp', 5, ns, r)],
		['evaluate', (ns, r) => evaluateQuotaWithCoordinator(null as never, [{ kind: 'tool-daily', principalId: 'p', toolName: 't', limit: 1 }], ns, r)],
	];
	for (const [label, call] of NULL_FIELD_CALLS) {
		it(`${label} with a null shard field still routes through shardNameForKey, not the singleton`, async () => {
			const { namespace, names } = recordingNamespace();
			await call(namespace, ON);
			expect(names).toEqual([shardNameForKey(null as never, SALT)]);
		});
	}

	it('routes the same scoping key to the same name on every call (no split state)', async () => {
		const { namespace, names } = recordingNamespace();
		for (let i = 0; i < 5; i++) {
			await checkScopedRateLimitWithCoordinator('198.51.100.9', 'control', 5, 50, namespace, ON);
			await checkSessionCreateRateLimitWithCoordinator('198.51.100.9', 5, 60_000, namespace, ON);
		}
		expect(new Set(names).size).toBe(1);
		expect(names[0]).toBe(shardNameForKey('198.51.100.9', SALT));
	});

	it('a salt change moves a key to a different name only through the salt', async () => {
		const { namespace, names } = recordingNamespace();
		await checkToolDailyRateLimitWithCoordinator('principal-z', 'tool', 5, namespace, { enabled: true, salt: 'a' });
		await checkToolDailyRateLimitWithCoordinator('principal-z', 'tool', 5, namespace, { enabled: true, salt: 'a' });
		expect(names[0]).toBe(names[1]);
		expect(names[0]).toBe(shardNameForKey('principal-z', 'a'));
	});

	it('reset targets the singleton first', async () => {
		const { namespace, names } = recordingNamespace();
		await resetQuotaCoordinatorState(namespace);
		expect(names[0]).toBe(SINGLETON);
	});
});
