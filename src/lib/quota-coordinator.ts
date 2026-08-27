// SPDX-License-Identifier: BUSL-1.1

import { DurableObject } from 'cloudflare:workers';
import { disposeUnreadResponseBody, readJsonResponseCapped } from './response-body';
import { readBoundedText } from './request-body';

const COORDINATOR_NAME = 'global-quota-coordinator';
const CLEANUP_ALARM_INTERVAL_MS = 15 * 60 * 1000;
const KEY_PREFIX = 'quota:';
const COORDINATOR_HTTP_MAX_BODY_BYTES = 64 * 1024;
const COORDINATOR_REQUEST_MAX_BODY_BYTES = 16 * 1024;

/**
 * R8 (PROPOSAL): shard the per-IP/per-principal counters off the global singleton.
 *
 * The #1 worldwide-throughput ceiling was that EVERY unauthenticated tools/call
 * routed 3-4 SERIAL coordinator round trips to ONE Durable Object instance
 * (`global-quota-coordinator`). The counter KEYS are already principal/IP-scoped,
 * so only the ROUTING NAME was global — concentrating all load on a single DO.
 *
 * This routes the per-IP/per-principal kinds (`scoped-rate`, `tool-daily`,
 * `distinct-domain-daily`, `session-create`, and the batched `evaluate`) to `getByName('${SHARD_PREFIX}${n}')`
 * where `n = fnv1a(shardKey) % QUOTA_SHARD_COUNT`. The shard key is the counter's
 * OWN scoping field (the IP for scoped-rate/session-create, the principalId for
 * tool-daily/distinct-domain-daily). That invariant — shard key === counter scope — is what keeps counts
 * EXACTLY identical to the single-instance behavior: a given principal's counter
 * always lands on the same shard, so it is never split or double-counted.
 *
 * The genuinely-global cost ceiling (`global-daily`) and `reset` stay on the
 * singleton — those counters are NOT principal-scoped and MUST stay exact on one
 * instance (see blockers in the PR for the global-daily exactness decision).
 *
 * `QUOTA_SHARD_COUNT` is a FROZEN constant for the life of a deployment (ADAM
 * non-negotiable #7). A caller's shard is `fnv1a(salt + key) % QUOTA_SHARD_COUNT`,
 * so the moment the count (or the salt) changes, EVERY caller re-maps to a
 * different shard and abandons its in-flight counter — that is a windowed-
 * relaxation event (every per-IP/per-tool counter resets once), NOT a hot edit.
 * Do NOT change it mid-window. Treat a change exactly like flipping the sharding
 * flag on: schedule a low-traffic window, accept the one-time counter reset, and
 * document it in CHANGELOG + the runbook. The reset path that clears every shard's
 * stranded counters is `resetQuotaCoordinatorState()` below.
 */
const QUOTA_SHARD_COUNT = 16;
const SHARD_PREFIX = 'quota-shard-';

/**
 * Strong-consistency state (OAuth one-time claims/revocation/versioning and
 * paid/trial budgets) must never follow the operator-controlled quota shard
 * flag or salt. Changing either intentionally remaps ephemeral rate counters;
 * remapping authorization state would re-enable consumed codes or revoked
 * tokens. Keep this count/prefix frozen and migrate explicitly if it ever
 * changes.
 */
const SECURITY_STATE_SHARD_COUNT = 32;
const SECURITY_STATE_SHARD_PREFIX = 'security-state-shard-';

/**
 * ADAM non-negotiable #4: the shard key is NOT the raw attacker-known IP. We salt
 * the FNV-1a input with a deploy-time secret (`QUOTA_SHARD_SALT`) so an operator of
 * an IP range / botnet cannot precompute which addresses hash to a chosen shard and
 * reconcentrate load onto 1/16th of capacity. The salt is mixed into the hash input,
 * not the modulus, so distribution stays uniform; only the *mapping* is unknowable
 * without the salt.
 *
 * NOTE: changing the salt re-maps every caller's shard exactly like changing
 * QUOTA_SHARD_COUNT — it is a windowed-relaxation event, not a hot edit (see above).
 * An empty/unset salt is permitted (degrades to the unsalted mapping) but is only
 * reached when sharding is enabled WITHOUT a configured salt — log-worthy at the
 * call site; the routing still works, it is just precomputable.
 *
 * AVAILABILITY TRADEOFF (LINUS MUST-FIX #3 — known, accepted): with a finite shard
 * count an attacker who controls an IP range can still concentrate load onto one
 * shard. The salt makes the *mapping* unknowable (they cannot pre-pick a target
 * shard), but if they saturate whichever shard their traffic lands on, that DO's
 * latency rises, the circuit breaker opens, and quota checks for that shard degrade
 * to the serial → KV → in-memory fallback. NO quota is bypassed on any path (per-IP
 * counts stay exact), and the degradation is observable (`quota_coordinator_fallback`).
 * The real mitigation for single-shard saturation is the upstream IP-rate WAF, not
 * the hash choice — crypto/consistent hashing buys nothing when the attacker controls
 * the hash input. The breaker→KV fallback MUST be load-tested for single-shard
 * saturation before the flag is flipped in production.
 */
export interface ShardRouting {
	/**
	 * Feature flag (ADAM non-negotiable #2). When `false` (the default — unset
	 * `QUOTA_SHARDING_ENABLED`), every rate/quota payload routes to the singleton
	 * `COORDINATOR_NAME`, i.e. byte-for-byte the pre-shard behavior. Security
	 * state uses its separate frozen routing regardless of this flag. Quota
	 * sharding is only active when an operator flips this ON at a chosen window.
	 */
	enabled: boolean;
	/** Deploy-time salt mixed into the shard-key hash input. */
	salt: string;
}

/** Routing config that keeps ephemeral quota payloads on the singleton. */
export const SINGLETON_ROUTING: ShardRouting = { enabled: false, salt: '' };

/**
 * R8 / ADAM #4 config guard: sharding is ENABLED but no salt is configured. With an
 * empty salt the shard mapping degrades to the unsalted FNV-1a of the raw key, which
 * an IP-range / botnet operator can precompute to reconcentrate load onto one shard
 * (see {@link ShardRouting}). The salt SHOULD be supplied as a deploy Secret
 * (`QUOTA_SHARD_SALT`). Returns `true` when the misconfiguration is present so the
 * caller can emit an observable degradation event. Pure; never throws.
 */
export function isQuotaShardSaltMissing(routing: ShardRouting): boolean {
	return routing.enabled && routing.salt.length === 0;
}

/** FNV-1a 32-bit hash — deterministic, dependency-free, stable across instances. */
function fnv1a(input: string): number {
	let hash = 0x811c9dc5;
	for (let i = 0; i < input.length; i++) {
		hash ^= input.charCodeAt(i);
		// 32-bit FNV prime multiply via shifts; keep it unsigned/32-bit each step
		hash = (hash + ((hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24))) >>> 0;
	}
	return hash >>> 0;
}

/**
 * Map a scoping key (IP or principalId) to a stable shard index. The salt is
 * prefixed onto the hash input so the raw key is never directly hashable (#4).
 */
export function shardIndexForKey(key: string, salt = ''): number {
	return fnv1a(`${salt}\0${key}`) % QUOTA_SHARD_COUNT;
}

/** Durable Object instance name for a given shard key. Exported for test assertions. */
export function shardNameForKey(key: string, salt = ''): string {
	return `${SHARD_PREFIX}${shardIndexForKey(key, salt)}`;
}

/** Stable routing for security state; deliberately independent of quota flags. */
export function securityStateShardNameForKey(key: string): string {
	return `${SECURITY_STATE_SHARD_PREFIX}${fnv1a(key) % SECURITY_STATE_SHARD_COUNT}`;
}

type ScopedQuotaScope = 'tools' | 'control';

interface CounterRecord {
	count: number;
	expiresAt: number;
}

interface VersionRecord {
	value: number;
}

interface IdempotencyRecord extends CounterRecord {
	requestHash: string;
	status: 'in_progress' | 'complete';
	result?: string;
}

interface RateLimitResult {
	allowed: boolean;
	retryAfterMs?: number;
	minuteRemaining: number;
	hourRemaining: number;
}

interface ToolDailyRateLimitResult {
	allowed: boolean;
	retryAfterMs?: number;
	remaining: number;
	limit: number;
}

interface GlobalRateLimitResult {
	allowed: boolean;
	retryAfterMs?: number;
	remaining: number;
	limit: number;
}

interface SessionCreateRateResult {
	allowed: boolean;
	retryAfterMs?: number;
	remaining: number;
}

export interface BudgetReservationResult {
	allowed: boolean;
	remaining: number;
	limit: number;
	used: number;
}

/** Atomic admission result for one validated OAuth DCR persistent write. */
export interface OAuthDcrBudgetResult {
	allowed: boolean;
	retryAfterMs?: number;
}

export interface OAuthDcrBudgetLimits {
	sourceDailyLimit: number;
	globalHourlyLimit: number;
	globalDailyLimit: number;
}

export interface ClaimOnceResult {
	claimed: boolean;
}

export interface MarkerResult {
	present: boolean;
}

export interface VersionResult {
	value: number;
}

export type IdempotencyBeginResult =
	| { state: 'started' }
	| { state: 'in_progress' }
	| { state: 'complete'; result: string }
	| { state: 'conflict' };

export interface IdempotencyCompleteResult {
	completed: boolean;
}

/** Atomic subject-version mutation plus replay result. Idempotency is scoped to the subject shard. */
export type IdempotentVersionBumpResult = { state: 'complete'; value: number } | { state: 'conflict' };

/**
 * A single per-IP/per-principal sub-check inside a batched `evaluate` round trip.
 * Only `scoped-rate` and `tool-daily` are batchable — `global-daily` is NOT
 * (it lives on the singleton; mixing it into a sharded batch would mis-route the
 * global counter and is rejected by validation).
 */
export type EvaluateCheck =
	| {
			kind: 'scoped-rate';
			scope: ScopedQuotaScope;
			ip: string;
			minuteLimit: number;
			hourLimit: number;
	  }
	| {
			kind: 'tool-daily';
			principalId: string;
			toolName: string;
			limit: number;
	  };

/**
 * Result of one sub-check, tagged so the caller can demux. The `index` echoes the
 * request order so the caller maps verdicts back to its checks unambiguously.
 */
export type EvaluateResult =
	| { index: number; kind: 'scoped-rate'; result: RateLimitResult }
	| { index: number; kind: 'tool-daily'; result: ToolDailyRateLimitResult };

interface EvaluateResponse {
	results: EvaluateResult[];
}

export type QuotaCoordinatorRequest =
	| {
			kind: 'scoped-rate';
			scope: ScopedQuotaScope;
			ip: string;
			minuteLimit: number;
			hourLimit: number;
	  }
	| {
			kind: 'tool-daily';
			principalId: string;
			toolName: string;
			limit: number;
	  }
	| {
			kind: 'distinct-domain-daily';
			principalId: string;
			domainFingerprint: string;
			limit: number;
	  }
	| {
			kind: 'global-daily';
			limit: number;
	  }
	| {
			kind: 'session-create';
			ip: string;
			limit: number;
			windowMs: number;
	  }
	| ({
			kind: 'oauth-dcr-write';
			/** SHA-256 of the caller source address; raw addresses never enter global state. */
			sourceFingerprint: string;
	  } & OAuthDcrBudgetLimits)
	| {
			kind: 'reserve-budget';
			coordinationKey: string;
			amount: number;
			limit: number;
			expiresAt: number;
			initialUsed?: number;
	  }
	| {
			kind: 'claim-once';
			coordinationKey: string;
			expiresAt: number;
	  }
	| {
			kind: 'marker-set';
			coordinationKey: string;
			expiresAt: number;
	  }
	| {
			kind: 'marker-has';
			coordinationKey: string;
	  }
	| {
			kind: 'version-get';
			coordinationKey: string;
			defaultValue: number;
	  }
	| {
			kind: 'version-bump';
			coordinationKey: string;
			defaultValue: number;
	  }
	| {
			kind: 'version-set-max';
			coordinationKey: string;
			defaultValue: number;
			value: number;
	  }
	| {
			kind: 'version-bump-idempotent';
			/** Subject-derived key; also fixes the security-state shard used by the transaction. */
			coordinationKey: string;
			/** Caller-key hash used only for replay state inside that subject shard. */
			idempotencyCoordinationKey: string;
			requestHash: string;
			defaultValue: number;
			expiresAt: number;
	  }
	| {
			kind: 'idempotency-begin';
			coordinationKey: string;
			requestHash: string;
			expiresAt: number;
	  }
	| {
			kind: 'idempotency-complete';
			coordinationKey: string;
			requestHash: string;
			result: string;
	  }
	| {
			/**
			 * R8: batch multiple per-IP/per-principal sub-checks into ONE round trip.
			 * `shardKey` is the routing key (caller-provided) — ALL sub-checks in a
			 * single evaluate MUST share the same shard key so they land on the same
			 * instance and stay count-exact. Sub-checks run in REQUEST ORDER and SHORT
			 * CIRCUIT on the first denial (the rejected counter is still incremented;
			 * later counters in the batch are NOT touched — matching the serial
			 * single-instance behavior where a denied earlier check returns before the
			 * later check runs).
			 */
			kind: 'evaluate';
			shardKey: string;
			checks: EvaluateCheck[];
	  }
	| {
			kind: 'reset';
	  };

export type QuotaCoordinatorResponse =
	| RateLimitResult
	| ToolDailyRateLimitResult
	| GlobalRateLimitResult
	| SessionCreateRateResult
	| BudgetReservationResult
	| OAuthDcrBudgetResult
	| ClaimOnceResult
	| MarkerResult
	| VersionResult
	| IdempotentVersionBumpResult
	| IdempotencyBeginResult
	| IdempotencyCompleteResult
	| EvaluateResponse
	| undefined;

/**
 * Routing name for a payload. Security state always uses frozen security shards;
 * per-IP/per-principal quota counters fan across quota shards only when enabled;
 * the global counter + reset stay on the singleton.
 *
 * `reset` deliberately targets the singleton here: tests + the admin reset path
 * call it once, and the per-shard state is best-effort/TTL'd (the cleanup alarm
 * expires every shard's counters), so a single-name reset is sufficient for the
 * singleton's global counter. (Per-shard reset is exposed separately via
 * `resetQuotaCoordinatorState`'s shard sweep — see below.)
 */
function routingNameForPayload(payload: QuotaCoordinatorRequest, routing: ShardRouting): string {
	// Authorization/idempotency state always uses the frozen security sharding
	// scheme. It must not follow the independently controlled quota flag/salt.
	switch (payload.kind) {
		case 'reserve-budget':
		case 'claim-once':
		case 'marker-set':
		case 'marker-has':
		case 'version-get':
		case 'version-bump':
		case 'version-set-max':
		case 'version-bump-idempotent':
		case 'idempotency-begin':
		case 'idempotency-complete':
			return securityStateShardNameForKey(payload.coordinationKey);
	}
	// Flag-OFF (ADAM #2): every quota payload stays on the singleton — byte-for-byte
	// the pre-shard behavior. global-daily + reset ALWAYS stay on the singleton even
	// when quota sharding is on (ADAM #5: the cost ceiling is never approximated).
	if (!routing.enabled) return COORDINATOR_NAME;
	switch (payload.kind) {
		case 'scoped-rate':
		case 'session-create':
			return shardNameForKey(payload.ip, routing.salt);
		case 'tool-daily':
		case 'distinct-domain-daily':
			return shardNameForKey(payload.principalId, routing.salt);
		case 'evaluate':
			return shardNameForKey(payload.shardKey, routing.salt);
		case 'global-daily':
		case 'oauth-dcr-write':
		case 'reset':
		default:
			return COORDINATOR_NAME;
	}
}

function getCoordinatorStub(
	namespace: DurableObjectNamespace<QuotaCoordinator> | undefined,
	name: string = COORDINATOR_NAME,
): DurableObjectStub<QuotaCoordinator> | undefined {
	if (!namespace) return undefined;
	return namespace.getByName(name);
}

async function callCoordinator<T>(
	namespace: DurableObjectNamespace<QuotaCoordinator> | undefined,
	payload: QuotaCoordinatorRequest,
	routing: ShardRouting = SINGLETON_ROUTING,
): Promise<T | undefined> {
	const stub = getCoordinatorStub(namespace, routingNameForPayload(payload, routing));
	if (!stub) return undefined;

	const rpcDispatch = (stub as unknown as { dispatch?: (request: QuotaCoordinatorRequest) => Promise<QuotaCoordinatorResponse> }).dispatch;
	if (typeof rpcDispatch === 'function') {
		return (await stub.dispatch(payload)) as T | undefined;
	}

	// Compatibility seam for injected/self-host test stubs that predate DO RPC.
	const response = await stub.fetch('https://quota.internal/', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(payload),
	});
	if (!response.ok) {
		const status = response.status;
		await disposeUnreadResponseBody(response);
		throw new Error(`Quota coordinator returned HTTP ${status}`);
	}
	if (payload.kind === 'reset') return undefined;
	const body = await readJsonResponseCapped<T>(response, COORDINATOR_HTTP_MAX_BODY_BYTES);
	if (body === null) throw new Error('Quota coordinator returned invalid or oversized JSON');
	return body;
}

export async function checkScopedRateLimitWithCoordinator(
	ip: string,
	scope: ScopedQuotaScope,
	minuteLimit: number,
	hourLimit: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
	routing: ShardRouting = SINGLETON_ROUTING,
): Promise<RateLimitResult | undefined> {
	return callCoordinator<RateLimitResult>(
		namespace,
		{
			kind: 'scoped-rate',
			scope,
			ip,
			minuteLimit,
			hourLimit,
		},
		routing,
	);
}

export async function checkToolDailyRateLimitWithCoordinator(
	principalId: string,
	toolName: string,
	limit: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
	routing: ShardRouting = SINGLETON_ROUTING,
): Promise<ToolDailyRateLimitResult | undefined> {
	return callCoordinator<ToolDailyRateLimitResult>(
		namespace,
		{
			kind: 'tool-daily',
			principalId,
			toolName,
			limit,
		},
		routing,
	);
}

/**
 * Atomically count a distinct domain once per principal/day. Undefined means
 * the coordinator binding was absent and no state was mutated.
 */
export async function checkDistinctDomainDailyLimitWithCoordinator(
	principalId: string,
	domainFingerprint: string,
	limit: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
	routing: ShardRouting = SINGLETON_ROUTING,
): Promise<ToolDailyRateLimitResult | undefined> {
	return callCoordinator<ToolDailyRateLimitResult>(
		namespace,
		{
			kind: 'distinct-domain-daily',
			principalId,
			domainFingerprint,
			limit,
		},
		routing,
	);
}

export async function checkGlobalDailyLimitWithCoordinator(
	limit: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<GlobalRateLimitResult | undefined> {
	// ADAM #5: global-daily NEVER takes a routing arg — it is hard-pinned to the
	// singleton by routingNameForPayload, so the cost ceiling stays exact.
	return callCoordinator<GlobalRateLimitResult>(namespace, {
		kind: 'global-daily',
		limit,
	});
}

export async function checkSessionCreateRateLimitWithCoordinator(
	ip: string,
	limit: number,
	windowMs: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
	routing: ShardRouting = SINGLETON_ROUTING,
): Promise<SessionCreateRateResult | undefined> {
	return callCoordinator<SessionCreateRateResult>(
		namespace,
		{
			kind: 'session-create',
			ip,
			limit,
			windowMs,
		},
		routing,
	);
}

/**
 * Atomically reserve one validated Dynamic Client Registration write across
 * the per-source daily and fleet-wide hourly/daily ceilings. This is pinned to
 * the singleton: distributing the global counters would make the cost ceiling
 * approximate. `undefined` means the strong coordinator is not provisioned.
 */
export async function checkOAuthDcrBudgetWithCoordinator(
	sourceFingerprint: string,
	limits: OAuthDcrBudgetLimits,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<OAuthDcrBudgetResult | undefined> {
	return callCoordinator<OAuthDcrBudgetResult>(namespace, {
		kind: 'oauth-dcr-write',
		sourceFingerprint,
		...limits,
	});
}

/** Atomically reserve units from a bounded, expiring budget. Undefined means no binding. */
export async function reserveBudgetWithCoordinator(
	coordinationKey: string,
	amount: number,
	limit: number,
	expiresAt: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
	initialUsed = 0,
): Promise<BudgetReservationResult | undefined> {
	return callCoordinator<BudgetReservationResult>(namespace, {
		kind: 'reserve-budget',
		coordinationKey,
		amount,
		limit,
		expiresAt,
		initialUsed,
	});
}

/** Atomically claim an expiring key once. Undefined means no binding. */
export async function claimOnceWithCoordinator(
	coordinationKey: string,
	expiresAt: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<ClaimOnceResult | undefined> {
	return callCoordinator<ClaimOnceResult>(namespace, { kind: 'claim-once', coordinationKey, expiresAt });
}

/** Persist an expiring deny marker in strong state. Undefined means no binding. */
export async function setMarkerWithCoordinator(
	coordinationKey: string,
	expiresAt: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<MarkerResult | undefined> {
	return callCoordinator<MarkerResult>(namespace, { kind: 'marker-set', coordinationKey, expiresAt });
}

/** Read an expiring deny marker from strong state. Undefined means no binding. */
export async function hasMarkerWithCoordinator(
	coordinationKey: string,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<MarkerResult | undefined> {
	return callCoordinator<MarkerResult>(namespace, { kind: 'marker-has', coordinationKey });
}

/** Read a persistent monotonic version from strong state. Undefined means no binding. */
export async function getVersionWithCoordinator(
	coordinationKey: string,
	defaultValue: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<VersionResult | undefined> {
	return callCoordinator<VersionResult>(namespace, { kind: 'version-get', coordinationKey, defaultValue });
}

/** Atomically bump a persistent monotonic version. Undefined means no binding. */
export async function bumpVersionWithCoordinator(
	coordinationKey: string,
	defaultValue: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<VersionResult | undefined> {
	return callCoordinator<VersionResult>(namespace, { kind: 'version-bump', coordinationKey, defaultValue });
}

/** Atomically raise a persistent monotonic value; retries with the same/lower value are no-ops. */
export async function setMaxVersionWithCoordinator(
	coordinationKey: string,
	defaultValue: number,
	value: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<VersionResult | undefined> {
	return callCoordinator<VersionResult>(namespace, { kind: 'version-set-max', coordinationKey, defaultValue, value });
}

/**
 * Atomically bump a subject version and persist its replay value in one
 * transaction. Routing is derived from the subject `coordinationKey`, so a lost
 * response cannot strand a separate idempotency claim ahead of the mutation.
 */
export async function bumpVersionIdempotentlyWithCoordinator(
	coordinationKey: string,
	idempotencyCoordinationKey: string,
	requestHash: string,
	defaultValue: number,
	expiresAt: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<IdempotentVersionBumpResult | undefined> {
	return callCoordinator<IdempotentVersionBumpResult>(namespace, {
		kind: 'version-bump-idempotent',
		coordinationKey,
		idempotencyCoordinationKey,
		requestHash,
		defaultValue,
		expiresAt,
	});
}

/**
 * Atomically reserve an idempotency key for one canonical request. The result is
 * held in the same frozen security-state shard as the claim, so concurrent
 * retries cannot both begin execution. Undefined means the binding is absent.
 */
export async function beginIdempotentRequestWithCoordinator(
	coordinationKey: string,
	requestHash: string,
	expiresAt: number,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<IdempotencyBeginResult | undefined> {
	return callCoordinator<IdempotencyBeginResult>(namespace, {
		kind: 'idempotency-begin',
		coordinationKey,
		requestHash,
		expiresAt,
	});
}

/** Persist the terminal response for a previously reserved idempotency key. */
export async function completeIdempotentRequestWithCoordinator(
	coordinationKey: string,
	requestHash: string,
	result: string,
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<IdempotencyCompleteResult | undefined> {
	return callCoordinator<IdempotencyCompleteResult>(namespace, {
		kind: 'idempotency-complete',
		coordinationKey,
		requestHash,
		result,
	});
}

/**
 * Thrown when a real DO `evaluate` round trip returned a 2xx body that we cannot
 * parse into the expected `{ results: EvaluateResult[] }` shape (LINUS MUST-FIX #1:
 * version skew / a future DO ordering checks differently). The DO transaction has
 * ALREADY committed its increments, so the caller MUST NOT re-run the serial
 * incrementing checks (that would double/triple-count). It takes a single
 * non-incrementing path (fail-soft allow) and emits a degradation event. Distinct
 * from `undefined` (the DO provably did NOT run: namespace absent / breaker open /
 * network throw) which DOES legitimately fall through to serial.
 */
export class MalformedEvaluateResponse extends Error {
	constructor(detail: string) {
		super(`Malformed quota evaluate response: ${detail}`);
		this.name = 'MalformedEvaluateResponse';
	}
}

/**
 * Validate a raw evaluate response body. A present-but-unrecognized response is an
 * ERROR (the DO ran), NOT a silent partial. Returns the typed results array, or
 * throws `MalformedEvaluateResponse` when:
 *  - `response.results` is not an array, OR
 *  - an entry is not a well-formed `{ index, kind, result }` tuple with a known kind.
 */
export function parseEvaluateResponse(response: unknown): EvaluateResult[] {
	if (!response || typeof response !== 'object' || !('results' in response)) {
		throw new MalformedEvaluateResponse('missing results');
	}
	const results = (response as { results: unknown }).results;
	if (!Array.isArray(results)) {
		throw new MalformedEvaluateResponse('results is not an array');
	}
	for (const entry of results) {
		if (!entry || typeof entry !== 'object') {
			throw new MalformedEvaluateResponse('entry is not an object');
		}
		const e = entry as Record<string, unknown>;
		if (typeof e.index !== 'number' || (e.kind !== 'scoped-rate' && e.kind !== 'tool-daily')) {
			throw new MalformedEvaluateResponse(`unrecognized entry kind "${String(e.kind)}"`);
		}
		if (!e.result || typeof e.result !== 'object' || typeof (e.result as Record<string, unknown>).allowed !== 'boolean') {
			throw new MalformedEvaluateResponse('entry result missing allowed');
		}
	}
	return results as EvaluateResult[];
}

/**
 * R8: a batched per-IP/per-principal evaluation. All sub-checks route to the
 * shard named by `shardKey` and run in ONE round trip, short-circuiting on the
 * first denial (identical to the serial single-instance semantics). Returns the
 * tagged per-check verdicts, or `undefined` if the namespace is absent.
 *
 * LINUS MUST-FIX #1: a real DO call that returns a 2xx body we cannot parse THROWS
 * `MalformedEvaluateResponse` (so the breaker counts it and the caller knows the DO
 * ran and committed) rather than returning a partial/empty array that the caller
 * would mistake for "DO didn't run" and re-increment serially.
 *
 * The caller MUST pass a `shardKey` shared by every sub-check's scope. In the
 * unauthenticated tools/call path both the scoped-rate (`ip`) and tool-daily
 * (`principalId === ip`) checks key on the same IP, so the IP is the shard key.
 */
export async function evaluateQuotaWithCoordinator(
	shardKey: string,
	checks: EvaluateCheck[],
	namespace?: DurableObjectNamespace<QuotaCoordinator>,
	routing: ShardRouting = SINGLETON_ROUTING,
): Promise<EvaluateResult[] | undefined> {
	const response = await callCoordinator<EvaluateResponse>(
		namespace,
		{
			kind: 'evaluate',
			shardKey,
			checks,
		},
		routing,
	);
	// `undefined` === the DO provably did not run (namespace absent). Anything else
	// is a real response body and MUST validate or throw — never a silent fallthrough.
	if (response === undefined) return undefined;
	return parseEvaluateResponse(response);
}

/**
 * Reset ONLY the shard instances (`quota-shard-0..N-1`), leaving the singleton — and
 * therefore the authoritative `global-daily` cost-ceiling counter — UNTOUCHED.
 *
 * This is the R8 salt/count-ROTATION reset. Flipping `QUOTA_SHARDING_ENABLED` or
 * rotating `QUOTA_SHARD_SALT` / `QUOTA_SHARD_COUNT` re-maps every caller to a
 * different shard and strands their old per-IP / per-tool-daily counters. Sweeping
 * the shards clears those stranded counters at the rotation window WITHOUT resetting
 * the global cost ceiling (which is never sharded and must stay exact). Prefer this
 * over {@link resetQuotaCoordinatorState} in production — the latter also nukes
 * `global-daily`.
 *
 * Best-effort: each shard reset is independent and swallows its own error so a single
 * unreachable shard never blocks the rest. No-op when the namespace is absent.
 */
export async function resetQuotaCoordinatorShards(namespace?: DurableObjectNamespace<QuotaCoordinator>): Promise<void> {
	if (!namespace) return;
	const shardResets: Promise<unknown>[] = [];
	for (let i = 0; i < QUOTA_SHARD_COUNT; i++) {
		const stub = namespace.getByName(`${SHARD_PREFIX}${i}`);
		const rpcDispatch = (stub as unknown as { dispatch?: (request: QuotaCoordinatorRequest) => Promise<QuotaCoordinatorResponse> })
			.dispatch;
		shardResets.push(
			(typeof rpcDispatch === 'function'
				? stub.dispatch({ kind: 'reset' })
				: stub.fetch('https://quota.internal/', {
						method: 'POST',
						headers: { 'content-type': 'application/json' },
						body: JSON.stringify({ kind: 'reset' }),
					})
			).catch(() => undefined),
		);
	}
	await Promise.all(shardResets);
}

/** Test/full-wipe helper for the frozen strong-state shards. Never use for a quota rotation. */
async function resetSecurityStateShards(namespace?: DurableObjectNamespace<QuotaCoordinator>): Promise<void> {
	if (!namespace) return;
	const resets: Promise<unknown>[] = [];
	for (let i = 0; i < SECURITY_STATE_SHARD_COUNT; i++) {
		const stub = namespace.getByName(`${SECURITY_STATE_SHARD_PREFIX}${i}`);
		const rpcDispatch = (stub as unknown as { dispatch?: (request: QuotaCoordinatorRequest) => Promise<QuotaCoordinatorResponse> })
			.dispatch;
		resets.push(
			(typeof rpcDispatch === 'function'
				? stub.dispatch({ kind: 'reset' })
				: stub.fetch('https://quota.internal/', {
						method: 'POST',
						headers: { 'content-type': 'application/json' },
						body: JSON.stringify({ kind: 'reset' }),
					})
			).catch(() => undefined),
		);
	}
	await Promise.all(resets);
}

/**
 * Reset the singleton (its per-IP counters AND the `global-daily` cost ceiling) plus
 * every shard. Clears ALL quota state — full-wipe / test-isolation semantics.
 *
 * DANGER — DO NOT RUN IN PRODUCTION. This `deleteAll()`s the singleton, which holds
 * the authoritative `global-daily` COST-CEILING counter. Wiping it mid-day resets the
 * global spend guardrail to zero, letting a fresh full day's worth of tool calls
 * through (a cost-overrun foot-gun). For an R8 salt/count ROTATION — the only
 * legitimate operational reset — use {@link resetQuotaCoordinatorShards}, which
 * PRESERVES `global-daily`. This full reset exists for TEST ISOLATION (spec
 * `afterEach`) and a deliberate, off-hours full wipe only.
 */
export async function resetQuotaCoordinatorState(namespace?: DurableObjectNamespace<QuotaCoordinator>): Promise<void> {
	// Reset the singleton (global-daily + its per-IP counters) first, then sweep shards.
	await callCoordinator(namespace, { kind: 'reset' });
	await Promise.all([resetQuotaCoordinatorShards(namespace), resetSecurityStateShards(namespace)]);
}

function normalizeRecord(record: unknown, now: number): CounterRecord | undefined {
	if (!record || typeof record !== 'object') return undefined;
	const candidate = record as Partial<CounterRecord>; // typeof record === 'object' checked above; fields validated below
	if (
		typeof candidate.count !== 'number' ||
		!Number.isSafeInteger(candidate.count) ||
		candidate.count < 0 ||
		typeof candidate.expiresAt !== 'number' ||
		!Number.isSafeInteger(candidate.expiresAt)
	)
		return undefined;
	if (candidate.expiresAt <= now) return undefined;
	return { count: candidate.count, expiresAt: candidate.expiresAt };
}

function minuteWindowEnd(now: number): number {
	return (Math.floor(now / 60_000) + 1) * 60_000;
}

function hourWindowEnd(now: number): number {
	return (Math.floor(now / 3_600_000) + 1) * 3_600_000;
}

function dayWindowEnd(now: number): number {
	return (Math.floor(now / 86_400_000) + 1) * 86_400_000;
}

function scopedMinuteKey(scope: ScopedQuotaScope, ip: string, now: number): string {
	const prefix = scope === 'tools' ? 'tools:min' : 'control:min';
	return `${KEY_PREFIX}${prefix}:${ip}:${Math.floor(now / 60_000)}`;
}

function scopedHourKey(scope: ScopedQuotaScope, ip: string, now: number): string {
	const prefix = scope === 'tools' ? 'tools:hr' : 'control:hr';
	return `${KEY_PREFIX}${prefix}:${ip}:${Math.floor(now / 3_600_000)}`;
}

function toolDailyKey(principalId: string, toolName: string, now: number): string {
	return `${KEY_PREFIX}tool:day:${toolName.trim().toLowerCase()}:${principalId}:${Math.floor(now / 86_400_000)}`;
}

function distinctDomainDailyCountKey(principalId: string, now: number): string {
	return `${KEY_PREFIX}domain:day:count:${principalId}:${Math.floor(now / 86_400_000)}`;
}

function distinctDomainDailyMarkerKey(principalId: string, domainFingerprint: string, now: number): string {
	return `${KEY_PREFIX}domain:day:mark:${principalId}:${Math.floor(now / 86_400_000)}:${domainFingerprint}`;
}

function globalDailyKey(now: number): string {
	return `${KEY_PREFIX}global:day:${Math.floor(now / 86_400_000)}`;
}

function sessionCreateKey(ip: string, windowMs: number, now: number): string {
	return `${KEY_PREFIX}session:create:${ip}:${Math.floor(now / windowMs)}`;
}

function oauthDcrSourceDailyKey(sourceFingerprint: string, now: number): string {
	return `${KEY_PREFIX}oauth:dcr:source:day:${sourceFingerprint}:${Math.floor(now / 86_400_000)}`;
}

function oauthDcrGlobalHourlyKey(now: number): string {
	return `${KEY_PREFIX}oauth:dcr:global:hr:${Math.floor(now / 3_600_000)}`;
}

function oauthDcrGlobalDailyKey(now: number): string {
	return `${KEY_PREFIX}oauth:dcr:global:day:${Math.floor(now / 86_400_000)}`;
}

function coordinatedCounterKey(kind: 'budget' | 'claim' | 'marker', coordinationKey: string): string {
	return `${KEY_PREFIX}strong:${kind}:${coordinationKey}`;
}

function coordinatedVersionKey(coordinationKey: string): string {
	return `strong:version:${coordinationKey}`;
}

function coordinatedIdempotencyKey(coordinationKey: string): string {
	return `${KEY_PREFIX}strong:idempotency:${coordinationKey}`;
}

/** Keep well below the Durable Object per-value ceiling and bound RPC memory. */
const MAX_IDEMPOTENCY_RESULT_BYTES = 64 * 1024;

const VALID_KINDS = new Set<string>([
	'scoped-rate',
	'tool-daily',
	'distinct-domain-daily',
	'global-daily',
	'session-create',
	'oauth-dcr-write',
	'reserve-budget',
	'claim-once',
	'marker-set',
	'marker-has',
	'version-get',
	'version-bump',
	'version-set-max',
	'version-bump-idempotent',
	'idempotency-begin',
	'idempotency-complete',
	'evaluate',
	'reset',
]);

/** Max sub-checks in one evaluate batch — bounds DO work; the request path only ever sends ≤4. */
const MAX_EVALUATE_CHECKS = 8;

/** Validate the per-field invariants on a single object (shared by top-level + evaluate sub-checks). */
function validateQuotaFields(obj: Record<string, unknown>): string | undefined {
	if ('ip' in obj && (typeof obj.ip !== 'string' || obj.ip.length > 50)) {
		return 'Invalid ip: must be string <= 50 chars';
	}
	if ('principalId' in obj && (typeof obj.principalId !== 'string' || obj.principalId.length > 100)) {
		return 'Invalid principalId: must be string <= 100 chars';
	}
	if ('scope' in obj && (typeof obj.scope !== 'string' || obj.scope.length > 30)) {
		return 'Invalid scope';
	}
	if ('toolName' in obj && (typeof obj.toolName !== 'string' || obj.toolName.length > 100)) {
		return 'Invalid toolName: must be string <= 100 chars';
	}
	if (
		'domainFingerprint' in obj &&
		(typeof obj.domainFingerprint !== 'string' ||
			obj.domainFingerprint.length === 0 ||
			obj.domainFingerprint.length > 128 ||
			/[\u0000-\u001f\u007f]/.test(obj.domainFingerprint))
	) {
		return 'Invalid domainFingerprint: must be a non-empty printable string <= 128 chars';
	}
	if ('sourceFingerprint' in obj && (typeof obj.sourceFingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(obj.sourceFingerprint))) {
		return 'Invalid sourceFingerprint: must be a lowercase SHA-256 hex digest';
	}
	if (
		'coordinationKey' in obj &&
		(typeof obj.coordinationKey !== 'string' ||
			obj.coordinationKey.length === 0 ||
			obj.coordinationKey.length > 256 ||
			/[\u0000-\u001f\u007f]/.test(obj.coordinationKey))
	) {
		return 'Invalid coordinationKey: must be a non-empty printable string <= 256 chars';
	}
	if (
		'idempotencyCoordinationKey' in obj &&
		(typeof obj.idempotencyCoordinationKey !== 'string' ||
			obj.idempotencyCoordinationKey.length === 0 ||
			obj.idempotencyCoordinationKey.length > 256 ||
			/[\u0000-\u001f\u007f]/.test(obj.idempotencyCoordinationKey))
	) {
		return 'Invalid idempotencyCoordinationKey: must be a non-empty printable string <= 256 chars';
	}
	for (const numField of [
		'minuteLimit',
		'hourLimit',
		'limit',
		'windowMs',
		'amount',
		'defaultValue',
		'initialUsed',
		'value',
		'sourceDailyLimit',
		'globalHourlyLimit',
		'globalDailyLimit',
	] as const) {
		if (numField in obj) {
			const val = obj[numField];
			if (typeof val !== 'number' || !Number.isSafeInteger(val) || val < 0) {
				return `Invalid ${numField}: must be a non-negative safe integer`;
			}
		}
	}
	if ('expiresAt' in obj && (typeof obj.expiresAt !== 'number' || !Number.isSafeInteger(obj.expiresAt) || obj.expiresAt <= 0)) {
		return 'Invalid expiresAt: must be a positive safe integer';
	}
	if ('requestHash' in obj && (typeof obj.requestHash !== 'string' || !/^[a-f0-9]{64}$/.test(obj.requestHash))) {
		return 'Invalid requestHash: must be a lowercase SHA-256 hex digest';
	}
	if (
		'result' in obj &&
		(typeof obj.result !== 'string' || new TextEncoder().encode(obj.result).byteLength > MAX_IDEMPOTENCY_RESULT_BYTES)
	) {
		return `Invalid result: must be a UTF-8 string <= ${MAX_IDEMPOTENCY_RESULT_BYTES} bytes`;
	}
	return undefined;
}

/** Validate a raw JSON payload against the QuotaCoordinatorRequest discriminated union */
export function validateQuotaPayload(raw: unknown): { valid: true; payload: QuotaCoordinatorRequest } | { valid: false; error: string } {
	if (!raw || typeof raw !== 'object' || !('kind' in raw)) {
		return { valid: false, error: 'Invalid payload: missing kind' };
	}

	const { kind } = raw as { kind: unknown }; // safe: 'kind' in raw is checked above
	if (typeof kind !== 'string' || !VALID_KINDS.has(kind)) {
		return { valid: false, error: `Invalid payload: unknown kind "${String(kind)}"` };
	}

	const obj = raw as Record<string, unknown>;
	const requireFields = (...fields: string[]): string | undefined => fields.find((field) => !(field in obj));

	if (kind === 'evaluate') {
		if (typeof obj.shardKey !== 'string' || obj.shardKey.length === 0 || obj.shardKey.length > 100) {
			return { valid: false, error: 'Invalid shardKey: must be non-empty string <= 100 chars' };
		}
		if (!Array.isArray(obj.checks) || obj.checks.length === 0 || obj.checks.length > MAX_EVALUATE_CHECKS) {
			return { valid: false, error: `Invalid checks: must be a non-empty array <= ${MAX_EVALUATE_CHECKS} entries` };
		}
		for (const check of obj.checks) {
			if (!check || typeof check !== 'object') {
				return { valid: false, error: 'Invalid evaluate check: must be an object' };
			}
			const checkObj = check as Record<string, unknown>;
			// global-daily is intentionally NOT batchable: it would mis-route the global
			// counter onto a shard. Only the per-IP/per-principal kinds are permitted.
			if (checkObj.kind !== 'scoped-rate' && checkObj.kind !== 'tool-daily') {
				return { valid: false, error: 'Invalid evaluate check: kind must be scoped-rate or tool-daily' };
			}
			const required = checkObj.kind === 'scoped-rate' ? ['scope', 'ip', 'minuteLimit', 'hourLimit'] : ['principalId', 'toolName', 'limit'];
			const missing = required.find((field) => !(field in checkObj));
			if (missing) return { valid: false, error: `Invalid evaluate check: missing ${missing}` };
			const fieldErr = validateQuotaFields(checkObj);
			if (fieldErr) return { valid: false, error: fieldErr };
			if (checkObj.kind === 'scoped-rate' && checkObj.scope !== 'tools' && checkObj.scope !== 'control') {
				return { valid: false, error: 'Invalid scope' };
			}
		}
		return { valid: true, payload: raw as QuotaCoordinatorRequest };
	}

	const requiredByKind: Partial<Record<QuotaCoordinatorRequest['kind'], string[]>> = {
		'scoped-rate': ['scope', 'ip', 'minuteLimit', 'hourLimit'],
		'tool-daily': ['principalId', 'toolName', 'limit'],
		'distinct-domain-daily': ['principalId', 'domainFingerprint', 'limit'],
		'global-daily': ['limit'],
		'session-create': ['ip', 'limit', 'windowMs'],
		'oauth-dcr-write': ['sourceFingerprint', 'sourceDailyLimit', 'globalHourlyLimit', 'globalDailyLimit'],
		'reserve-budget': ['coordinationKey', 'amount', 'limit', 'expiresAt'],
		'claim-once': ['coordinationKey', 'expiresAt'],
		'marker-set': ['coordinationKey', 'expiresAt'],
		'marker-has': ['coordinationKey'],
		'version-get': ['coordinationKey', 'defaultValue'],
		'version-bump': ['coordinationKey', 'defaultValue'],
		'version-set-max': ['coordinationKey', 'defaultValue', 'value'],
		'version-bump-idempotent': ['coordinationKey', 'idempotencyCoordinationKey', 'requestHash', 'defaultValue', 'expiresAt'],
		'idempotency-begin': ['coordinationKey', 'requestHash', 'expiresAt'],
		'idempotency-complete': ['coordinationKey', 'requestHash', 'result'],
	};
	const missing = requireFields(...(requiredByKind[kind as QuotaCoordinatorRequest['kind']] ?? []));
	if (missing) return { valid: false, error: `Invalid ${kind}: missing ${missing}` };

	const fieldErr = validateQuotaFields(obj);
	if (fieldErr) return { valid: false, error: fieldErr };
	if (kind === 'scoped-rate' && obj.scope !== 'tools' && obj.scope !== 'control') {
		return { valid: false, error: 'Invalid scope' };
	}
	if (kind === 'reserve-budget' && (obj.amount as number) < 1) {
		return { valid: false, error: 'Invalid amount: must be at least 1' };
	}
	if (
		kind === 'reserve-budget' &&
		(obj.initialUsed as number | undefined) !== undefined &&
		(obj.initialUsed as number) > (obj.limit as number)
	) {
		return { valid: false, error: 'Invalid initialUsed: cannot exceed limit' };
	}
	if (
		(kind === 'version-get' || kind === 'version-bump' || kind === 'version-set-max' || kind === 'version-bump-idempotent') &&
		(obj.defaultValue as number) < 1
	) {
		return { valid: false, error: 'Invalid defaultValue: must be at least 1' };
	}
	if (kind === 'version-set-max' && (obj.value as number) < 1) {
		return { valid: false, error: 'Invalid value: must be at least 1' };
	}
	if (kind === 'session-create' && (obj.windowMs as number) < 1) {
		return { valid: false, error: 'Invalid windowMs: must be at least 1' };
	}
	if (
		kind === 'oauth-dcr-write' &&
		((obj.sourceDailyLimit as number) < 1 || (obj.globalHourlyLimit as number) < 1 || (obj.globalDailyLimit as number) < 1)
	) {
		return { valid: false, error: 'Invalid OAuth DCR limits: all limits must be at least 1' };
	}

	return { valid: true, payload: raw as QuotaCoordinatorRequest };
}

export class QuotaCoordinator extends DurableObject<Env> {
	private async ensureCleanupAlarm(): Promise<void> {
		const currentAlarm = await this.ctx.storage.getAlarm();
		if (currentAlarm !== null) return;
		await this.ctx.storage.setAlarm(Date.now() + CLEANUP_ALARM_INTERVAL_MS);
	}

	private async getCounter(txn: DurableObjectTransaction, key: string, now: number): Promise<CounterRecord | undefined> {
		const record = normalizeRecord(await txn.get<CounterRecord>(key), now);
		if (!record) {
			await txn.delete(key);
		}
		return record;
	}

	/**
	 * Pure scoped-rate counter logic operating inside an existing transaction.
	 * Shared by the single `handleScopedRateLimit` and the batched `handleEvaluate`
	 * so the two paths are byte-for-byte identical in their counting semantics.
	 */
	private async scopedRateTxn(
		txn: DurableObjectTransaction,
		check: Extract<EvaluateCheck, { kind: 'scoped-rate' }>,
		now: number,
	): Promise<RateLimitResult> {
		const minuteKey = scopedMinuteKey(check.scope, check.ip, now);
		const hourKey = scopedHourKey(check.scope, check.ip, now);

		const [minuteRecord, hourRecord] = await Promise.all([this.getCounter(txn, minuteKey, now), this.getCounter(txn, hourKey, now)]);
		const minuteCount = minuteRecord?.count ?? 0;
		const hourCount = hourRecord?.count ?? 0;

		if (minuteCount >= check.minuteLimit) {
			return {
				allowed: false,
				retryAfterMs: Math.max(minuteWindowEnd(now) - now, 0),
				minuteRemaining: 0,
				hourRemaining: Math.max(check.hourLimit - hourCount, 0),
			};
		}

		if (hourCount >= check.hourLimit) {
			return {
				allowed: false,
				retryAfterMs: Math.max(hourWindowEnd(now) - now, 0),
				minuteRemaining: Math.max(check.minuteLimit - minuteCount, 0),
				hourRemaining: 0,
			};
		}

		const newMinute = minuteCount + 1;
		const newHour = hourCount + 1;
		await txn.put({
			[minuteKey]: { count: newMinute, expiresAt: minuteWindowEnd(now) },
			[hourKey]: { count: newHour, expiresAt: hourWindowEnd(now) },
		});

		return {
			allowed: true,
			minuteRemaining: check.minuteLimit - newMinute,
			hourRemaining: check.hourLimit - newHour,
		};
	}

	/** Pure tool-daily counter logic operating inside an existing transaction (see scopedRateTxn). */
	private async toolDailyTxn(
		txn: DurableObjectTransaction,
		check: Extract<EvaluateCheck, { kind: 'tool-daily' }>,
		now: number,
	): Promise<ToolDailyRateLimitResult> {
		const key = toolDailyKey(check.principalId, check.toolName, now);
		const record = await this.getCounter(txn, key, now);
		const currentCount = record?.count ?? 0;

		if (currentCount >= check.limit) {
			return {
				allowed: false,
				retryAfterMs: Math.max(dayWindowEnd(now) - now, 0),
				remaining: 0,
				limit: check.limit,
			};
		}

		const nextCount = currentCount + 1;
		await txn.put(key, { count: nextCount, expiresAt: dayWindowEnd(now) });

		return {
			allowed: true,
			remaining: Math.max(check.limit - nextCount, 0),
			limit: check.limit,
		};
	}

	private async handleScopedRateLimit(payload: Extract<QuotaCoordinatorRequest, { kind: 'scoped-rate' }>): Promise<RateLimitResult> {
		const now = Date.now();
		const result = await this.ctx.storage.transaction((txn: DurableObjectTransaction) => this.scopedRateTxn(txn, payload, now));
		await this.ensureCleanupAlarm();
		return result;
	}

	private async handleToolDailyRateLimit(
		payload: Extract<QuotaCoordinatorRequest, { kind: 'tool-daily' }>,
	): Promise<ToolDailyRateLimitResult> {
		const now = Date.now();
		const result = await this.ctx.storage.transaction((txn: DurableObjectTransaction) => this.toolDailyTxn(txn, payload, now));
		await this.ensureCleanupAlarm();
		return result;
	}

	private async handleDistinctDomainDailyLimit(
		payload: Extract<QuotaCoordinatorRequest, { kind: 'distinct-domain-daily' }>,
	): Promise<ToolDailyRateLimitResult> {
		const now = Date.now();
		const expiresAt = dayWindowEnd(now);
		const countKey = distinctDomainDailyCountKey(payload.principalId, now);
		const markerKey = distinctDomainDailyMarkerKey(payload.principalId, payload.domainFingerprint, now);

		const result = await this.ctx.storage.transaction(async (txn: DurableObjectTransaction) => {
			const [marker, countRecord] = await Promise.all([this.getCounter(txn, markerKey, now), this.getCounter(txn, countKey, now)]);
			const currentCount = countRecord?.count ?? 0;

			// Re-scanning an already-seen domain is always allowed and never consumes
			// another slot, including when the principal is already at its cap.
			if (marker) {
				return {
					allowed: true,
					remaining: Math.max(payload.limit - currentCount, 0),
					limit: payload.limit,
				};
			}

			if (currentCount >= payload.limit) {
				return {
					allowed: false,
					retryAfterMs: Math.max(expiresAt - now, 0),
					remaining: 0,
					limit: payload.limit,
				};
			}

			const nextCount = currentCount + 1;
			// Count and marker commit in the same Durable Object transaction, so
			// concurrent first-seen domains cannot lose updates or split the write.
			await txn.put({
				[countKey]: { count: nextCount, expiresAt },
				[markerKey]: { count: 1, expiresAt },
			});
			return {
				allowed: true,
				remaining: Math.max(payload.limit - nextCount, 0),
				limit: payload.limit,
			};
		});

		await this.ensureCleanupAlarm();
		return result;
	}

	/**
	 * R8: run a batch of per-IP/per-principal sub-checks in ONE transaction,
	 * short-circuiting on the FIRST denial. This replicates the serial single-
	 * instance behavior exactly: in the serial path a denied earlier check returns
	 * before the later check's counter is ever touched, so here we stop incrementing
	 * as soon as one sub-check denies. Only the denying counter (and any that passed
	 * before it) are mutated.
	 */
	private async handleEvaluate(payload: Extract<QuotaCoordinatorRequest, { kind: 'evaluate' }>): Promise<EvaluateResponse> {
		const now = Date.now();
		const results = await this.ctx.storage.transaction(async (txn: DurableObjectTransaction): Promise<EvaluateResult[]> => {
			const out: EvaluateResult[] = [];
			for (let i = 0; i < payload.checks.length; i++) {
				const check = payload.checks[i];
				if (check.kind === 'scoped-rate') {
					const result = await this.scopedRateTxn(txn, check, now);
					out.push({ index: i, kind: 'scoped-rate', result });
					if (!result.allowed) break;
				} else {
					const result = await this.toolDailyTxn(txn, check, now);
					out.push({ index: i, kind: 'tool-daily', result });
					if (!result.allowed) break;
				}
			}
			return out;
		});

		await this.ensureCleanupAlarm();
		return { results };
	}

	private async handleGlobalDailyLimit(
		payload: Extract<QuotaCoordinatorRequest, { kind: 'global-daily' }>,
	): Promise<GlobalRateLimitResult> {
		const now = Date.now();
		const key = globalDailyKey(now);

		const result = await this.ctx.storage.transaction(async (txn: DurableObjectTransaction) => {
			const record = await this.getCounter(txn, key, now);
			const currentCount = record?.count ?? 0;

			if (currentCount >= payload.limit) {
				return {
					allowed: false,
					retryAfterMs: Math.max(dayWindowEnd(now) - now, 0),
					remaining: 0,
					limit: payload.limit,
				};
			}

			const nextCount = currentCount + 1;
			await txn.put(key, { count: nextCount, expiresAt: dayWindowEnd(now) });

			return {
				allowed: true,
				remaining: Math.max(payload.limit - nextCount, 0),
				limit: payload.limit,
			};
		});

		await this.ensureCleanupAlarm();
		return result;
	}

	private async handleSessionCreate(
		payload: Extract<QuotaCoordinatorRequest, { kind: 'session-create' }>,
	): Promise<SessionCreateRateResult> {
		const now = Date.now();
		const key = sessionCreateKey(payload.ip, payload.windowMs, now);
		const windowEnd = (Math.floor(now / payload.windowMs) + 1) * payload.windowMs;

		const result = await this.ctx.storage.transaction(async (txn: DurableObjectTransaction) => {
			const record = await this.getCounter(txn, key, now);
			const currentCount = record?.count ?? 0;

			if (currentCount >= payload.limit) {
				return {
					allowed: false,
					retryAfterMs: Math.max(windowEnd - now, 0),
					remaining: 0,
				};
			}

			const nextCount = currentCount + 1;
			await txn.put(key, { count: nextCount, expiresAt: windowEnd });

			return {
				allowed: true,
				remaining: Math.max(payload.limit - nextCount, 0),
			};
		});

		await this.ensureCleanupAlarm();
		return result;
	}

	private async handleOAuthDcrWrite(payload: Extract<QuotaCoordinatorRequest, { kind: 'oauth-dcr-write' }>): Promise<OAuthDcrBudgetResult> {
		const now = Date.now();
		const sourceKey = oauthDcrSourceDailyKey(payload.sourceFingerprint, now);
		const globalHourKey = oauthDcrGlobalHourlyKey(now);
		const globalDayKey = oauthDcrGlobalDailyKey(now);

		const result = await this.ctx.storage.transaction(async (txn: DurableObjectTransaction) => {
			const [sourceRecord, globalHourRecord, globalDayRecord] = await Promise.all([
				this.getCounter(txn, sourceKey, now),
				this.getCounter(txn, globalHourKey, now),
				this.getCounter(txn, globalDayKey, now),
			]);
			const sourceCount = sourceRecord?.count ?? 0;
			const globalHourCount = globalHourRecord?.count ?? 0;
			const globalDayCount = globalDayRecord?.count ?? 0;

			// Reject without mutating any bucket. The all-or-none transaction prevents
			// a denied global request from burning an unrelated source's allowance.
			if (sourceCount >= payload.sourceDailyLimit || globalDayCount >= payload.globalDailyLimit) {
				return { allowed: false, retryAfterMs: Math.max(dayWindowEnd(now) - now, 0) };
			}
			if (globalHourCount >= payload.globalHourlyLimit) {
				return { allowed: false, retryAfterMs: Math.max(hourWindowEnd(now) - now, 0) };
			}

			await txn.put({
				[sourceKey]: { count: sourceCount + 1, expiresAt: dayWindowEnd(now) },
				[globalHourKey]: { count: globalHourCount + 1, expiresAt: hourWindowEnd(now) },
				[globalDayKey]: { count: globalDayCount + 1, expiresAt: dayWindowEnd(now) },
			});
			return { allowed: true };
		});

		await this.ensureCleanupAlarm();
		return result;
	}

	private async handleReserveBudget(
		payload: Extract<QuotaCoordinatorRequest, { kind: 'reserve-budget' }>,
	): Promise<BudgetReservationResult> {
		const now = Date.now();
		if (payload.expiresAt <= now) {
			return { allowed: false, remaining: 0, limit: payload.limit, used: 0 };
		}
		const key = coordinatedCounterKey('budget', payload.coordinationKey);
		const result = await this.ctx.storage.transaction(async (txn: DurableObjectTransaction) => {
			const record = await this.getCounter(txn, key, now);
			const used = record?.count ?? payload.initialUsed ?? 0;
			if (payload.amount > payload.limit - used) {
				return { allowed: false, remaining: Math.max(payload.limit - used, 0), limit: payload.limit, used };
			}
			const next = used + payload.amount;
			await txn.put(key, { count: next, expiresAt: payload.expiresAt });
			return { allowed: true, remaining: payload.limit - next, limit: payload.limit, used: next };
		});
		await this.ensureCleanupAlarm();
		return result;
	}

	private async handleClaimOnce(payload: Extract<QuotaCoordinatorRequest, { kind: 'claim-once' }>): Promise<ClaimOnceResult> {
		const now = Date.now();
		if (payload.expiresAt <= now) return { claimed: false };
		const key = coordinatedCounterKey('claim', payload.coordinationKey);
		const result = await this.ctx.storage.transaction(async (txn: DurableObjectTransaction) => {
			if (await this.getCounter(txn, key, now)) return { claimed: false };
			await txn.put(key, { count: 1, expiresAt: payload.expiresAt });
			return { claimed: true };
		});
		await this.ensureCleanupAlarm();
		return result;
	}

	private async handleMarkerSet(payload: Extract<QuotaCoordinatorRequest, { kind: 'marker-set' }>): Promise<MarkerResult> {
		const now = Date.now();
		if (payload.expiresAt <= now) return { present: false };
		await this.ctx.storage.put(coordinatedCounterKey('marker', payload.coordinationKey), {
			count: 1,
			expiresAt: payload.expiresAt,
		});
		await this.ensureCleanupAlarm();
		return { present: true };
	}

	private async handleMarkerHas(payload: Extract<QuotaCoordinatorRequest, { kind: 'marker-has' }>): Promise<MarkerResult> {
		const now = Date.now();
		const key = coordinatedCounterKey('marker', payload.coordinationKey);
		const present = await this.ctx.storage.transaction(async (txn: DurableObjectTransaction) =>
			Boolean(await this.getCounter(txn, key, now)),
		);
		return { present };
	}

	private async handleVersionGet(payload: Extract<QuotaCoordinatorRequest, { kind: 'version-get' }>): Promise<VersionResult> {
		const key = coordinatedVersionKey(payload.coordinationKey);
		return this.ctx.storage.transaction(async (txn: DurableObjectTransaction) => {
			const record = await txn.get<VersionRecord>(key);
			const value = record?.value;
			if (Number.isSafeInteger(value) && (value as number) >= 1) return { value: value as number };
			await txn.put(key, { value: payload.defaultValue });
			return { value: payload.defaultValue };
		});
	}

	private async handleVersionBump(payload: Extract<QuotaCoordinatorRequest, { kind: 'version-bump' }>): Promise<VersionResult> {
		const key = coordinatedVersionKey(payload.coordinationKey);
		return this.ctx.storage.transaction(async (txn: DurableObjectTransaction) => {
			const record = await txn.get<VersionRecord>(key);
			const current =
				Number.isSafeInteger(record?.value) && (record?.value as number) >= 1 ? (record?.value as number) : payload.defaultValue;
			if (current >= Number.MAX_SAFE_INTEGER) throw new Error('Version counter exhausted');
			const value = current + 1;
			await txn.put(key, { value });
			return { value };
		});
	}

	private async handleVersionSetMax(payload: Extract<QuotaCoordinatorRequest, { kind: 'version-set-max' }>): Promise<VersionResult> {
		const key = coordinatedVersionKey(payload.coordinationKey);
		return this.ctx.storage.transaction(async (txn: DurableObjectTransaction) => {
			const record = await txn.get<VersionRecord>(key);
			const current =
				Number.isSafeInteger(record?.value) && (record?.value as number) >= 1 ? (record?.value as number) : payload.defaultValue;
			const value = Math.max(current, payload.value);
			if (value !== current || record === undefined) await txn.put(key, { value });
			return { value };
		});
	}

	private async handleIdempotentVersionBump(
		payload: Extract<QuotaCoordinatorRequest, { kind: 'version-bump-idempotent' }>,
	): Promise<IdempotentVersionBumpResult> {
		const now = Date.now();
		if (payload.expiresAt <= now) return { state: 'conflict' };
		const versionKey = coordinatedVersionKey(payload.coordinationKey);
		// Namespace the replay key by subject as well as caller key. Multiple
		// subjects intentionally share each of the 32 security shards; omitting the
		// subject here would make the same raw Idempotency-Key collide across them.
		const replayKey = coordinatedIdempotencyKey(`${payload.coordinationKey}:${payload.idempotencyCoordinationKey}`);
		const result = await this.ctx.storage.transaction(async (txn: DurableObjectTransaction): Promise<IdempotentVersionBumpResult> => {
			const rawReplay = await txn.get<IdempotencyRecord>(replayKey);
			const replay = this.normalizeIdempotencyRecord(rawReplay, now);
			if (replay) {
				if (replay.requestHash !== payload.requestHash || replay.status !== 'complete') return { state: 'conflict' };
				try {
					const parsed = JSON.parse(replay.result as string) as { value?: unknown };
					if (Number.isSafeInteger(parsed.value) && (parsed.value as number) >= 1) {
						return { state: 'complete', value: parsed.value as number };
					}
				} catch {
					// Corrupt replay state cannot safely authorize another mutation.
				}
				return { state: 'conflict' };
			}
			if (rawReplay !== undefined) await txn.delete(replayKey);

			const version = await txn.get<VersionRecord>(versionKey);
			const current =
				Number.isSafeInteger(version?.value) && (version?.value as number) >= 1 ? (version?.value as number) : payload.defaultValue;
			if (current >= Number.MAX_SAFE_INTEGER) throw new Error('Version counter exhausted');
			const value = current + 1;
			await txn.put(versionKey, { value });
			await txn.put(replayKey, {
				count: 1,
				expiresAt: payload.expiresAt,
				requestHash: payload.requestHash,
				status: 'complete',
				result: JSON.stringify({ value }),
			} satisfies IdempotencyRecord);
			return { state: 'complete', value };
		});
		await this.ensureCleanupAlarm();
		return result;
	}

	private normalizeIdempotencyRecord(record: unknown, now: number): IdempotencyRecord | undefined {
		const counter = normalizeRecord(record, now);
		if (!counter || !record || typeof record !== 'object') return undefined;
		const candidate = record as Partial<IdempotencyRecord>;
		if (typeof candidate.requestHash !== 'string' || !/^[a-f0-9]{64}$/.test(candidate.requestHash)) return undefined;
		if (candidate.status !== 'in_progress' && candidate.status !== 'complete') return undefined;
		if (candidate.status === 'complete' && typeof candidate.result !== 'string') return undefined;
		if (typeof candidate.result === 'string' && new TextEncoder().encode(candidate.result).byteLength > MAX_IDEMPOTENCY_RESULT_BYTES) {
			return undefined;
		}
		return {
			...counter,
			requestHash: candidate.requestHash,
			status: candidate.status,
			...(candidate.result !== undefined ? { result: candidate.result } : {}),
		};
	}

	private async handleIdempotencyBegin(
		payload: Extract<QuotaCoordinatorRequest, { kind: 'idempotency-begin' }>,
	): Promise<IdempotencyBeginResult> {
		const now = Date.now();
		if (payload.expiresAt <= now) return { state: 'conflict' };
		const key = coordinatedIdempotencyKey(payload.coordinationKey);
		const result = await this.ctx.storage.transaction(async (txn: DurableObjectTransaction): Promise<IdempotencyBeginResult> => {
			const raw = await txn.get<IdempotencyRecord>(key);
			const existing = this.normalizeIdempotencyRecord(raw, now);
			if (!existing) {
				if (raw !== undefined) await txn.delete(key);
				await txn.put(key, {
					count: 1,
					expiresAt: payload.expiresAt,
					requestHash: payload.requestHash,
					status: 'in_progress',
				} satisfies IdempotencyRecord);
				return { state: 'started' };
			}
			if (existing.requestHash !== payload.requestHash) return { state: 'conflict' };
			if (existing.status === 'complete') return { state: 'complete', result: existing.result as string };
			return { state: 'in_progress' };
		});
		await this.ensureCleanupAlarm();
		return result;
	}

	private async handleIdempotencyComplete(
		payload: Extract<QuotaCoordinatorRequest, { kind: 'idempotency-complete' }>,
	): Promise<IdempotencyCompleteResult> {
		const now = Date.now();
		const key = coordinatedIdempotencyKey(payload.coordinationKey);
		return this.ctx.storage.transaction(async (txn: DurableObjectTransaction): Promise<IdempotencyCompleteResult> => {
			const existing = this.normalizeIdempotencyRecord(await txn.get<IdempotencyRecord>(key), now);
			if (!existing || existing.requestHash !== payload.requestHash) return { completed: false };
			if (existing.status === 'complete') return { completed: existing.result === payload.result };
			await txn.put(key, { ...existing, status: 'complete', result: payload.result } satisfies IdempotencyRecord);
			return { completed: true };
		});
	}

	/** Type-safe RPC entrypoint used by Worker callers. */
	async dispatch(payload: QuotaCoordinatorRequest): Promise<QuotaCoordinatorResponse> {
		const validation = validateQuotaPayload(payload);
		if (!validation.valid) throw new TypeError(validation.error);
		const validPayload = validation.payload;
		switch (validPayload.kind) {
			case 'scoped-rate':
				return this.handleScopedRateLimit(validPayload);
			case 'tool-daily':
				return this.handleToolDailyRateLimit(validPayload);
			case 'distinct-domain-daily':
				return this.handleDistinctDomainDailyLimit(validPayload);
			case 'global-daily':
				return this.handleGlobalDailyLimit(validPayload);
			case 'session-create':
				return this.handleSessionCreate(validPayload);
			case 'oauth-dcr-write':
				return this.handleOAuthDcrWrite(validPayload);
			case 'reserve-budget':
				return this.handleReserveBudget(validPayload);
			case 'claim-once':
				return this.handleClaimOnce(validPayload);
			case 'marker-set':
				return this.handleMarkerSet(validPayload);
			case 'marker-has':
				return this.handleMarkerHas(validPayload);
			case 'version-get':
				return this.handleVersionGet(validPayload);
			case 'version-bump':
				return this.handleVersionBump(validPayload);
			case 'version-set-max':
				return this.handleVersionSetMax(validPayload);
			case 'version-bump-idempotent':
				return this.handleIdempotentVersionBump(validPayload);
			case 'idempotency-begin':
				return this.handleIdempotencyBegin(validPayload);
			case 'idempotency-complete':
				return this.handleIdempotencyComplete(validPayload);
			case 'evaluate':
				return this.handleEvaluate(validPayload);
			case 'reset':
				await this.ctx.storage.deleteAll();
				await this.ctx.storage.deleteAlarm();
				return undefined;
		}
	}

	async fetch(request: Request): Promise<Response> {
		if (request.method !== 'POST') {
			return new Response('Method Not Allowed', { status: 405 });
		}

		const body = await readBoundedText(request, COORDINATOR_REQUEST_MAX_BODY_BYTES);
		if (!body.ok) return new Response('Payload Too Large', { status: 413 });
		let raw: unknown;
		try {
			raw = JSON.parse(body.text);
		} catch {
			return new Response('Invalid JSON', { status: 400 });
		}
		const validation = validateQuotaPayload(raw);
		if (!validation.valid) {
			return new Response(validation.error, { status: 400 });
		}

		const payload = validation.payload;
		const result = await this.dispatch(payload);
		return result === undefined ? new Response(null, { status: 204 }) : Response.json(result);
	}

	async alarm(): Promise<void> {
		const now = Date.now();
		const records = await this.ctx.storage.list<CounterRecord>({ prefix: KEY_PREFIX });
		const expiredKeys: string[] = [];
		for (const [key, value] of records.entries()) {
			if (!normalizeRecord(value, now)) {
				expiredKeys.push(key);
			}
		}
		if (expiredKeys.length > 0) {
			await this.ctx.storage.delete(expiredKeys);
		}

		if (records.size > expiredKeys.length) {
			await this.ctx.storage.setAlarm(now + CLEANUP_ALARM_INTERVAL_MS);
		}
	}
}
