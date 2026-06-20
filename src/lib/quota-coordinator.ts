// SPDX-License-Identifier: BUSL-1.1

import { DurableObject } from 'cloudflare:workers';

const COORDINATOR_NAME = 'global-quota-coordinator';
const CLEANUP_ALARM_INTERVAL_MS = 15 * 60 * 1000;
const KEY_PREFIX = 'quota:';

/**
 * R8 (PROPOSAL): shard the per-IP/per-principal counters off the global singleton.
 *
 * The #1 worldwide-throughput ceiling was that EVERY unauthenticated tools/call
 * routed 3-4 SERIAL coordinator round trips to ONE Durable Object instance
 * (`global-quota-coordinator`). The counter KEYS are already principal/IP-scoped,
 * so only the ROUTING NAME was global — concentrating all load on a single DO.
 *
 * This routes the per-IP/per-principal kinds (`scoped-rate`, `tool-daily`,
 * `session-create`, and the batched `evaluate`) to `getByName('${SHARD_PREFIX}${n}')`
 * where `n = fnv1a(shardKey) % QUOTA_SHARD_COUNT`. The shard key is the counter's
 * OWN scoping field (the IP for scoped-rate/session-create, the principalId for
 * tool-daily). That invariant — shard key === counter scope — is what keeps counts
 * EXACTLY identical to the single-instance behavior: a given principal's counter
 * always lands on the same shard, so it is never split or double-counted.
 *
 * The genuinely-global cost ceiling (`global-daily`) and `reset` stay on the
 * singleton — those counters are NOT principal-scoped and MUST stay exact on one
 * instance (see blockers in the PR for the global-daily exactness decision).
 *
 * `QUOTA_SHARD_COUNT` is a fixed value so the distribution is stable; a caller's
 * shard NEVER moves for a fixed count, so there is no migration concern for
 * in-flight counters as long as the count is not changed mid-window. Changing the
 * count is a maintainer decision (see blockers).
 */
const QUOTA_SHARD_COUNT = 16;
const SHARD_PREFIX = 'quota-shard-';

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

/** Map a scoping key (IP or principalId) to a stable shard index. */
export function shardIndexForKey(key: string): number {
	return fnv1a(key) % QUOTA_SHARD_COUNT;
}

/** Durable Object instance name for a given shard key. Exported for test assertions. */
export function shardNameForKey(key: string): string {
	return `${SHARD_PREFIX}${shardIndexForKey(key)}`;
}

type ScopedQuotaScope = 'tools' | 'control';

interface CounterRecord {
	count: number;
	expiresAt: number;
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

type QuotaCoordinatorRequest =
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
			kind: 'global-daily';
			limit: number;
	  }
	| {
			kind: 'session-create';
			ip: string;
			limit: number;
			windowMs: number;
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

/**
 * Routing name for a payload. Per-IP/per-principal counters fan across shards by
 * their OWN scoping field; the global counter + reset stay on the singleton.
 *
 * `reset` deliberately targets the singleton here: tests + the admin reset path
 * call it once, and the per-shard state is best-effort/TTL'd (the cleanup alarm
 * expires every shard's counters), so a single-name reset is sufficient for the
 * singleton's global counter. (Per-shard reset is exposed separately via
 * `resetQuotaCoordinatorState`'s shard sweep — see below.)
 */
function routingNameForPayload(payload: QuotaCoordinatorRequest): string {
	switch (payload.kind) {
		case 'scoped-rate':
		case 'session-create':
			return shardNameForKey(payload.ip);
		case 'tool-daily':
			return shardNameForKey(payload.principalId);
		case 'evaluate':
			return shardNameForKey(payload.shardKey);
		case 'global-daily':
		case 'reset':
		default:
			return COORDINATOR_NAME;
	}
}

function getCoordinatorStub(
	namespace: DurableObjectNamespace | undefined,
	name: string = COORDINATOR_NAME,
): DurableObjectStub | undefined {
	if (!namespace) return undefined;
	return namespace.getByName(name);
}

async function callCoordinator<T>(
	namespace: DurableObjectNamespace | undefined,
	payload: QuotaCoordinatorRequest,
): Promise<T | undefined> {
	const stub = getCoordinatorStub(namespace, routingNameForPayload(payload));
	if (!stub) return undefined;

	const response = await stub.fetch('https://quota.internal/', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(payload),
	});

	if (!response.ok) {
		throw new Error(`Quota coordinator returned HTTP ${response.status}`);
	}

	if (payload.kind === 'reset') {
		return undefined;
	}

	return (await response.json()) as T; // response shape matches the generic T per handler contract
}

export async function checkScopedRateLimitWithCoordinator(
	ip: string,
	scope: ScopedQuotaScope,
	minuteLimit: number,
	hourLimit: number,
	namespace?: DurableObjectNamespace,
): Promise<RateLimitResult | undefined> {
	return callCoordinator<RateLimitResult>(namespace, {
		kind: 'scoped-rate',
		scope,
		ip,
		minuteLimit,
		hourLimit,
	});
}

export async function checkToolDailyRateLimitWithCoordinator(
	principalId: string,
	toolName: string,
	limit: number,
	namespace?: DurableObjectNamespace,
): Promise<ToolDailyRateLimitResult | undefined> {
	return callCoordinator<ToolDailyRateLimitResult>(namespace, {
		kind: 'tool-daily',
		principalId,
		toolName,
		limit,
	});
}

export async function checkGlobalDailyLimitWithCoordinator(
	limit: number,
	namespace?: DurableObjectNamespace,
): Promise<GlobalRateLimitResult | undefined> {
	return callCoordinator<GlobalRateLimitResult>(namespace, {
		kind: 'global-daily',
		limit,
	});
}

export async function checkSessionCreateRateLimitWithCoordinator(
	ip: string,
	limit: number,
	windowMs: number,
	namespace?: DurableObjectNamespace,
): Promise<SessionCreateRateResult | undefined> {
	return callCoordinator<SessionCreateRateResult>(namespace, {
		kind: 'session-create',
		ip,
		limit,
		windowMs,
	});
}

/**
 * R8: a batched per-IP/per-principal evaluation. All sub-checks route to the
 * shard named by `shardKey` and run in ONE round trip, short-circuiting on the
 * first denial (identical to the serial single-instance semantics). Returns the
 * tagged per-check verdicts, or `undefined` if the namespace is absent.
 *
 * The caller MUST pass a `shardKey` shared by every sub-check's scope. In the
 * unauthenticated tools/call path both the scoped-rate (`ip`) and tool-daily
 * (`principalId === ip`) checks key on the same IP, so the IP is the shard key.
 */
export async function evaluateQuotaWithCoordinator(
	shardKey: string,
	checks: EvaluateCheck[],
	namespace?: DurableObjectNamespace,
): Promise<EvaluateResult[] | undefined> {
	const response = await callCoordinator<EvaluateResponse>(namespace, {
		kind: 'evaluate',
		shardKey,
		checks,
	});
	return response?.results;
}

export async function resetQuotaCoordinatorState(namespace?: DurableObjectNamespace): Promise<void> {
	// Reset the singleton (global-daily) AND every shard so test isolation and the
	// admin reset path clear ALL per-IP/per-principal counters, not just the global one.
	await callCoordinator(namespace, { kind: 'reset' });
	if (!namespace) return;
	const shardResets: Promise<unknown>[] = [];
	for (let i = 0; i < QUOTA_SHARD_COUNT; i++) {
		const stub = namespace.getByName(`${SHARD_PREFIX}${i}`);
		shardResets.push(
			stub
				.fetch('https://quota.internal/', {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ kind: 'reset' }),
				})
				.catch(() => undefined),
		);
	}
	await Promise.all(shardResets);
}

function normalizeRecord(record: unknown, now: number): CounterRecord | undefined {
	if (!record || typeof record !== 'object') return undefined;
	const candidate = record as Partial<CounterRecord>; // typeof record === 'object' checked above; fields validated below
	if (typeof candidate.count !== 'number' || typeof candidate.expiresAt !== 'number') return undefined;
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

function globalDailyKey(now: number): string {
	return `${KEY_PREFIX}global:day:${Math.floor(now / 86_400_000)}`;
}

function sessionCreateKey(ip: string, windowMs: number, now: number): string {
	return `${KEY_PREFIX}session:create:${ip}:${Math.floor(now / windowMs)}`;
}

const VALID_KINDS = new Set<string>(['scoped-rate', 'tool-daily', 'global-daily', 'session-create', 'evaluate', 'reset']);

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
	for (const numField of ['minuteLimit', 'hourLimit', 'limit', 'windowMs'] as const) {
		if (numField in obj) {
			const val = obj[numField];
			if (typeof val !== 'number' || !Number.isFinite(val) || val < 0) {
				return `Invalid ${numField}: must be a non-negative finite number`;
			}
		}
	}
	return undefined;
}

/** Validate a raw JSON payload against the QuotaCoordinatorRequest discriminated union */
export function validateQuotaPayload(
	raw: unknown,
): { valid: true; payload: QuotaCoordinatorRequest } | { valid: false; error: string } {
	if (!raw || typeof raw !== 'object' || !('kind' in raw)) {
		return { valid: false, error: 'Invalid payload: missing kind' };
	}

	const { kind } = raw as { kind: unknown }; // safe: 'kind' in raw is checked above
	if (typeof kind !== 'string' || !VALID_KINDS.has(kind)) {
		return { valid: false, error: `Invalid payload: unknown kind "${String(kind)}"` };
	}

	const obj = raw as Record<string, unknown>;

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
			const fieldErr = validateQuotaFields(checkObj);
			if (fieldErr) return { valid: false, error: fieldErr };
		}
		return { valid: true, payload: raw as QuotaCoordinatorRequest };
	}

	const fieldErr = validateQuotaFields(obj);
	if (fieldErr) return { valid: false, error: fieldErr };

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

		const [minuteRecord, hourRecord] = await Promise.all([
			this.getCounter(txn, minuteKey, now),
			this.getCounter(txn, hourKey, now),
		]);
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

	private async handleGlobalDailyLimit(payload: Extract<QuotaCoordinatorRequest, { kind: 'global-daily' }>): Promise<GlobalRateLimitResult> {
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

	private async handleSessionCreate(payload: Extract<QuotaCoordinatorRequest, { kind: 'session-create' }>): Promise<SessionCreateRateResult> {
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

	async fetch(request: Request): Promise<Response> {
		if (request.method !== 'POST') {
			return new Response('Method Not Allowed', { status: 405 });
		}

		const raw: unknown = await request.json();
		const validation = validateQuotaPayload(raw);
		if (!validation.valid) {
			return new Response(validation.error, { status: 400 });
		}

		const payload = validation.payload;
		switch (payload.kind) {
			case 'scoped-rate':
				return Response.json(await this.handleScopedRateLimit(payload));
			case 'tool-daily':
				return Response.json(await this.handleToolDailyRateLimit(payload));
			case 'global-daily':
				return Response.json(await this.handleGlobalDailyLimit(payload));
			case 'session-create':
				return Response.json(await this.handleSessionCreate(payload));
			case 'evaluate':
				return Response.json(await this.handleEvaluate(payload));
			case 'reset':
				await this.ctx.storage.deleteAll();
				await this.ctx.storage.deleteAlarm();
				return new Response(null, { status: 204 });
			default:
				// Unreachable — validateQuotaPayload ensures kind is valid
				return new Response('Invalid payload', { status: 400 });
		}
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