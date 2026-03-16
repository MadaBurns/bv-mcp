// SPDX-License-Identifier: BUSL-1.1

import { DurableObject } from 'cloudflare:workers';

const COORDINATOR_NAME = 'global-quota-coordinator';
const CLEANUP_ALARM_INTERVAL_MS = 15 * 60 * 1000;
const KEY_PREFIX = 'quota:';

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
			kind: 'reset';
	  };

function getCoordinatorStub(namespace: DurableObjectNamespace | undefined): DurableObjectStub | undefined {
	if (!namespace) return undefined;
	return namespace.getByName(COORDINATOR_NAME);
}

async function callCoordinator<T>(
	namespace: DurableObjectNamespace | undefined,
	payload: QuotaCoordinatorRequest,
): Promise<T | undefined> {
	const stub = getCoordinatorStub(namespace);
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

export async function resetQuotaCoordinatorState(namespace?: DurableObjectNamespace): Promise<void> {
	await callCoordinator(namespace, { kind: 'reset' });
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

const VALID_KINDS = new Set<string>(['scoped-rate', 'tool-daily', 'global-daily', 'session-create', 'reset']);

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

	// Validate string field lengths to prevent storage exhaustion
	const obj = raw as Record<string, unknown>;
	if ('ip' in obj && (typeof obj.ip !== 'string' || obj.ip.length > 50)) {
		return { valid: false, error: 'Invalid ip: must be string <= 50 chars' };
	}
	if ('principalId' in obj && (typeof obj.principalId !== 'string' || obj.principalId.length > 100)) {
		return { valid: false, error: 'Invalid principalId: must be string <= 100 chars' };
	}
	if ('scope' in obj && (typeof obj.scope !== 'string' || obj.scope.length > 30)) {
		return { valid: false, error: 'Invalid scope' };
	}

	// Validate numeric fields to prevent NaN/Infinity propagation
	for (const numField of ['minuteLimit', 'hourLimit', 'limit', 'windowMs'] as const) {
		if (numField in obj) {
			const val = obj[numField];
			if (typeof val !== 'number' || !Number.isFinite(val) || val < 0) {
				return { valid: false, error: `Invalid ${numField}: must be a non-negative finite number` };
			}
		}
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

	private async handleScopedRateLimit(payload: Extract<QuotaCoordinatorRequest, { kind: 'scoped-rate' }>): Promise<RateLimitResult> {
		const now = Date.now();
		const minuteKey = scopedMinuteKey(payload.scope, payload.ip, now);
		const hourKey = scopedHourKey(payload.scope, payload.ip, now);

		const result = await this.ctx.storage.transaction(async (txn: DurableObjectTransaction) => {
			const [minuteRecord, hourRecord] = await Promise.all([
				this.getCounter(txn, minuteKey, now),
				this.getCounter(txn, hourKey, now),
			]);
			const minuteCount = minuteRecord?.count ?? 0;
			const hourCount = hourRecord?.count ?? 0;

			if (minuteCount >= payload.minuteLimit) {
				return {
					allowed: false,
					retryAfterMs: Math.max(minuteWindowEnd(now) - now, 0),
					minuteRemaining: 0,
					hourRemaining: Math.max(payload.hourLimit - hourCount, 0),
				};
			}

			if (hourCount >= payload.hourLimit) {
				return {
					allowed: false,
					retryAfterMs: Math.max(hourWindowEnd(now) - now, 0),
					minuteRemaining: Math.max(payload.minuteLimit - minuteCount, 0),
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
				minuteRemaining: payload.minuteLimit - newMinute,
				hourRemaining: payload.hourLimit - newHour,
			};
		});

		await this.ensureCleanupAlarm();
		return result;
	}

	private async handleToolDailyRateLimit(
		payload: Extract<QuotaCoordinatorRequest, { kind: 'tool-daily' }>,
	): Promise<ToolDailyRateLimitResult> {
		const now = Date.now();
		const key = toolDailyKey(payload.principalId, payload.toolName, now);

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