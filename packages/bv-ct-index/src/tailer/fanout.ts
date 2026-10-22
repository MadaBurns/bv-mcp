// SPDX-License-Identifier: BUSL-1.1
/**
 * The tailer fanned out: each `* * * * *` tick splits the tailed logs into shards and sends one message per shard to
 * the `bv-ct-index-tail` queue, whose consumer runs that shard's tick (src/tailer/index.ts) over its own logs, with
 * its own cursors, kill-switch check and ledger row update.
 *
 * Why a queue: an invocation can have only HEADER_SLOTS requests waiting for headers, and one invocation could not
 * read the logs as fast as they grow (measured 2026-10-22: about 212k entries a minute against about 22k read). A
 * Worker reached through a service binding shares the caller's connection limit (Cloudflare limits docs,
 * "Simultaneous open connections"), so binding the Worker to itself adds no slots. Each queue consumer invocation is
 * its own top-level invocation.
 */

import type { Env } from '../index';
import { describeError, loadPlanInputs, runTailer, type TickSummary } from './index';

/** Shards a tick fans out to. */
export const SHARDS = 4;
/**
 * A shard message older than this is dropped unread: the next minute's tick has already sent a fresh one for the same
 * logs, and running both would read the same entries twice. Queue consumers that are slow to scale out shed load here.
 */
export const STALE_SHARD_MS = 50_000;

export interface ShardPlan {
	killed: boolean;
	/** Log ids per shard; empty shards are left out. */
	shards: string[][];
	logs: number;
	/** Entries the logs' heads were ahead of their cursors at their last write: what the tailer still has to read. */
	backlog: number;
}

/** One message on the `bv-ct-index-tail` queue. */
export interface ShardRequest {
	scheduledTime: number;
	shard: number;
	logIds: string[];
}

export interface FanoutSummary {
	killed: boolean;
	logs: number;
	backlog: number;
	shards: number;
	/** Why the shard messages could not be sent, if they could not; this tick then reads nothing. */
	failed: string | null;
}

interface FanoutOptions {
	now?: number;
	fetch?: typeof fetch;
	shards?: number;
}

/**
 * Deals the logs out to `shards` shards, most behind first, round-robin, so the deep backlogs land on different
 * shards. A log with no cursor yet counts as not behind.
 */
export function partitionLogs(logIds: readonly string[], behind: ReadonlyMap<string, number>, shards: number): string[][] {
	const lag = (logId: string) => behind.get(logId) ?? 0;
	const sorted = [...logIds].sort((a, b) => lag(b) - lag(a) || byId(a, b));
	const out: string[][] = Array.from({ length: Math.max(1, shards) }, () => []);
	sorted.forEach((logId, i) => out[i % out.length]!.push(logId));
	return out.filter((shard) => shard.length > 0);
}

/** Code-unit order, so the deal does not depend on the runtime's locale. */
function byId(a: string, b: string): number {
	if (a === b) return 0;
	return a < b ? -1 : 1;
}

/** The kill switch, then the tailed logs split into shards by how far each is behind. */
export async function planShards(env: Pick<Env, 'CURSORS' | 'ENTRIES' | 'CERT_DETAILS'>, options: FanoutOptions = {}): Promise<ShardPlan> {
	const inputs = await loadPlanInputs(env, options);
	if (inputs.killed) return { killed: true, shards: [], logs: 0, backlog: 0 };
	return {
		killed: false,
		shards: partitionLogs(inputs.logIds, inputs.behind, options.shards ?? SHARDS),
		logs: inputs.logIds.length,
		backlog: [...inputs.behind.values()].reduce((sum, n) => sum + n, 0),
	};
}

/** One tick fanned out: plan the shards and send them, one message each, to the tail queue. */
export async function runFanout(
	env: Pick<Env, 'CURSORS' | 'ENTRIES' | 'CERT_DETAILS'>,
	scheduledTime: number,
	tail: Pick<Queue<ShardRequest>, 'sendBatch'>,
	options: FanoutOptions = {},
): Promise<FanoutSummary> {
	const plan = await planShards(env, options);
	const summary: FanoutSummary = { killed: plan.killed, logs: plan.logs, backlog: plan.backlog, shards: plan.shards.length, failed: null };
	if (plan.shards.length === 0) return summary;
	try {
		await tail.sendBatch(plan.shards.map((logIds, shard) => ({ body: { scheduledTime, shard, logIds }, contentType: 'json' as const })));
	} catch (error) {
		summary.failed = describeError(error);
	}
	return summary;
}

export interface ShardOutcome {
	shard: number;
	/** The shard's tick, or null when the message was dropped as stale or malformed. */
	summary: TickSummary | null;
	skipped?: 'stale' | 'malformed';
}

function isShardRequest(body: unknown): body is ShardRequest {
	const request = body as Partial<ShardRequest> | null;
	return (
		typeof request?.scheduledTime === 'number' &&
		typeof request.shard === 'number' &&
		Array.isArray(request.logIds) &&
		request.logIds.every((logId) => typeof logId === 'string')
	);
}

/**
 * Runs one shard message from the tail queue. A stale or malformed message is dropped, not retried: the next tick
 * plans the same logs again from their cursors.
 */
export async function runShard(
	env: Pick<Env, 'CURSORS' | 'ENTRIES' | 'CERT_DETAILS'>,
	body: unknown,
	options: { now?: number; fetch?: typeof fetch } = {},
): Promise<ShardOutcome> {
	if (!isShardRequest(body)) return { shard: -1, summary: null, skipped: 'malformed' };
	if ((options.now ?? Date.now()) - body.scheduledTime > STALE_SHARD_MS) return { shard: body.shard, summary: null, skipped: 'stale' };
	const summary = await runTailer(env, {
		scheduledTime: body.scheduledTime,
		now: options.now,
		fetch: options.fetch,
		logIds: new Set(body.logIds),
	});
	return { shard: body.shard, summary };
}
