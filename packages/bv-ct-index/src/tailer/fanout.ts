// SPDX-License-Identifier: BUSL-1.1
/**
 * The tailer fanned out: each `* * * * *` tick splits the tailed logs into shards and runs every shard at once in
 * its own invocation (TailShard in src/index.ts, reached through this Worker's own TAILER service binding). An
 * invocation can only have HEADER_SLOTS fetches waiting for headers, so one invocation could not read the logs as
 * fast as they grow (measured 2026-10-22: about 212k entries a minute against about 22k read). Shards are
 * independent: each runs the whole tick of src/tailer/index.ts over its own logs, with its own cursors, kill-switch
 * check and ledger row update.
 */

import type { Env } from '../index';
import { describeError, loadPlanInputs, type TickSummary } from './index';

/** Invocations a tick fans out to. A request may make at most 32 Worker invocations, so this stays well under it. */
export const SHARDS = 4;

export interface ShardPlan {
	killed: boolean;
	/** Log ids per shard; empty shards are left out. */
	shards: string[][];
	logs: number;
	/** Entries the logs' heads were ahead of their cursors at their last write: what the tailer still has to read. */
	backlog: number;
}

/** What the cron hands one shard (TailShard.tailLogs in src/index.ts). */
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
	entries: number;
	subrequests: number;
	/** shard -> why its invocation failed. The other shards' cursors are unaffected. */
	failed: Record<number, string>;
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
	const sorted = [...logIds].sort((a, b) => (behind.get(b) ?? 0) - (behind.get(a) ?? 0) || (a < b ? -1 : a > b ? 1 : 0));
	const out: string[][] = Array.from({ length: Math.max(1, shards) }, () => []);
	sorted.forEach((logId, i) => out[i % out.length]!.push(logId));
	return out.filter((shard) => shard.length > 0);
}

/** The kill switch, then the tailed logs split into shards by how far each is behind. */
export async function planShards(env: Pick<Env, 'CURSORS' | 'ENTRIES'>, options: FanoutOptions = {}): Promise<ShardPlan> {
	const inputs = await loadPlanInputs(env, options);
	if (inputs.killed) return { killed: true, shards: [], logs: 0, backlog: 0 };
	return {
		killed: false,
		shards: partitionLogs(inputs.logIds, inputs.behind, options.shards ?? SHARDS),
		logs: inputs.logIds.length,
		backlog: [...inputs.behind.values()].reduce((sum, n) => sum + n, 0),
	};
}

/** One tick fanned out: plan the shards, run them all at once through `tailShard`, and total what they did. */
export async function runFanout(
	env: Pick<Env, 'CURSORS' | 'ENTRIES'>,
	scheduledTime: number,
	tailShard: (request: ShardRequest) => Promise<TickSummary>,
	options: FanoutOptions = {},
): Promise<FanoutSummary> {
	const plan = await planShards(env, options);
	const summary: FanoutSummary = {
		killed: plan.killed,
		logs: plan.logs,
		backlog: plan.backlog,
		shards: plan.shards.length,
		entries: 0,
		subrequests: 0,
		failed: {},
	};
	const results = await Promise.allSettled(plan.shards.map((logIds, shard) => tailShard({ scheduledTime, shard, logIds })));
	for (const [shard, result] of results.entries()) {
		if (result.status === 'rejected') {
			summary.failed[shard] = describeError(result.reason);
			continue;
		}
		summary.entries += result.value.entries;
		summary.subrequests += result.value.subrequests;
	}
	return summary;
}
