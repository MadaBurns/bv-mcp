// SPDX-License-Identifier: BUSL-1.1
/** The cron side of the bounded catch-up reader: one queue message per claimable row (src/tailer/catchup.ts documents the design). */

import type { Env } from '../index';
import { CATCHUP_KILL_KEY, CATCHUP_MAX_ROWS, SELECT_CATCHUP_KILL, SELECT_KILLED, SELECT_ROWS } from './catchup-paging';
import type { BackfillRow, CatchupRequest } from './catchup-types';
import { describeError } from './index';

export interface DispatchSummary {
	killed: boolean;
	/** Claimable rows found, and messages sent for them. */
	rows: number;
	sent: number;
	failed: string | null;
}

/**
 * The cron's work: one message per claimable row (at most CATCHUP_MAX_ROWS) on its own queue, each run by its own
 * queue-consumer invocation. The claim itself happens in runCatchup, so a message that finds the row taken does nothing.
 */
export async function dispatchCatchup(
	env: Pick<Env, 'CURSORS'>,
	queue: Pick<Queue<CatchupRequest>, 'sendBatch'>,
	scheduledTime: number,
	options: { now?: number } = {},
): Promise<DispatchSummary> {
	const db = env.CURSORS;
	const [ledger, own] = await db.batch<{ killed?: number; v?: string }>([
		db.prepare(SELECT_KILLED),
		db.prepare(SELECT_CATCHUP_KILL).bind(CATCHUP_KILL_KEY),
	]);
	if ((ledger?.results.length ?? 0) > 0 || own?.results[0]?.v === '1') return { killed: true, rows: 0, sent: 0, failed: null };
	const at = new Date(options.now ?? Date.now()).toISOString();
	// A failed read (the table missing because the migration has not been applied, say) is reported, not thrown: the
	// dispatch runs on a cron and must not fail every tick.
	let rows: BackfillRow[];
	try {
		rows = (await db.prepare(SELECT_ROWS).bind(at, CATCHUP_MAX_ROWS).all<BackfillRow>()).results;
	} catch (error) {
		return { killed: false, rows: 0, sent: 0, failed: describeError(error) };
	}
	const requests = rows.map((row) => ({
		body: { kind: 'catchup' as const, scheduledTime, logId: row.log_id, upperIndex: row.upper_index },
		contentType: 'json' as const,
	}));
	if (requests.length === 0) return { killed: false, rows: 0, sent: 0, failed: null };
	try {
		await queue.sendBatch(requests);
	} catch (error) {
		return { killed: false, rows: requests.length, sent: 0, failed: describeError(error) };
	}
	return { killed: false, rows: requests.length, sent: requests.length, failed: null };
}

export function isCatchupRequest(body: unknown): body is CatchupRequest {
	const request = body as Partial<CatchupRequest> | null;
	return (
		request?.kind === 'catchup' &&
		typeof request.scheduledTime === 'number' &&
		typeof request.logId === 'string' &&
		typeof request.upperIndex === 'number'
	);
}
