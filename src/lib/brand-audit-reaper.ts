// SPDX-License-Identifier: BUSL-1.1

/**
 * Brand-audit reaper.
 *
 * Backstop for the consumer-side failure mode where a target row stays in
 * `status='running'` indefinitely because the consumer's 300s
 * `Promise.race` cap fires but its failure-flip UPDATE never lands. This
 * happens when:
 *   1. The wrapping orchestrator (`brandAuditSingle`) has no AbortSignal, so
 *      Promise.race ignores the losing promise but the orchestrator keeps
 *      running and consuming the worker's wall-clock / CPU budget.
 *   2. The catch handler's `UPDATE ... SET status='failed'` runs after the
 *      worker has already exceeded its request budget and Cloudflare
 *      terminates the request before the write commits.
 *   3. (Now closed via atomic claim in the consumer) — queue redelivery
 *      stampede races on D1, leaving the row repeatedly thrashed.
 *
 * Called from the 15-minute cron handler. Targets that have been `running`
 * for longer than {@link STUCK_TARGET_THRESHOLD_MS} (measured from the consumer's
 * CLAIM, see {@link targetRunningSince}) are unambiguously stuck — no legitimate audit takes that long
 * because the consumer cap is 5 min. Flip them to `failed`, increment the
 * parent's `completed_targets` counter, and finalize the parent when its
 * `completed_targets >= total_targets`.
 *
 * Idempotency: the WHERE clause filters on `status='running'`, so a target
 * reaped on a prior tick won't be reaped again.
 *
 * Bounded per-tick: caps at {@link MAX_REAP_PER_TICK} so a sudden surge of
 * stuck rows can't dominate the cron's CPU budget. Surplus rows wait one
 * cron interval.
 */

/**
 * Targets in `running` longer than this are definitely stuck — cron-tick reaper
 * cutoff. Tightened from 15min → 10min on 2026-05-21 after the brand-beta.example.com
 * dead-zone investigation: the 300s consumer cap, plus generous grace for the
 * cap-fire macrotask + final D1 flip, plus a couple of cron-tick safety
 * margins, fits comfortably under 10 minutes. The read-path piggyback in
 * `brand_audit_status` (see {@link BRAND_AUDIT_TARGET_DEADLINE_MS}) handles
 * the polling-customer case near-instantly; this constant is the backstop for
 * audits nobody is polling (cron watches, fire-and-forget enqueues).
 */
export const STUCK_TARGET_THRESHOLD_MS = 10 * 60 * 1000;

/**
 * Per-target running-budget deadline used by the read path
 * (`brand_audit_status`, `brand_audit_get_report`) to synthesise `failed` for
 * targets whose consumer could no longer self-flip. Set to the consumer cap
 * (300s) plus 120s of grace — accounts for cap-fire macrotask + D1
 * catch-handler UPDATE when microtasks are partially starved.
 *
 * Aged from the consumer's claim ({@link targetRunningSince}), NOT from enqueue:
 * queue delivery lag / serial processing of a large batch is time the target
 * spent `queued`, not running, and must not count against its budget.
 *
 * 7 minutes leaves a buffer wide enough that a legitimate 5-minute audit
 * isn't truncated by a polling read at the cliff. Anything older is the
 * tier-1-class hang where the worker was killed before the catch ran.
 *
 * Must remain strictly less than {@link STUCK_TARGET_THRESHOLD_MS} so the read
 * path closes the dead zone before the cron reaper would.
 */
export const BRAND_AUDIT_TARGET_DEADLINE_MS = 7 * 60 * 1000;

/**
 * When a `running` target started running, for aging purposes.
 *
 * The consumer's atomic claim stamps `completed_at` with the claim time while the
 * row is `running` (the column is otherwise unused until the row turns terminal, so
 * no schema migration is needed). Aging from `created_at` (enqueue time) instead
 * reaps late targets of a large batch, which the consumer claims serially long
 * after enqueue, within seconds of them starting. Legacy rows claimed before this
 * stamp existed have `completed_at = NULL` and fall back to `created_at`.
 */
export function targetRunningSince(row: { created_at: number; completed_at: number | null }): number {
	return row.completed_at ?? row.created_at;
}

/** Hard cap on reaps per cron tick — prevents runaway D1 spend on infra incidents. */
export const MAX_REAP_PER_TICK = 50;

export interface ReaperDeps {
	db: D1Database;
	now?: () => number;
}

export interface ReaperResult {
	scannedRows: number;
	reapedTargets: number;
	finalizedAudits: number;
	skippedOverCap: boolean;
}

interface StuckTargetRow {
	audit_id: string;
	target: string;
}

interface AuditCounterRow {
	completed_targets: number;
	total_targets: number;
}

/**
 * Reap stuck brand-audit target rows. Returns a small summary so the caller
 * can emit a telemetry log. Never throws — D1 failures cause the reaper to
 * exit early and report partial progress; the next cron tick retries.
 */
export async function reapStuckBrandAudits(deps: ReaperDeps): Promise<ReaperResult> {
	const now = (deps.now ?? Date.now)();
	const threshold = now - STUCK_TARGET_THRESHOLD_MS;
	const result: ReaperResult = {
		scannedRows: 0,
		reapedTargets: 0,
		finalizedAudits: 0,
		skippedOverCap: false,
	};

	let stuck: StuckTargetRow[];
	try {
		const rows = await deps.db
			.prepare('SELECT audit_id, target FROM brand_audit_targets WHERE status = ? AND COALESCE(completed_at, created_at) < ? LIMIT ?')
			.bind('running', threshold, MAX_REAP_PER_TICK + 1)
			.all<StuckTargetRow>();
		stuck = rows.results ?? [];
	} catch {
		return result;
	}

	result.scannedRows = stuck.length;
	if (stuck.length > MAX_REAP_PER_TICK) {
		stuck = stuck.slice(0, MAX_REAP_PER_TICK);
		result.skippedOverCap = true;
	}

	const finalizedAuditIds = new Set<string>();
	for (const row of stuck) {
		const flipped = await flipTargetFailed(deps.db, row, now);
		if (!flipped) continue;
		result.reapedTargets += 1;

		const counter = await bumpAuditCounter(deps.db, row.audit_id, now);
		if (counter && counter.completed_targets >= counter.total_targets) {
			const finalized = await finalizeAudit(deps.db, row.audit_id, now);
			if (finalized && !finalizedAuditIds.has(row.audit_id)) {
				finalizedAuditIds.add(row.audit_id);
				result.finalizedAudits += 1;
			}
		}
	}

	return result;
}

async function flipTargetFailed(db: D1Database, row: StuckTargetRow, now: number): Promise<boolean> {
	try {
		const res = await db
			.prepare(
				"UPDATE brand_audit_targets SET status = 'failed', error = ?, completed_at = ? WHERE audit_id = ? AND target = ? AND status = 'running'",
			)
			.bind(
				`reaper: target stuck >${Math.floor(STUCK_TARGET_THRESHOLD_MS / 60_000)}min; consumer cap did not flip status`,
				now,
				row.audit_id,
				row.target,
			)
			.run();
		return (res.meta?.changes ?? 0) > 0;
	} catch {
		return false;
	}
}

async function bumpAuditCounter(db: D1Database, auditId: string, now: number): Promise<AuditCounterRow | null> {
	try {
		await db
			.prepare('UPDATE brand_audits SET completed_targets = completed_targets + 1, updated_at = ? WHERE id = ?')
			.bind(now, auditId)
			.run();
		const counter = (await db
			.prepare('SELECT completed_targets, total_targets FROM brand_audits WHERE id = ? LIMIT 1')
			.bind(auditId)
			.first()) as AuditCounterRow | null;
		return counter;
	} catch {
		return null;
	}
}

async function finalizeAudit(db: D1Database, auditId: string, now: number): Promise<boolean> {
	try {
		const res = await db
			.prepare("UPDATE brand_audits SET status = 'completed', completed_at = ?, updated_at = ? WHERE id = ? AND status != 'completed'")
			.bind(now, now, auditId)
			.run();
		return (res.meta?.changes ?? 0) > 0;
	} catch {
		return false;
	}
}
