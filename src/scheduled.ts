// SPDX-License-Identifier: BUSL-1.1

/**
 * Cron Trigger handler for periodic analytics alerting.
 *
 * Queries Analytics Engine SQL API for recent anomalies and sends
 * Slack/Discord webhook alerts when thresholds are breached.
 *
 * Required env vars: CF_ACCOUNT_ID, CF_ANALYTICS_TOKEN, ALERT_WEBHOOK_URL
 * Optional env vars: ALERT_ERROR_THRESHOLD (default 5%), ALERT_MIN_ERROR_SAMPLES (default 20),
 *   ALERT_P95_THRESHOLD (default 15000ms), ALERT_RATE_LIMIT_THRESHOLD (default 50 hits),
 *   ALERT_LOOKBACK_MINUTES (default 15)
 *
 * Every RATE-based lane here pairs its threshold with a minimum-sample floor and
 * abstains below it. A percentage over a handful of events is not a measurement, and
 * a threshold cannot tell a real 100% from a single stray call. Absolute-count lanes
 * (tail exceptions, binding degradation, queue failures) carry the low-volume case.
 */

import {
	queryRecentAnomalies,
	queryLatencyByWorkloadClass,
	queryRateLimitSurge,
	queryTierDigest,
	queryBindingDegradation,
	queryQueueFailures,
	queryTailExceptions,
	resolveAnalyticsDataset,
} from './lib/analytics-queries';
import { buildAlertPayload, buildDigestPayload, sendAlert, sendFuzzingAlert } from './lib/alerting';
import type { SendAlertOptions } from './lib/alerting';
import { queryAnalyticsEngine } from './lib/analytics-engine';
import { logEvent, logError } from './lib/log';
import { scoreWindow } from './lib/fuzzing-detector';
import { readWindow } from './lib/fuzzing-counter';
import { buildFuzzingAlertPayload } from './schemas/alerting';
import { FUZZ_THRESHOLDS } from './lib/config';
import { reapStuckBrandAudits } from './lib/brand-audit-reaper';
import { runSpfCanary, shouldAlertOnCanary } from './lib/spf-canary';
import { resolveAlertWebhookUrl } from './lib/operator-webhook-binding';

interface AnomalyRow {
	total_calls?: number;
	error_count?: number;
	/** Pre-dispatch arg-validation rejections (blob4='none') — no tool ran. */
	input_error_count?: number;
	/** Errors from tools that actually EXECUTED (blob4!='none') — the honest signal. */
	real_error_count?: number;
	error_pct?: number;
	real_error_pct?: number;
	p95_ms?: number;
}

interface LatencyRow {
	workload_class?: string;
	total_calls?: number;
	p95_ms?: number;
	max_ms?: number;
}

interface RateLimitRow {
	total_hits?: number;
}

interface BindingDegradationRow {
	component?: string;
	degradation_type?: string;
	event_count?: number;
}

interface QueueFailureRow {
	handler?: string;
	batch_count?: number;
	error_batch_count?: number;
	failure_count?: number;
}

interface TailExceptionRow {
	exception_count?: number;
}

export interface ScheduledEnv {
	CF_ACCOUNT_ID?: string;
	CF_ANALYTICS_TOKEN?: string;
	/**
	 * Optional override for the Analytics Engine DATASET name the alert queries read
	 * FROM. Defaults in code to `bv_dns_security_mcp` (the prod dataset the
	 * `MCP_ANALYTICS` binding writes to) — see `resolveAnalyticsDataset`. Set only if a
	 * deploy writes telemetry to a differently-named dataset (e.g. local
	 * `bv_mcp_usage_reporting`). NOT the Worker binding name.
	 */
	ANALYTICS_DATASET?: string;
	ALERT_WEBHOOK_URL?: string;
	ALERT_ERROR_THRESHOLD?: string;
	ALERT_P95_THRESHOLD?: string;
	ALERT_RATE_LIMIT_THRESHOLD?: string;
	ALERT_LOOKBACK_MINUTES?: string;
	/** p95 ceiling for the BATCH/enumeration workload class (default 30000ms). Separate from ALERT_P95_THRESHOLD, which governs the interactive class. */
	ALERT_BATCH_P95_THRESHOLD?: string;
	/** Lookback for the latency lane ONLY (default 360m). Latency needs a far wider window than error-rate to collect enough samples for a percentile. */
	ALERT_LATENCY_LOOKBACK_MINUTES?: string;
	/** Minimum tool calls in a class before its p95 is believed (default 20). Below this, p95 degenerates toward max. */
	ALERT_MIN_LATENCY_SAMPLES?: string;
	/** Minimum tool calls in the error-rate window before an error PERCENTAGE is believed (default 20). Below this the lane abstains — see DEFAULT_MIN_ERROR_SAMPLES. */
	ALERT_MIN_ERROR_SAMPLES?: string;
	ALERT_SPF_NULL_RATE_THRESHOLD?: string;
	/** Min present-binding-degradation events in the lookback window to alert (default 1). */
	ALERT_BINDING_DEGRADATION_THRESHOLD?: string;
	/** Min async-path (queue/cron) failed messages/sub-tasks in the lookback window to alert (default 1). */
	ALERT_QUEUE_FAILURE_THRESHOLD?: string;
	/** Min fatal Worker exceptions exported by the tail consumer in the lookback window to alert (default 1). */
	ALERT_TAIL_EXCEPTION_THRESHOLD?: string;
	RATE_LIMIT?: KVNamespace;
	BRAND_AUDIT_DB?: D1Database;
	INTELLIGENCE_DB?: D1Database;
	/**
	 * Phase 2, decisions #8/#9 (optional). When bound, the retention cron prunes the
	 * retention-bounded `scan_rollup` table. Absent in prod's public `wrangler.jsonc`
	 * (Phase 2 ships dark) → the prune is skipped entirely, byte-for-byte unchanged.
	 */
	SCAN_SCHEDULE_DB?: D1Database;
	ANALYTICS_RETENTION_DAYS?: string;
	/**
	 * Phase 1, decision #2 (default-off). Mirrors the producer flag; carried here for
	 * config parity. The retention cron does not branch on it — the rollup is a
	 * write-path concern in `src/mcp/execute.ts`.
	 */
	ANALYTICS_ROLLUP_INTERNAL?: string;
	/**
	 * Phase 1, decision #3 (default-off). `'true'` + `MCP_ACCESS_LOG_ARCHIVE` present
	 * switches the retention cron from a hard DELETE to archive-then-delete (gzipped
	 * NDJSON, non-PII columns only) to R2. Flag off or binding absent → today's DELETE.
	 */
	ANALYTICS_ARCHIVE_ENABLED?: string;
	/** Phase 1, decision #3 — R2 object lifetime (days) for archived NDJSON. Documentation-only; enforced by the bucket lifecycle rule, not code. */
	ANALYTICS_ARCHIVE_RETENTION_DAYS?: string;
	/** Phase 1, decision #3 — R2 bucket for the short-bridge access-log archive. Absent → retention cron keeps today's hard DELETE. */
	MCP_ACCESS_LOG_ARCHIVE?: R2Bucket;
	/** Service binding to bv-web-prod. Absent on BSL self-hosts — dynamic webhook resolution falls back to ALERT_WEBHOOK_URL. */
	BV_WEB?: Fetcher;
	/** Bearer token for BV_WEB internal calls. Already a live secret on production — see docs/plans/2026-07-09-operator-alert-webhook-binding.md. */
	BV_WEB_INTERNAL_KEY?: string;
	/** General-purpose cache KV. Used here as the operator-webhook last-known-good fallback (key: operator-webhook:last-known-good, 24h TTL). */
	SCAN_CACHE?: KVNamespace;
}

/** Clamp ANALYTICS_RETENTION_DAYS to [1, 365]; default 90 on missing/invalid. */
export function clampRetentionDays(raw: string | undefined): number {
	const n = Number(raw);
	if (!Number.isFinite(n)) return 90;
	return Math.min(365, Math.max(1, Math.floor(n)));
}

/**
 * Phase 1, decision #3 — NON-PII columns archived to R2. Deliberately EXCLUDES
 * the PII-gated set (`ip_ciphertext`, `ip_key_version`, `ptr_hostname`, `city`,
 * `latitude`, `longitude`, `user_agent`). Allowlist, not denylist, so a future
 * column never leaks into the archive by default. Projection happens in code (the
 * SELECT also names these columns, but the projection is the load-bearing guard).
 */
const ARCHIVE_COLUMNS = [
	'id',
	'created_at',
	'ip_hash',
	'ip_masked',
	'tool_name',
	'domain',
	'country',
	'region',
	'asn',
	'as_org',
	'key_hash',
	'client_type',
	'colo',
	'session_hash',
	'method',
	'transport',
	'status',
	'source',
	'response_ms',
	'rate_limited',
] as const;

/** Keyset page size for the archive SELECT — bounds per-iteration memory + the gzip buffer. */
const ARCHIVE_PAGE_SIZE = 5000;

/** Project a raw access-log row to the non-PII archive shape (drops any PII column the SELECT didn't). */
function projectArchiveRow(row: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const col of ARCHIVE_COLUMNS) {
		if (col in row) out[col] = row[col];
	}
	return out;
}

/** Gzip UTF-8 text via the Workers-native CompressionStream (no Node APIs). */
async function gzipText(text: string): Promise<Uint8Array> {
	const compressed = new Response(text).body!.pipeThrough(new CompressionStream('gzip'));
	return new Uint8Array(await new Response(compressed).arrayBuffer());
}

/**
 * Phase 1, decision #3 — archive aging `mcp_access_log` rows to R2 as gzipped
 * NDJSON before the retention DELETE. Keyset-paginated by `id`; each page is a
 * separate `mcp-access-log/v1/window=<bucket>/part-NNNN.ndjson.gz` object. PII
 * columns are stripped via {@link projectArchiveRow}. Returns `true` when every
 * page archived cleanly (or threw, caught by the caller); the caller deletes only
 * on `true` so a failed archive holds the rows.
 *
 * `cutoffSeconds` is the single retention boundary (epoch seconds) computed ONCE
 * by the caller and bound verbatim to the SELECT — the same literal also drives
 * the caller's DELETE, so no statement re-evaluates `strftime('now')` and a row
 * can't cross the boundary between SELECT and DELETE (S1, TOCTOU). The R2 window
 * key derives deterministically from that boundary's day bucket, so a retried or
 * partially-failed run overwrites rather than duplicating objects (S3, idempotent).
 */
async function archiveExpiringAccessLogRows(db: D1Database, archive: R2Bucket, cutoffSeconds: number): Promise<boolean> {
	const windowBucket = Math.floor(cutoffSeconds / 86_400);
	const selectSql = `SELECT ${ARCHIVE_COLUMNS.join(', ')} FROM mcp_access_log WHERE created_at < ? AND id > ? ORDER BY id ASC LIMIT ?`;
	let lastId = 0;
	let part = 0;
	for (;;) {
		const result = await db.prepare(selectSql).bind(cutoffSeconds, lastId, ARCHIVE_PAGE_SIZE).all<Record<string, unknown>>();
		const rows = result.results ?? [];
		if (rows.length === 0) break;

		const ndjson = rows.map((row) => JSON.stringify(projectArchiveRow(row))).join('\n') + '\n';
		const key = `mcp-access-log/v1/window=${windowBucket}/part-${String(part).padStart(4, '0')}.ndjson.gz`;
		await archive.put(key, await gzipText(ndjson), {
			httpMetadata: { contentType: 'application/x-ndjson', contentEncoding: 'gzip' },
		});
		part += 1;

		const nextId = Number((rows[rows.length - 1] as { id?: unknown }).id);
		if (!Number.isFinite(nextId) || nextId <= lastId) break; // non-advancing keyset guard
		lastId = nextId;
		if (rows.length < ARCHIVE_PAGE_SIZE) break; // last (partial) page
	}
	return true;
}

const DEFAULT_ERROR_THRESHOLD = 5;
/**
 * Ceiling for the INTERACTIVE class. Derived from `SCAN_TIMEOUT_MS` (15s), not
 * picked round: `scan_domain` is ~90% of interactive volume and is designed to run
 * up to that budget, so an interactive p95 at or above it means scans are
 * systematically hitting their timeout — an incident. The previous 10s sat BELOW
 * that design envelope, leaving only ~10% headroom over the measured p95 of 8,952ms
 * (7d, 6,762 calls), so ordinary upper-normal scan latency was one blip from paging.
 */
const DEFAULT_P95_THRESHOLD = 15_000;
const DEFAULT_RATE_LIMIT_THRESHOLD = 50;
const DEFAULT_LOOKBACK_MINUTES = 15;
/**
 * Ceiling for the BATCH/enumeration class. Above `batch_scan`'s own 25s budget so a
 * tool finishing inside its documented budget is never an anomaly (#729).
 */
const DEFAULT_BATCH_P95_THRESHOLD = 30_000;
/**
 * The latency lane looks back MUCH further than the 15m error-rate lane. At the
 * measured traffic (~11 tool calls/hour) a 15m window holds ~3 calls, and
 * `quantileExactWeighted(0.95)` over 3 samples returns the MAXIMUM — the alert
 * was reporting the slowest call in the window and calling it a percentile.
 */
const DEFAULT_LATENCY_LOOKBACK_MINUTES = 360;
/**
 * Below this many samples a p95 is not a tail estimate, so the lane abstains and
 * says so in the log rather than paging on a number it cannot support.
 */
const DEFAULT_MIN_LATENCY_SAMPLES = 20;
/**
 * Minimum tool calls in the error-rate window before a PERCENTAGE computed over it
 * is believed. Not picked round — it is derived from the threshold it guards: at the
 * default 5% ceiling, 20 is the smallest denominator at which ONE error cannot trip
 * the alert (1/20 = 5.0%, which is not > 5%). Any smaller window is one stray call
 * away from paging, which is exactly what happened: `error_count: 1 total_calls: 1`
 * → 100% → `critical`, because 100 > 5 x 2.
 *
 * The same floor already guards the latency lane ({@link DEFAULT_MIN_LATENCY_SAMPLES})
 * and the per-tool error query (`HAVING total > 10` in `queryErrorRate`). The alerting
 * error lane was the one rate estimator with no denominator guard at all.
 */
const DEFAULT_MIN_ERROR_SAMPLES = 20;
/** Cron cadence in minutes (the every-15-minutes trigger). Used to evaluate the latency lane once per NON-OVERLAPPING lookback window. */
const CRON_INTERVAL_MINUTES = 15;
/** A single present-binding failure (mis-rotated key, bv-recon 5xx) is worth surfacing. */
const DEFAULT_BINDING_DEGRADATION_THRESHOLD = 1;
/** A single errored async-path batch (brand-audit queue throw, cron failure) is worth surfacing. */
const DEFAULT_QUEUE_FAILURE_THRESHOLD = 1;

/** Main scheduled handler — called by Cron Trigger. */
export async function handleScheduled(env: ScheduledEnv): Promise<void> {
	// Brand-audit reaper — safety-net for `running` rows the consumer can't
	// self-flip. The consumer's catch handler runs an `UPDATE ... status='failed'`
	// on budget exhaustion, but Cloudflare can kill the worker mid-flight when
	// the unbudgeted DNS fan-out blows the per-request CPU budget, and the
	// failure-flip never commits. This cron is the ONLY thing that can
	// resurrect those rows. Runs every 15 min, idempotent (WHERE status='running'
	// AND created_at < threshold), bounded MAX_REAP_PER_TICK.
	if (env.BRAND_AUDIT_DB) {
		try {
			const reap = await reapStuckBrandAudits({ db: env.BRAND_AUDIT_DB });
			if (reap.reapedTargets > 0 || reap.scannedRows > 0) {
				logEvent({
					timestamp: new Date().toISOString(),
					category: 'scheduled',
					result: 'brand_audit_reaper',
					severity: reap.skippedOverCap ? 'warn' : 'info',
					details: {
						scanned: reap.scannedRows,
						reaped: reap.reapedTargets,
						finalized: reap.finalizedAudits,
						skippedOverCap: reap.skippedOverCap,
					},
				});
			}
		} catch (err) {
			logError(err instanceof Error ? err : String(err), {
				category: 'scheduled',
				result: 'brand_audit_reaper_failed',
			});
		}
	}

	if (env.INTELLIGENCE_DB) {
		// S1 (TOCTOU): compute the retention boundary ONCE in JS and bind the same
		// literal to BOTH the archive SELECT and the DELETE. Neither statement calls
		// strftime('now'), so the two no longer evaluate the boundary at different
		// wall-clock instants — a row can't cross the cutoff between SELECT and DELETE
		// and get deleted without being archived (the archive-before-delete guarantee).
		const cutoffSeconds = Math.floor(Date.now() / 1000) - clampRetentionDays(env.ANALYTICS_RETENTION_DAYS) * 86_400;

		// Phase 1, decision #3: archive-then-delete. When enabled AND the R2 binding
		// is present, stream the aging rows to R2 as gzipped NDJSON (non-PII columns
		// only) before deleting. A failed archive HOLDS the rows for the next tick (no
		// data loss). Flag off or binding absent → today's hard DELETE (byte-for-byte
		// unchanged). Best-effort, fail-soft throughout.
		const archiveEnabled = env.ANALYTICS_ARCHIVE_ENABLED === 'true' && !!env.MCP_ACCESS_LOG_ARCHIVE;
		let archiveOk = true;
		if (archiveEnabled) {
			archiveOk = await archiveExpiringAccessLogRows(env.INTELLIGENCE_DB, env.MCP_ACCESS_LOG_ARCHIVE!, cutoffSeconds).catch((err) => {
				logError(err instanceof Error ? err : String(err), {
					category: 'retention',
					details: { table: 'mcp_access_log', operation: 'archive_before_delete' },
				});
				return false;
			});
		}

		if (!archiveEnabled || archiveOk) {
			await env.INTELLIGENCE_DB.prepare('DELETE FROM mcp_access_log WHERE created_at < ?')
				.bind(cutoffSeconds)
				.run()
				.catch((err) => {
					logError(err instanceof Error ? err : String(err), {
						category: 'retention',
						details: { table: 'mcp_access_log', operation: 'delete_older_than_configured' },
					});
				});
		}
	}

	// S2: bound the Phase 2 `scan_rollup` table. Entirely gated on the optional
	// SCAN_SCHEDULE_DB binding (absent in prod's public wrangler.jsonc → no-op,
	// byte-for-byte unchanged). `bucket_day` = floor(timestampMs / 86_400_000), so
	// the cutoff is the day bucket `retentionDays` ago. No-op today (no writer yet);
	// this keeps the table bounded the moment a writer lands. Best-effort, fail-soft.
	if (env.SCAN_SCHEDULE_DB) {
		const cutoffBucketDay = Math.floor((Date.now() - clampRetentionDays(env.ANALYTICS_RETENTION_DAYS) * 86_400_000) / 86_400_000);
		await env.SCAN_SCHEDULE_DB.prepare('DELETE FROM scan_rollup WHERE bucket_day < ?')
			.bind(cutoffBucketDay)
			.run()
			.catch((err) => {
				logError(err instanceof Error ? err : String(err), {
					category: 'retention',
					details: { table: 'scan_rollup', operation: 'prune_older_than_configured' },
				});
			});
	}

	// PRECEDENCE IS DELIBERATE: resolveAlertWebhookUrl prefers the dynamic
	// (bv-web-prod admin-managed) value over env.ALERT_WEBHOOK_URL when both
	// are available. Do not reorder this to "static wins" — see
	// src/lib/operator-webhook-binding.ts and
	// docs/plans/2026-07-09-operator-alert-webhook-binding.md.
	const webhookUrl = await resolveAlertWebhookUrl(env);
	if (!webhookUrl) return;
	if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return;

	// Resolve the AE DATASET name once (defaults to bv_dns_security_mcp — the prod
	// dataset the MCP_ANALYTICS binding writes to; NOT the binding name). Threaded
	// into every query builder below the same way accountId/token are.
	const dataset = resolveAnalyticsDataset(env.ANALYTICS_DATASET);

	const parsedError = parseFloat(env.ALERT_ERROR_THRESHOLD ?? '');
	const errorThreshold = Number.isFinite(parsedError) ? parsedError : DEFAULT_ERROR_THRESHOLD;
	const parsedP95 = parseFloat(env.ALERT_P95_THRESHOLD ?? '');
	const p95Threshold = Number.isFinite(parsedP95) ? parsedP95 : DEFAULT_P95_THRESHOLD;
	const parsedRateLimit = parseFloat(env.ALERT_RATE_LIMIT_THRESHOLD ?? '');
	const rateLimitThreshold = Number.isFinite(parsedRateLimit) ? parsedRateLimit : DEFAULT_RATE_LIMIT_THRESHOLD;
	const parsedBindingDegradation = parseFloat(env.ALERT_BINDING_DEGRADATION_THRESHOLD ?? '');
	const bindingDegradationThreshold = Number.isFinite(parsedBindingDegradation)
		? parsedBindingDegradation
		: DEFAULT_BINDING_DEGRADATION_THRESHOLD;
	const parsedQueueFailure = parseFloat(env.ALERT_QUEUE_FAILURE_THRESHOLD ?? '');
	const queueFailureThreshold = Number.isFinite(parsedQueueFailure) ? parsedQueueFailure : DEFAULT_QUEUE_FAILURE_THRESHOLD;
	const parsedTailException = parseFloat(env.ALERT_TAIL_EXCEPTION_THRESHOLD ?? '');
	const tailExceptionThreshold = Number.isFinite(parsedTailException) ? parsedTailException : 1;
	const lookback = env.ALERT_LOOKBACK_MINUTES ?? String(DEFAULT_LOOKBACK_MINUTES);
	const parsedBatchP95 = parseFloat(env.ALERT_BATCH_P95_THRESHOLD ?? '');
	const batchP95Threshold = Number.isFinite(parsedBatchP95) ? parsedBatchP95 : DEFAULT_BATCH_P95_THRESHOLD;
	const parsedLatencyLookback = parseInt(env.ALERT_LATENCY_LOOKBACK_MINUTES ?? '', 10);
	const latencyLookbackMinutes =
		Number.isFinite(parsedLatencyLookback) && parsedLatencyLookback > 0 ? parsedLatencyLookback : DEFAULT_LATENCY_LOOKBACK_MINUTES;
	const parsedMinSamples = parseInt(env.ALERT_MIN_LATENCY_SAMPLES ?? '', 10);
	const minLatencySamples = Number.isFinite(parsedMinSamples) && parsedMinSamples >= 0 ? parsedMinSamples : DEFAULT_MIN_LATENCY_SAMPLES;
	const parsedMinErrorSamples = parseInt(env.ALERT_MIN_ERROR_SAMPLES ?? '', 10);
	const minErrorSamples =
		Number.isFinite(parsedMinErrorSamples) && parsedMinErrorSamples >= 0 ? parsedMinErrorSamples : DEFAULT_MIN_ERROR_SAMPLES;

	// EACH QUERY GETS ITS OWN try. Running all six inside a single try meant the
	// FIRST rejection aborted the whole check, taking every later alert down with
	// it — how one malformed-SQL 422 disabled the entire alerting pipeline for 610
	// consecutive ticks (PR #708), including the fatal-exception alert. A broken
	// query's blast radius must be that query alone.
	//
	// `lane()` never rethrows: it records the failure and returns `fallback`, so the
	// lanes after it still run. What each failure costs is then reported ONCE at the
	// end — degraded (some lanes) vs the total-failure watchdog (all lanes).
	const laneFailures: Array<{ lane: string; reason: string }> = [];
	// COUNTED, not a constant (#729). The latency lane runs only on a window boundary,
	// so the number of lanes attempted varies per tick — a hardcoded total would report
	// a genuine 5-of-5 whole-pipeline outage as "5 of 6 degraded" and lose the loud
	// page. Counting also removes the bump-me-when-you-add-a-lane drift hazard.
	let lanesAttempted = 0;

	async function lane<T>(name: string, fallback: T, run: () => Promise<T>): Promise<T> {
		lanesAttempted += 1;
		try {
			return await run();
		} catch (err) {
			const reason = (err instanceof Error ? err.message : String(err)).replace(/\s+/g, ' ').trim().slice(0, 200);
			laneFailures.push({ lane: name, reason });
			logError(err instanceof Error ? err : String(err), {
				severity: 'error',
				category: 'scheduled',
				details: { message: 'Analytics alerting lane failed', lane: name },
			});
			return fallback;
		}
	}

	// Every lane below is independent: it queries, evaluates its own thresholds and
	// dispatches its own alert. A lane that throws contributes a `laneFailures` entry
	// and nothing else. A lane is a QUERY, not an alert: error-rate keeps the
	// `anomalies` lane, while latency moved to its own `latency` lane (#729) because it
	// needs a different lookback and a per-workload-class threshold.

	try {
		const anomalyRows = await lane<AnomalyRow[]>(
			'anomalies',
			[],
			async () =>
				(await queryAnalyticsEngine(env.CF_ACCOUNT_ID!, env.CF_ANALYTICS_TOKEN!, queryRecentAnomalies(lookback, dataset))) as AnomalyRow[],
		);
		const anomaly = anomalyRows[0];

		// Reader-blind self-check (log-only, non-paging). For a live service that
		// receives traffic, an anomaly query returning ZERO tool_call rows over the
		// lookback window almost always means the reader is querying the wrong/empty
		// AE dataset (the exact failure this fix addresses — binding name vs dataset
		// name) rather than a genuine traffic lull. We only LOG (never sendAlert) so a
		// genuinely idle self-host that opted into analytics can't be paged — the line
		// is greppable in tail/logpush where the misconfig is diagnosable.
		if (!anomaly || !anomaly.total_calls || anomaly.total_calls <= 0) {
			logEvent({
				timestamp: new Date().toISOString(),
				category: 'scheduled',
				result: 'ok',
				severity: 'warn',
				details: {
					message:
						'Analytics reader saw 0 tool_call rows over the lookback window — if this service is receiving traffic, the AE reader may be querying the wrong/empty dataset (check ANALYTICS_DATASET vs the MCP_ANALYTICS binding dataset).',
					dataset,
					lookbackMinutes: lookback,
				},
			});
		}

		if (anomaly && anomaly.total_calls && anomaly.total_calls > 0) {
			const totalCalls = anomaly.total_calls;
			const p95Ms = anomaly.p95_ms ?? 0;

			// JUDGE THE REAL ERROR RATE, NOT THE CONFLATED ONE.
			//
			// `error_pct` counts pre-dispatch arg-validation rejections (blob4='none') as
			// service errors. Those are a fuzzer or a probe sending a bad/absent domain to a
			// public endpoint — no tool ran, so nothing about the service was measured. The
			// split already existed in `queryErrorRate` for the per-tool report (where it
			// moved check_mx from ~16% to ~0%); the lane that actually PAGES was still
			// reading the conflated number.
			//
			// `real_error_pct` is absent on a reader pinned to an older query shape, so fall
			// back to the conflated value rather than silently reporting 0% — a fallback that
			// over-reports is safe here; one that under-reports would hide an outage.
			const errorPct = anomaly.real_error_pct ?? anomaly.error_pct ?? 0;
			const realErrorCount = anomaly.real_error_count ?? anomaly.error_count ?? 0;

			// ABSTAIN rather than page on a rate we cannot compute. A percentage over a
			// handful of calls is not a rate — at the measured traffic (~11 tool calls/hour)
			// a 15m window holds ~3 calls, so ONE stray error is 33%, and one call that is
			// also the only call is 100%. Both paged `critical` against a 5% threshold.
			//
			// This deliberately makes the lane quiet on a low-traffic deploy, and that is the
			// correct trade: at n < 20 a "100% error rate" is genuinely indistinguishable
			// from one bad probe, so there is no threshold that separates them. A real
			// low-volume incident is not left uncovered — the tail-exception, binding-
			// degradation and queue-failure lanes all alert on ABSOLUTE counts (threshold 1)
			// and so do not depend on rate inference at all. That division of labour is what
			// makes the floor safe: rate detectors abstain, count detectors cover.
			//
			// Logged (never alerted) so a permanently-quiet lane is greppable rather than
			// indistinguishable from a healthy one — same posture as the latency lane.
			if (totalCalls < minErrorSamples) {
				logEvent({
					timestamp: new Date().toISOString(),
					category: 'scheduled',
					result: 'ok',
					severity: 'info',
					details: {
						message: 'Error-rate lane abstained: too few calls for an error percentage to be meaningful.',
						totalCalls,
						realErrorCount,
						minSamples: minErrorSamples,
						lookbackMinutes: Number(lookback),
					},
				});
			} else if (errorPct > errorThreshold) {
				const severity = errorPct > errorThreshold * 2 ? 'critical' : 'warning';
				await sendAlert(
					webhookUrl,
					buildAlertPayload({
						// total_calls is in the TITLE, not just the metrics block: "5 of 11 calls"
						// reads very differently from "45.5%", and the reader sees the title first.
						// Same lesson as the latency lane (#729).
						title: `Error rate ${errorPct.toFixed(1)}% — ${realErrorCount} of ${totalCalls} calls (last ${lookback}m)`,
						severity,
						metrics: {
							real_error_pct: errorPct.toFixed(1) + '%',
							real_error_count: realErrorCount,
							// Reported so the reader can see how much of the raw error count was
							// fuzz/probe noise that the alert deliberately did NOT judge.
							input_error_count: anomaly.input_error_count ?? 0,
							total_calls: totalCalls,
							p95_ms: Math.round(p95Ms),
						},
						threshold: `real_error_pct > ${errorThreshold}% over >= ${minErrorSamples} calls`,
					}),
					alertOptions(env),
				);
			}

			// p95 is NOT alerted here any more (#729). It stays in the error payload above
			// as context, but judging it needs a wider window and a per-workload-class
			// threshold — see the `latency` lane below.
		}

		// LATENCY LANE (#729) — deliberately NOT part of the `anomalies` lane above.
		//
		// It needs a different window (a percentile needs samples the 15m error-rate
		// window does not have) and a different threshold per workload class, so it is
		// its own query and its own lane.
		//
		// Evaluated only on a NON-OVERLAPPING window boundary. A 6h lookback read every
		// 15m would re-report the same slow window up to 24 times — turning one true
		// finding into 24 pages, which is the failure this issue is about, with the sign
		// flipped. The trade-off is that a missed cron tick skips that window entirely;
		// for a trend alert that is the right way to be wrong.
		const minutesSinceEpoch = Math.floor(Date.now() / 60_000);
		const atLatencyWindowBoundary = minutesSinceEpoch % latencyLookbackMinutes < CRON_INTERVAL_MINUTES;

		if (atLatencyWindowBoundary) {
			const latencyRows = await lane<LatencyRow[]>(
				'latency',
				[],
				async () =>
					(await queryAnalyticsEngine(
						env.CF_ACCOUNT_ID!,
						env.CF_ANALYTICS_TOKEN!,
						queryLatencyByWorkloadClass(String(latencyLookbackMinutes), dataset),
					)) as LatencyRow[],
			);

			for (const row of latencyRows) {
				const workloadClass = row.workload_class === 'batch' ? 'batch' : 'interactive';
				const calls = row.total_calls ?? 0;
				const p95 = row.p95_ms ?? 0;
				const classThreshold = workloadClass === 'batch' ? batchP95Threshold : p95Threshold;

				// ABSTAIN rather than page on a percentile we cannot compute. At n below the
				// floor, quantileExactWeighted(0.95) converges on the MAXIMUM, so a single
				// long call becomes "the p95" — measured at ~3 calls per 15m window, that is
				// exactly how a tool running inside its own budget paged `critical`.
				// Logged (never alerted) so a permanently-quiet lane is greppable rather
				// than indistinguishable from a healthy one.
				if (calls < minLatencySamples) {
					logEvent({
						timestamp: new Date().toISOString(),
						category: 'scheduled',
						result: 'ok',
						severity: 'info',
						details: {
							message: 'Latency lane abstained: too few samples for a p95 to be meaningful.',
							workloadClass,
							totalCalls: calls,
							minSamples: minLatencySamples,
							lookbackMinutes: latencyLookbackMinutes,
						},
					});
					continue;
				}

				if (p95 > classThreshold) {
					await sendAlert(
						webhookUrl,
						buildAlertPayload({
							// total_calls is in the TITLE, not just the metrics block: "p95 22612ms
							// over 35 calls" reads very differently from "p95 22612ms", and the
							// reader sees the title first.
							title: `P95 latency ${Math.round(p95)}ms over ${calls} ${workloadClass} calls (last ${latencyLookbackMinutes}m)`,
							severity: p95 > classThreshold * 2 ? 'critical' : 'warning',
							metrics: {
								workload_class: workloadClass,
								p95_ms: Math.round(p95),
								max_ms: Math.round(row.max_ms ?? 0),
								total_calls: calls,
							},
							threshold: `p95_ms > ${classThreshold}ms (${workloadClass})`,
						}),
						alertOptions(env),
					);
				}
			}
		}

		const rateLimitRows = await lane<RateLimitRow[]>(
			'rate_limit',
			[],
			async () =>
				(await queryAnalyticsEngine(env.CF_ACCOUNT_ID!, env.CF_ANALYTICS_TOKEN!, queryRateLimitSurge(lookback, dataset))) as RateLimitRow[],
		);
		const rateLimitData = rateLimitRows[0];

		if (rateLimitData && (rateLimitData.total_hits ?? 0) > rateLimitThreshold) {
			await sendAlert(
				webhookUrl,
				buildAlertPayload({
					title: `Rate limit surge: ${rateLimitData.total_hits} hits (last ${lookback}m)`,
					severity: (rateLimitData.total_hits ?? 0) > rateLimitThreshold * 3 ? 'critical' : 'warning',
					metrics: { total_hits: rateLimitData.total_hits },
					threshold: `rate_limit_hits > ${rateLimitThreshold}`,
				}),
				alertOptions(env),
			);
		}

		// Present-binding degradation (BV_RECON / BV_TLS_PROBE 5xx / timeout). A
		// mis-rotated key or upstream outage is invisible without this — the
		// fail-soft bindings null out silently otherwise. Absent bindings and the
		// benign recon 404 never reach the `degradation` dataset, so any row here
		// is a real, present-binding failure worth surfacing.
		const degradationRows = await lane<BindingDegradationRow[]>(
			'binding_degradation',
			[],
			async () =>
				(await queryAnalyticsEngine(
					env.CF_ACCOUNT_ID!,
					env.CF_ANALYTICS_TOKEN!,
					queryBindingDegradation(lookback, dataset),
				)) as BindingDegradationRow[],
		);
		const totalDegradations = degradationRows.reduce((sum, r) => sum + (r.event_count ?? 0), 0);

		if (totalDegradations >= bindingDegradationThreshold) {
			const components = [...new Set(degradationRows.map((r) => r.component ?? 'unknown'))].join(', ');
			const breakdown = degradationRows
				.map((r) => `${r.component ?? 'unknown'}:${r.degradation_type ?? 'unknown'}=${r.event_count ?? 0}`)
				.join(' · ');
			// The degradation dataset now carries both service-binding failures and the
			// global cost-ceiling degraded-fallback signal (cost_ceiling_degraded /
			// component global_cost_ceiling). Title the alert per whichever signals are
			// present so a cost-ceiling outage doesn't read as a binding failure.
			const hasCostCeiling = degradationRows.some((r) => r.degradation_type === 'cost_ceiling_degraded');
			const hasBinding = degradationRows.some((r) => r.degradation_type !== 'cost_ceiling_degraded');
			const subject =
				hasCostCeiling && hasBinding ? 'Degradation' : hasCostCeiling ? 'Global cost-ceiling degraded' : 'Service-binding degradation';
			await sendAlert(
				webhookUrl,
				buildAlertPayload({
					title: `${subject}: ${totalDegradations} event(s) (${components}, last ${lookback}m)`,
					severity: totalDegradations > bindingDegradationThreshold * 5 ? 'critical' : 'warning',
					metrics: { total_events: totalDegradations, breakdown: breakdown || '(none)' },
					threshold: `binding_degradation_events >= ${bindingDegradationThreshold}`,
				}),
				alertOptions(env),
			);
		}

		// Async-path (queue/cron) batch failures. The brand-audit queue consumer,
		// the tenant-scan consumer, and the cron sweep emit a `queue_batch` event
		// per run; an errored batch or any failed sub-task is otherwise invisible to
		// `queryRecentAnomalies` (which only sees `tool_call`). Surface it here so a
		// queue retry-storm or a cron that keeps throwing is alertable.
		const queueFailureRows = await lane<QueueFailureRow[]>(
			'queue_failures',
			[],
			async () =>
				(await queryAnalyticsEngine(
					env.CF_ACCOUNT_ID!,
					env.CF_ANALYTICS_TOKEN!,
					queryQueueFailures(lookback, dataset),
				)) as QueueFailureRow[],
		);
		const totalQueueFailures = queueFailureRows.reduce((sum, r) => sum + (r.failure_count ?? 0), 0);
		const totalErrorBatches = queueFailureRows.reduce((sum, r) => sum + (r.error_batch_count ?? 0), 0);

		if (totalQueueFailures >= queueFailureThreshold || totalErrorBatches > 0) {
			const handlers = [...new Set(queueFailureRows.map((r) => r.handler ?? 'unknown'))].join(', ');
			const breakdown = queueFailureRows
				.map((r) => `${r.handler ?? 'unknown'}:errors=${r.error_batch_count ?? 0}/failures=${r.failure_count ?? 0}`)
				.join(' · ');
			await sendAlert(
				webhookUrl,
				buildAlertPayload({
					title: `Async-path failures: ${totalQueueFailures} failed message(s), ${totalErrorBatches} errored batch(es) (${handlers}, last ${lookback}m)`,
					severity: totalQueueFailures > queueFailureThreshold * 5 || totalErrorBatches > 5 ? 'critical' : 'warning',
					metrics: {
						queue_failures: totalQueueFailures,
						error_batches: totalErrorBatches,
						breakdown: breakdown || '(none)',
					},
					threshold: `queue_failures >= ${queueFailureThreshold}`,
				}),
				alertOptions(env),
			);
		}

		const tailExceptionRows = await lane<TailExceptionRow[]>(
			'tail_exceptions',
			[],
			async () =>
				(await queryAnalyticsEngine(
					env.CF_ACCOUNT_ID!,
					env.CF_ANALYTICS_TOKEN!,
					queryTailExceptions(lookback, dataset),
				)) as TailExceptionRow[],
		);
		const tailExceptionCount = tailExceptionRows[0]?.exception_count ?? 0;

		if (tailExceptionCount >= tailExceptionThreshold) {
			await sendAlert(
				webhookUrl,
				buildAlertPayload({
					title: `Fatal Worker exceptions: ${tailExceptionCount} event(s) (last ${lookback}m)`,
					severity: tailExceptionCount > tailExceptionThreshold * 5 ? 'critical' : 'warning',
					metrics: { exception_count: tailExceptionCount },
					threshold: `tail_exceptions >= ${tailExceptionThreshold}`,
				}),
				alertOptions(env),
			);
		}

		// EVERY lane failed ⇒ this is a whole-pipeline outage (expired token, AE down,
		// network), not several coincidental query bugs. Throw to the watchdog below so
		// it keeps its single loud page rather than fragmenting into degraded notices.
		if (lanesAttempted > 0 && laneFailures.length >= lanesAttempted) {
			throw new Error(laneFailures[0].reason);
		}

		// SOME lanes failed ⇒ partial outage. The surviving alerts have already been
		// dispatched above; say which lanes are blind and why, so a broken query is
		// visible on its own rather than only as an absence of alerts. Non-critical:
		// the pipeline is still working, just not completely.
		if (laneFailures.length > 0) {
			await sendAlert(
				webhookUrl,
				buildAlertPayload({
					title: `Alerting check degraded: ${laneFailures.length} of ${lanesAttempted} analytics queries failed`,
					severity: 'warning',
					metrics: {
						failed_lanes: laneFailures.map((f) => f.lane).join(', '),
						detail: laneFailures
							.map((f) => `${f.lane}: ${f.reason}`)
							.join(' · ')
							.slice(0, 400),
					},
					threshold: 'alerting_lane_partial_failure',
				}),
				alertOptions(env),
			).catch(() => {});
		}

		logEvent({
			timestamp: new Date().toISOString(),
			category: 'scheduled',
			result: 'ok',
			severity: laneFailures.length > 0 ? 'warn' : 'info',
			details: {
				message: laneFailures.length > 0 ? 'Analytics alerting check completed with degraded lanes' : 'Analytics alerting check completed',
				failedLanes: laneFailures.map((f) => f.lane).join(', '),
				errorPct: anomaly?.error_pct ?? 0,
				p95Ms: anomaly?.p95_ms ?? 0,
				rateLimitHits: rateLimitData?.total_hits ?? 0,
				bindingDegradations: totalDegradations,
				queueFailures: totalQueueFailures,
				tailExceptions: tailExceptionCount,
			},
		});
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			category: 'scheduled',
			details: { message: 'Analytics alerting check failed' },
		});
		// Watchdog: the alerting pipeline ITSELF failed (AE query error, expired
		// token, network) — every threshold alert above is silently disabled.
		// The webhook is configured (guard at the top of this function), so page
		// through it. Best-effort: if the webhook is down too there is nothing
		// left to do in-band.
		//
		// CARRY THE REASON. A watchdog that pages "could not run" with no cause forces
		// the operator to reconstruct it by probing the live API by hand — measured
		// cost of the 2026-08 outage, where a malformed-SQL 422 ran for the full
		// retention window looking identical to an expired token. `queryAnalyticsEngine`
		// now puts the AE rejection body in the message (analytics-engine.ts), so the
		// distinguishing detail is already here; truncated to keep the payload one-line.
		const reason = (err instanceof Error ? err.message : String(err)).replace(/\s+/g, ' ').trim().slice(0, 300);
		await sendAlert(
			webhookUrl,
			buildAlertPayload({
				title: 'Alerting pipeline failure: analytics check could not run',
				severity: 'critical',
				metrics: { pipeline_failed: 1, reason: reason || '(no detail)' },
				threshold: 'alerting_self_check',
			}),
			alertOptions(env),
		).catch(() => {});
	}
}

/**
 * Transport options for this cron tick's alert dispatches.
 *
 * Passing `BV_WEB` lets `sendAlert`/`sendFuzzingAlert` deliver bv-web's own
 * ingest URL over the service binding instead of the public hostname, which the
 * zone's Cloudflare bot challenge intercepts with a 403 before the request ever
 * reaches bv-web. Undefined on BSL self-hosts, where the public-URL path is kept.
 */
function alertOptions(env: ScheduledEnv): SendAlertOptions {
	return { bvWeb: env.BV_WEB };
}

/**
 * Per-principal alert suppression window. A principal who trips the threshold
 * gets one alert; further alerts are silenced for FUZZ_ALERT_COOLDOWN_SECONDS
 * to prevent the cron job from re-firing every 15 min while the same fuzz
 * keys are still in their 10-min window. Empirical sustained attacks
 * therefore generate ~1 alert/hour rather than ~4 alerts/hour.
 */
const FUZZ_ALERT_COOLDOWN_SECONDS = 60 * 60;

/**
 * Hard ceiling on outbound webhook calls per cron tick. Caps amplification
 * when many principals trip simultaneously (e.g., distributed/rotating-IP
 * attack) and protects against Slack incoming-webhook rate limits.
 */
const MAX_ALERTS_PER_TICK = 10;

/**
 * Fuzzing-detection scan: lists every principal with recent fuzz events in
 * RATE_LIMIT KV, scores their sliding window against FUZZ_THRESHOLDS, and posts
 * a `fuzzing_suspected` alert to ALERT_WEBHOOK_URL when the verdict trips.
 *
 * M4 fix (2026-05-08): per-principal dedup via `fuzz:alerted:<principalId>` KV
 * marker (1h TTL) and a per-tick cap of MAX_ALERTS_PER_TICK to bound outbound
 * webhook fan-out under sustained or distributed attack.
 *
 * Designed to fail-soft: KV unavailable or webhook 500 must not throw.
 * See docs/plans/2026-05-07-fuzzing-detection-tdd-plan.md.
 */
export async function handleFuzzingScan(env: ScheduledEnv): Promise<void> {
	const fuzzingWebhookUrl = await resolveAlertWebhookUrl(env);
	if (!fuzzingWebhookUrl || !env.RATE_LIMIT) return;

	const nowSec = Math.floor(Date.now() / 1000);
	const observedAt = new Date().toISOString();

	// fuzz:p:<principalId>:e:<bucket>:<kind> — scan to find all unique principals.
	let cursor: string | undefined;
	const principals = new Set<string>();
	try {
		do {
			const list = await env.RATE_LIMIT.list({ prefix: 'fuzz:p:', cursor, limit: 1000 });
			for (const k of list.keys) {
				// Extract `<principalId>` between `fuzz:p:` and `:e:`.
				const rest = k.name.slice('fuzz:p:'.length);
				const eIdx = rest.indexOf(':e:');
				if (eIdx > 0) principals.add(rest.slice(0, eIdx));
			}
			cursor = list.list_complete ? undefined : list.cursor;
		} while (cursor);
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'warn',
			category: 'scheduled',
			details: { message: 'fuzz_scan_list_failed' },
		});
		return;
	}

	let alertsSent = 0;
	for (const principalId of principals) {
		if (alertsSent >= MAX_ALERTS_PER_TICK) {
			logEvent({
				timestamp: new Date().toISOString(),
				category: 'scheduled',
				severity: 'warn',
				details: { message: 'fuzz_scan_alert_cap_reached', cap: MAX_ALERTS_PER_TICK, remaining: principals.size - alertsSent },
			});
			break;
		}
		try {
			const events = await readWindow(env.RATE_LIMIT, principalId, nowSec, FUZZ_THRESHOLDS.windowSeconds);
			const verdict = scoreWindow(events, FUZZ_THRESHOLDS);
			if (!verdict.suspected) continue;

			// Per-principal cooldown: skip if we've alerted on this principal within
			// the suppression window. Fail-soft on KV errors — logging an alert is
			// preferable to silently swallowing on a transient KV blip.
			const cooldownKey = `fuzz:alerted:${principalId}`;
			let alreadyAlerted = false;
			try {
				alreadyAlerted = (await env.RATE_LIMIT.get(cooldownKey)) !== null;
			} catch {
				// KV down — proceed with alert (fail-loud rather than silent).
			}
			if (alreadyAlerted) continue;

			// principalIdHash invariant: 16 hex chars. The recorder writes either keyHash
			// (already 16 hex from tier-auth) or ipHash (`i_<hex>` from analytics).
			// Strip the `i_` prefix and pad/trim to 16 hex chars to satisfy the schema.
			const principalKind: 'ip' | 'keyHash' = principalId.startsWith('i_') ? 'ip' : 'keyHash';
			const rawHash = principalId.startsWith('i_') ? principalId.slice(2) : principalId;
			const principalIdHash = rawHash.padEnd(16, '0').slice(0, 16);
			const payload = buildFuzzingAlertPayload(verdict, { principalKind, principalIdHash, observedAt });
			await sendFuzzingAlert(fuzzingWebhookUrl, payload, alertOptions(env));
			alertsSent++;

			// Mark suppression AFTER successful dispatch attempt. sendFuzzingAlert is
			// itself fail-soft so a webhook 500 still increments the cooldown — that's
			// intentional, retrying every 15 min during an outage isn't useful.
			try {
				await env.RATE_LIMIT.put(cooldownKey, '1', { expirationTtl: FUZZ_ALERT_COOLDOWN_SECONDS });
			} catch {
				// KV write failed — next tick will alert again, acceptable degradation.
			}
		} catch (err) {
			logError(err instanceof Error ? err : String(err), {
				severity: 'warn',
				category: 'scheduled',
				details: { message: 'fuzz_scan_principal_failed', principalId: principalId.slice(0, 8) },
			});
		}
	}
}

/**
 * Daily tier digest — sends a summary of per-tier usage to the alert webhook.
 * Called by a separate daily Cron Trigger (e.g., `0 8 * * *`).
 */
export async function handleDailyDigest(env: ScheduledEnv): Promise<void> {
	// SPF canary runs even when analytics are unconfigured — it does its own
	// outbound DoH probes and resolves its own webhook URL via
	// resolveAlertWebhookUrl (dynamic-first, ALERT_WEBHOOK_URL fallback).
	await handleSpfCanary(env);

	const digestWebhookUrl = await resolveAlertWebhookUrl(env);
	if (!digestWebhookUrl) return;
	if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return;

	try {
		const rows = await queryAnalyticsEngine(
			env.CF_ACCOUNT_ID,
			env.CF_ANALYTICS_TOKEN,
			queryTierDigest('1', resolveAnalyticsDataset(env.ANALYTICS_DATASET)),
		);
		const payload = buildDigestPayload(rows, 1);
		await sendAlert(digestWebhookUrl, payload, alertOptions(env));

		logEvent({
			timestamp: new Date().toISOString(),
			category: 'scheduled',
			result: 'ok',
			severity: 'info',
			details: { message: 'Daily tier digest sent', tierCount: rows.length },
		});
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			category: 'scheduled',
			details: { message: 'Daily tier digest failed' },
		});
	}
}

/** Default null-rate threshold (15%): with 20 canaries, 3+ nulls trips it. */
const DEFAULT_SPF_NULL_RATE_THRESHOLD = 0.15;

/**
 * SPF canary — daily synthetic probe of a curated stable-SPF domain set. When
 * the null rate breaches `ALERT_SPF_NULL_RATE_THRESHOLD` (default 15%), emits a
 * webhook alert listing the failing domains so the next responder has a
 * concrete reproducer instead of a dashboard impression.
 *
 * Always logs the canary outcome — even at null=0 — so the absence of an alert
 * is distinguishable from a silently-skipped run.
 */
export async function handleSpfCanary(env: ScheduledEnv): Promise<void> {
	try {
		const result = await runSpfCanary();
		const rawThreshold = env.ALERT_SPF_NULL_RATE_THRESHOLD ? Number(env.ALERT_SPF_NULL_RATE_THRESHOLD) : NaN;
		const threshold =
			Number.isFinite(rawThreshold) && rawThreshold > 0 && rawThreshold <= 1 ? rawThreshold : DEFAULT_SPF_NULL_RATE_THRESHOLD;

		logEvent({
			timestamp: new Date().toISOString(),
			category: 'scheduled',
			result: 'spf_canary',
			severity: result.nullCount > 0 || result.errorCount > 0 ? 'warn' : 'info',
			details: {
				probed: result.totalProbed,
				nullCount: result.nullCount,
				errorCount: result.errorCount,
				nullRatePct: Number((result.nullRate * 100).toFixed(2)),
				thresholdPct: Number((threshold * 100).toFixed(2)),
				nullDomains: result.nullDomains,
				errorDomains: result.errorDomains,
			},
		});

		const spfWebhookUrl = await resolveAlertWebhookUrl(env);
		if (!spfWebhookUrl) return;
		if (!shouldAlertOnCanary(result, threshold)) return;

		await sendAlert(
			spfWebhookUrl,
			buildAlertPayload({
				title: `SPF canary null rate ${(result.nullRate * 100).toFixed(1)}% (${result.nullCount}/${result.totalProbed})`,
				severity: result.nullRate >= threshold * 2 ? 'critical' : 'warning',
				metrics: {
					probed: result.totalProbed,
					null_count: result.nullCount,
					error_count: result.errorCount,
					null_domains: result.nullDomains.join(', ') || '(none)',
					error_domains: result.errorDomains.join(', ') || '(none)',
				},
				threshold: `spf_null_rate >= ${(threshold * 100).toFixed(0)}%`,
			}),
			alertOptions(env),
		);
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			category: 'scheduled',
			details: { message: 'SPF canary failed' },
		});
	}
}

// ----------------------------------------------------------------------------
// Phase 4 (v2.21.0): brand-audit watch scheduler
// ----------------------------------------------------------------------------

/**
 * Cap on watches enumerated per cron tick. Prevents a runaway-growth scenario
 * where 10k+ watches drain the worker's wall-clock budget. Watches not picked
 * up this tick get a fair-share opportunity the next time the cron fires
 * (every 15 min).
 */
export const MAX_WATCHES_PER_TICK = 100;

/** Interval → due-after milliseconds. Used to filter `last_run_at`. */
const INTERVAL_MS: Record<'daily' | 'weekly' | 'monthly', number> = {
	daily: 24 * 60 * 60 * 1000,
	weekly: 7 * 24 * 60 * 60 * 1000,
	monthly: 30 * 24 * 60 * 60 * 1000,
};

interface DueWatchRow {
	id: string;
	owner_id: string;
	domain: string;
	interval: 'daily' | 'weekly' | 'monthly';
	webhook_url: string | null;
	last_run_at: number | null;
	last_classification_hash: string | null;
}

interface BrandAuditWatchEnv {
	BRAND_AUDIT_DB?: D1Database;
	BRAND_AUDIT_QUEUE?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
}

interface PersistedWatchAuditRow {
	owner_id: string;
	total_targets: number;
	format: string;
	target: string;
}

async function deterministicWatchAuditId(row: DueWatchRow): Promise<string> {
	const anchor = row.last_run_at === null ? 'initial' : String(row.last_run_at);
	const material = `${row.id}\0${row.owner_id}\0${row.domain}\0${anchor}`;
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(material)));
	const hex = Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
	return `watch_${hex.slice(0, 58)}`;
}

/**
 * Enumerate active brand-audit watches whose `last_run_at` is older than their
 * interval (or null), enqueue a fresh `brand_audit_batch_start` for each, and
 * bump `last_run_at` so they don't re-fire in the next tick.
 *
 * The handler does NOT compute classification-hash diffs here — that's done
 * downstream when the audit completes and the consumer compares the new
 * classification fingerprint to `last_classification_hash`. v2.21.0 ships the
 * enqueue side; the diff-and-webhook delivery side is the next slice on the
 * Phase-4 work-list.
 */
export async function handleBrandAuditWatches(env: Record<string, unknown>, _ctx: ExecutionContext): Promise<void> {
	const e = env as BrandAuditWatchEnv;
	if (!e.BRAND_AUDIT_DB || !e.BRAND_AUDIT_QUEUE) return;
	const now = Date.now();

	let rows: DueWatchRow[] = [];
	try {
		const result = await e.BRAND_AUDIT_DB.prepare(
			`SELECT id, owner_id, domain, interval, webhook_url, last_run_at, last_classification_hash
			 FROM brand_audit_watches
			 WHERE active = 1
			   AND interval IN ('daily', 'weekly', 'monthly')
			   AND (
			     last_run_at IS NULL
			     OR (interval = 'daily' AND last_run_at <= ?)
			     OR (interval = 'weekly' AND last_run_at <= ?)
			     OR (interval = 'monthly' AND last_run_at <= ?)
			   )
			 ORDER BY last_run_at ASC NULLS FIRST, id ASC
			 LIMIT ?`,
		)
			.bind(now - INTERVAL_MS.daily, now - INTERVAL_MS.weekly, now - INTERVAL_MS.monthly, MAX_WATCHES_PER_TICK)
			.all<DueWatchRow>();
		rows = result.results ?? [];
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			category: 'scheduled',
			details: { message: 'brand-audit watch enumeration failed' },
		});
		return;
	}

	for (const row of rows) {
		// SQL excludes corrupt intervals before LIMIT so they cannot consume the
		// fair-share page. Keep this runtime guard for defensive fake/adaptor rows.
		if (!Object.prototype.hasOwnProperty.call(INTERVAL_MS, row.interval)) continue;
		try {
			const auditId = await deterministicWatchAuditId(row);
			// D1 batch is transactional: the queue producer must never observe an
			// audit message before both the parent and its exact target precondition
			// exist. INSERT OR IGNORE makes an enqueue/update retry use the same rows.
			await e.BRAND_AUDIT_DB.batch([
				e.BRAND_AUDIT_DB.prepare(
					'INSERT OR IGNORE INTO brand_audits (id, owner_id, status, total_targets, completed_targets, format, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
				).bind(auditId, row.owner_id, 'queued', 1, 0, 'json', now, now),
				e.BRAND_AUDIT_DB.prepare(
					'INSERT OR IGNORE INTO brand_audit_targets (audit_id, target, status, created_at) VALUES (?, ?, ?, ?)',
				).bind(auditId, row.domain, 'queued', now),
			]);

			const persisted = (await e.BRAND_AUDIT_DB.prepare(
				`SELECT a.owner_id, a.total_targets, a.format, t.target
				 FROM brand_audits a
				 JOIN brand_audit_targets t ON t.audit_id = a.id
				 WHERE a.id = ? AND t.target = ?
				 LIMIT 1`,
			)
				.bind(auditId, row.domain)
				.first()) as PersistedWatchAuditRow | null;
			if (
				!persisted ||
				persisted.owner_id !== row.owner_id ||
				persisted.total_targets !== 1 ||
				persisted.format !== 'json' ||
				persisted.target !== row.domain
			) {
				throw new Error('brand-audit watch persistence precondition mismatch');
			}

			// One-target batch — every watch is single-domain. A successful enqueue
			// followed by a failed CAS is safe: the next tick reuses this audit ID and
			// the consumer's target claim makes the duplicate delivery idempotent.
			await e.BRAND_AUDIT_QUEUE.send(
				{ auditId, target: row.domain, format: 'json', watchId: row.id, ownerId: row.owner_id },
				{ contentType: 'json' },
			);
			await e.BRAND_AUDIT_DB.prepare('UPDATE brand_audit_watches SET last_run_at = ? WHERE id = ? AND active = 1 AND last_run_at IS ?')
				.bind(now, row.id, row.last_run_at)
				.run();
		} catch (err) {
			logError(err instanceof Error ? err : String(err), {
				severity: 'warn',
				category: 'scheduled',
				details: { message: 'brand-audit watch enqueue failed', watchId: row.id },
			});
		}
	}
}
