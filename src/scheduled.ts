// SPDX-License-Identifier: BUSL-1.1

/**
 * Cron Trigger handler for periodic analytics alerting.
 *
 * Queries Analytics Engine SQL API for recent anomalies and sends
 * Slack/Discord webhook alerts when thresholds are breached.
 *
 * Required env vars: CF_ACCOUNT_ID, CF_ANALYTICS_TOKEN, ALERT_WEBHOOK_URL
 * Optional env vars: ALERT_ERROR_THRESHOLD (default 5%), ALERT_P95_THRESHOLD (default 10000ms),
 *   ALERT_RATE_LIMIT_THRESHOLD (default 50 hits), ALERT_LOOKBACK_MINUTES (default 15)
 */

import { queryRecentAnomalies, queryRateLimitSurge, queryTierDigest } from './lib/analytics-queries';
import { buildAlertPayload, buildDigestPayload, sendAlert } from './lib/alerting';
import { queryAnalyticsEngine } from './lib/analytics-engine';
import { logEvent, logError } from './lib/log';
import { scoreWindow } from './lib/fuzzing-detector';
import { readWindow } from './lib/fuzzing-counter';
import { buildFuzzingAlertPayload } from './schemas/alerting';
import { FUZZ_THRESHOLDS } from './lib/config';
import { reapStuckBrandAudits } from './lib/brand-audit-reaper';
import { runSpfCanary, shouldAlertOnCanary } from './lib/spf-canary';

interface AnomalyRow {
	total_calls?: number;
	error_count?: number;
	error_pct?: number;
	p95_ms?: number;
}

interface RateLimitRow {
	total_hits?: number;
}

export interface ScheduledEnv {
	CF_ACCOUNT_ID?: string;
	CF_ANALYTICS_TOKEN?: string;
	ALERT_WEBHOOK_URL?: string;
	ALERT_ERROR_THRESHOLD?: string;
	ALERT_P95_THRESHOLD?: string;
	ALERT_RATE_LIMIT_THRESHOLD?: string;
	ALERT_LOOKBACK_MINUTES?: string;
	ALERT_SPF_NULL_RATE_THRESHOLD?: string;
	RATE_LIMIT?: KVNamespace;
	BRAND_AUDIT_DB?: D1Database;
	INTELLIGENCE_DB?: D1Database;
}

const DEFAULT_ERROR_THRESHOLD = 5;
const DEFAULT_P95_THRESHOLD = 10_000;
const DEFAULT_RATE_LIMIT_THRESHOLD = 50;
const DEFAULT_LOOKBACK_MINUTES = 15;

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
		await env.INTELLIGENCE_DB
			.prepare("DELETE FROM mcp_access_log WHERE created_at < (strftime('%s', 'now') - ?)")
			.bind(90 * 24 * 3600)
			.run()
			.catch((err) => {
				logError(err instanceof Error ? err : String(err), {
					category: 'retention',
					details: { table: 'mcp_access_log', operation: 'delete_older_than_90d' },
				});
			});
	}

	if (!env.ALERT_WEBHOOK_URL) return;
	if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return;

	const parsedError = parseFloat(env.ALERT_ERROR_THRESHOLD ?? '');
	const errorThreshold = Number.isFinite(parsedError) ? parsedError : DEFAULT_ERROR_THRESHOLD;
	const parsedP95 = parseFloat(env.ALERT_P95_THRESHOLD ?? '');
	const p95Threshold = Number.isFinite(parsedP95) ? parsedP95 : DEFAULT_P95_THRESHOLD;
	const parsedRateLimit = parseFloat(env.ALERT_RATE_LIMIT_THRESHOLD ?? '');
	const rateLimitThreshold = Number.isFinite(parsedRateLimit) ? parsedRateLimit : DEFAULT_RATE_LIMIT_THRESHOLD;
	const lookback = env.ALERT_LOOKBACK_MINUTES ?? String(DEFAULT_LOOKBACK_MINUTES);

	try {
		const anomalyRows = await queryAnalyticsEngine(env.CF_ACCOUNT_ID, env.CF_ANALYTICS_TOKEN, queryRecentAnomalies(lookback)) as AnomalyRow[];
		const anomaly = anomalyRows[0];

		if (anomaly && anomaly.total_calls && anomaly.total_calls > 0) {
			const errorPct = anomaly.error_pct ?? 0;
			const p95Ms = anomaly.p95_ms ?? 0;

			if (errorPct > errorThreshold) {
				const severity = errorPct > errorThreshold * 2 ? 'critical' : 'warning';
				await sendAlert(
					env.ALERT_WEBHOOK_URL,
					buildAlertPayload({
						title: `Error rate ${errorPct.toFixed(1)}% (last ${lookback}m)`,
						severity,
						metrics: {
							error_pct: errorPct.toFixed(1) + '%',
							error_count: anomaly.error_count,
							total_calls: anomaly.total_calls,
							p95_ms: Math.round(p95Ms),
						},
						threshold: `error_pct > ${errorThreshold}%`,
					}),
				);
			}

			if (p95Ms > p95Threshold) {
				await sendAlert(
					env.ALERT_WEBHOOK_URL,
					buildAlertPayload({
						title: `P95 latency ${Math.round(p95Ms)}ms (last ${lookback}m)`,
						severity: p95Ms > p95Threshold * 2 ? 'critical' : 'warning',
						metrics: {
							p95_ms: Math.round(p95Ms),
							total_calls: anomaly.total_calls,
						},
						threshold: `p95_ms > ${p95Threshold}ms`,
					}),
				);
			}
		}

		const rateLimitRows = await queryAnalyticsEngine(
			env.CF_ACCOUNT_ID,
			env.CF_ANALYTICS_TOKEN,
			queryRateLimitSurge(lookback),
		) as RateLimitRow[];
		const rateLimitData = rateLimitRows[0];

		if (rateLimitData && (rateLimitData.total_hits ?? 0) > rateLimitThreshold) {
			await sendAlert(
				env.ALERT_WEBHOOK_URL,
				buildAlertPayload({
					title: `Rate limit surge: ${rateLimitData.total_hits} hits (last ${lookback}m)`,
					severity: (rateLimitData.total_hits ?? 0) > rateLimitThreshold * 3 ? 'critical' : 'warning',
					metrics: { total_hits: rateLimitData.total_hits },
					threshold: `rate_limit_hits > ${rateLimitThreshold}`,
				}),
			);
		}

		logEvent({
			timestamp: new Date().toISOString(),
			category: 'scheduled',
			result: 'ok',
			severity: 'info',
			details: {
				message: 'Analytics alerting check completed',
				errorPct: anomaly?.error_pct ?? 0,
				p95Ms: anomaly?.p95_ms ?? 0,
				rateLimitHits: rateLimitData?.total_hits ?? 0,
			},
		});
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			category: 'scheduled',
			details: { message: 'Analytics alerting check failed' },
		});
	}
}

/** Send a fuzzing alert as a JSON payload — separate from sendAlert which is Slack-shaped. */
async function sendFuzzingAlert(webhookUrl: string, payload: import('./schemas/alerting').FuzzingAlert): Promise<void> {
	if (!webhookUrl) return;
	try {
		const parsed = new URL(webhookUrl);
		if (parsed.protocol !== 'https:') return;
	} catch {
		return;
	}
	try {
		await fetch(webhookUrl, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload),
			redirect: 'manual',
			// Bound the operator webhook so a stalled endpoint can't hang the 15-min
			// cron tick (parity with sendAlert in lib/alerting.ts).
			signal: AbortSignal.timeout(5_000),
		});
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'warn',
			category: 'alerting',
			details: { message: 'fuzz_alert_dispatch_failed' },
		});
	}
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
	if (!env.ALERT_WEBHOOK_URL || !env.RATE_LIMIT) return;

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
			await sendFuzzingAlert(env.ALERT_WEBHOOK_URL, payload);
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
	// outbound DoH probes and depends only on ALERT_WEBHOOK_URL for delivery.
	await handleSpfCanary(env);

	if (!env.ALERT_WEBHOOK_URL) return;
	if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return;

	try {
		const rows = await queryAnalyticsEngine(env.CF_ACCOUNT_ID, env.CF_ANALYTICS_TOKEN, queryTierDigest('1'));
		const payload = buildDigestPayload(rows, 1);
		await sendAlert(env.ALERT_WEBHOOK_URL, payload);

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
		const threshold = Number.isFinite(rawThreshold) && rawThreshold > 0 && rawThreshold <= 1
			? rawThreshold
			: DEFAULT_SPF_NULL_RATE_THRESHOLD;

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

		if (!env.ALERT_WEBHOOK_URL) return;
		if (!shouldAlertOnCanary(result, threshold)) return;

		await sendAlert(
			env.ALERT_WEBHOOK_URL,
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
export async function handleBrandAuditWatches(
	env: Record<string, unknown>,
	_ctx: ExecutionContext,
): Promise<void> {
	const e = env as BrandAuditWatchEnv;
	if (!e.BRAND_AUDIT_DB || !e.BRAND_AUDIT_QUEUE) return;
	const now = Date.now();

	let rows: DueWatchRow[] = [];
	try {
		const result = await e.BRAND_AUDIT_DB
			.prepare(
				'SELECT id, owner_id, domain, interval, webhook_url, last_run_at, last_classification_hash FROM brand_audit_watches WHERE active = 1 ORDER BY last_run_at ASC NULLS FIRST LIMIT ?',
			)
			.bind(MAX_WATCHES_PER_TICK)
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
		const interval = INTERVAL_MS[row.interval];
		if (row.last_run_at !== null && now - row.last_run_at < interval) {
			continue;
		}
		try {
			const auditId = crypto.randomUUID();
			// One-target batch — every watch is single-domain.
			await e.BRAND_AUDIT_QUEUE.send(
				{ auditId, target: row.domain, format: 'json', watchId: row.id, ownerId: row.owner_id },
				{ contentType: 'json' },
			);
			await e.BRAND_AUDIT_DB
				.prepare('UPDATE brand_audit_watches SET last_run_at = ? WHERE id = ?')
				.bind(now, row.id)
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
