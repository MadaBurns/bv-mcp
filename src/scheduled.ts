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
}

const DEFAULT_ERROR_THRESHOLD = 5;
const DEFAULT_P95_THRESHOLD = 10_000;
const DEFAULT_RATE_LIMIT_THRESHOLD = 50;
const DEFAULT_LOOKBACK_MINUTES = 15;

/** Main scheduled handler — called by Cron Trigger. */
export async function handleScheduled(env: ScheduledEnv): Promise<void> {
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

/**
 * Daily tier digest — sends a summary of per-tier usage to the alert webhook.
 * Called by a separate daily Cron Trigger (e.g., `0 8 * * *`).
 */
export async function handleDailyDigest(env: ScheduledEnv): Promise<void> {
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
