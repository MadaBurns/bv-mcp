// SPDX-License-Identifier: BUSL-1.1

/**
 * Daily abuse watch — two alert-only signals that this server is being used as a
 * reconnaissance source by automated tooling.
 *
 *  1. A client DECLARED a watched name in its MCP `initialize` handshake. The
 *     watch list is operator-supplied (`ABUSE_WATCH_CLIENT_FRAGMENTS`); with it
 *     unset this signal is off. The name is client-controlled, so a hit is
 *     strong evidence and an absence proves nothing.
 *  2. Anonymous callers from one country were refused paid (gated) tools at
 *     least a threshold number of times in the window. This catches the renamed
 *     or nameless client the first signal cannot.
 *
 * Both are attribution signals for a human. Neither blocks, throttles or changes
 * a tier: blocking a self-declared name only teaches the caller to rename it.
 *
 * The refusal signal is grouped by country because the `rate_limit` event carries
 * no per-caller key; one busy caller and several quiet ones in the same country
 * look the same here.
 */

import type { AlertPayloadInput, SendAlertOptions } from './alerting';
import { buildAlertPayload, sendAlert } from './alerting';
import { queryAnalyticsEngine } from './analytics-engine';
import { queryAnonGatedRefusalsByCountry, queryWatchedClientSessions } from './analytics-queries';
import { logError, logEvent } from './log';

/** Window both signals look back over, in hours. Matches the daily cron cadence. */
export const ABUSE_WATCH_WINDOW_HOURS = 24;

/**
 * Default anonymous gated-tool refusals from one country in one window before
 * alerting. Deliberately conservative; override per deploy with
 * `ABUSE_WATCH_GATED_REFUSAL_THRESHOLD`.
 */
export const DEFAULT_GATED_REFUSAL_THRESHOLD = 50;

/** Upper bound on watch-list entries, so the generated query stays small. */
const MAX_WATCHED_FRAGMENTS = 10;

export interface WatchedClientRow {
	client?: string;
	country?: string;
	tier?: string;
	sessions?: number | string;
}

export interface GatedRefusalRow {
	country?: string;
	refusals?: number | string;
	tools?: number | string;
}

function count(value: number | string | undefined): number {
	const n = Number(value);
	return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * Parse the comma-separated watch list. Entries are trimmed and lowercased (the
 * stored name is lowercase), and anything that is not purely alphanumeric is
 * dropped rather than escaped.
 */
export function parseWatchedFragments(raw: string | undefined): string[] {
	if (!raw) return [];
	const fragments = raw
		.split(',')
		.map((entry) => entry.trim().toLowerCase())
		.filter((entry) => /^[a-z0-9]+$/.test(entry));
	return [...new Set(fragments)].slice(0, MAX_WATCHED_FRAGMENTS);
}

/** Resolve the refusal threshold; a missing, non-numeric or non-positive value uses the default. */
export function resolveGatedRefusalThreshold(raw: string | undefined): number {
	const parsed = Number.parseInt(raw ?? '', 10);
	return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_GATED_REFUSAL_THRESHOLD;
}

/** One alert naming every watched client seen, or `null` when none was. */
export function assessWatchedClients(rows: readonly WatchedClientRow[], windowHours = ABUSE_WATCH_WINDOW_HOURS): AlertPayloadInput | null {
	const seen = rows.filter((row) => row.client && count(row.sessions) > 0);
	if (seen.length === 0) return null;
	const total = seen.reduce((sum, row) => sum + count(row.sessions), 0);
	const breakdown = seen
		.map((row) => `${row.client} (${row.country ?? 'unknown'}, ${row.tier ?? 'anon'}) x${count(row.sessions)}`)
		.join(' · ');
	return {
		title: `Watched MCP client name declared: ${total} session(s) (last ${windowHours}h)`,
		severity: 'warning',
		metrics: { sessions: total, clients: breakdown },
		threshold: 'declared client name matches the operator watch list',
	};
}

/** One alert per country at or over the threshold. */
export function assessGatedRefusals(
	rows: readonly GatedRefusalRow[],
	threshold = DEFAULT_GATED_REFUSAL_THRESHOLD,
	windowHours = ABUSE_WATCH_WINDOW_HOURS,
): AlertPayloadInput[] {
	return rows
		.filter((row) => count(row.refusals) >= threshold)
		.map((row) => ({
			title: `Anonymous callers refused paid tools ${count(row.refusals)} times from ${row.country ?? 'unknown'} (last ${windowHours}h)`,
			severity: count(row.refusals) >= threshold * 3 ? ('critical' as const) : ('warning' as const),
			metrics: { country: row.country ?? 'unknown', refusals: count(row.refusals), distinct_tools: count(row.tools) },
			threshold: `anonymous gated_tool refusals per country >= ${threshold} in ${windowHours}h`,
		}));
}

export interface AbuseWatchEnv {
	CF_ACCOUNT_ID?: string;
	CF_ANALYTICS_TOKEN?: string;
	/** Comma-separated, lowercase alphanumeric fragments of declared client names to watch. Unset = signal off. */
	ABUSE_WATCH_CLIENT_FRAGMENTS?: string;
	/** Anonymous gated-tool refusals per country per window before alerting. Unset = the in-code default. */
	ABUSE_WATCH_GATED_REFUSAL_THRESHOLD?: string;
}

/**
 * Run both signals and send any alerts. Each signal is isolated: a failed query
 * on one is logged and does not stop the other. Never throws.
 */
export async function runAbuseWatch(env: AbuseWatchEnv, webhookUrl: string, dataset: string, options: SendAlertOptions): Promise<void> {
	if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return;
	const hours = String(ABUSE_WATCH_WINDOW_HOURS);
	const fragments = parseWatchedFragments(env.ABUSE_WATCH_CLIENT_FRAGMENTS);
	const threshold = resolveGatedRefusalThreshold(env.ABUSE_WATCH_GATED_REFUSAL_THRESHOLD);
	const alerts: AlertPayloadInput[] = [];
	const failed: string[] = [];

	if (fragments.length > 0) {
		try {
			const rows = (await queryAnalyticsEngine(
				env.CF_ACCOUNT_ID,
				env.CF_ANALYTICS_TOKEN,
				queryWatchedClientSessions(hours, fragments, dataset),
			)) as WatchedClientRow[];
			const alert = assessWatchedClients(rows);
			if (alert) alerts.push(alert);
		} catch (err) {
			failed.push('watched_clients');
			logError(err instanceof Error ? err : String(err), {
				severity: 'error',
				category: 'scheduled',
				details: { message: 'Abuse watch: watched-client query failed' },
			});
		}
	}

	try {
		const rows = (await queryAnalyticsEngine(
			env.CF_ACCOUNT_ID,
			env.CF_ANALYTICS_TOKEN,
			queryAnonGatedRefusalsByCountry(hours, dataset),
		)) as GatedRefusalRow[];
		alerts.push(...assessGatedRefusals(rows, threshold));
	} catch (err) {
		failed.push('gated_refusals');
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			category: 'scheduled',
			details: { message: 'Abuse watch: gated-refusal query failed' },
		});
	}

	for (const alert of alerts) {
		await sendAlert(webhookUrl, buildAlertPayload(alert), options);
	}

	// Always log the outcome so a quiet day is distinguishable from a skipped run,
	// and an unconfigured watch list is visible rather than silently inert.
	logEvent({
		timestamp: new Date().toISOString(),
		category: 'scheduled',
		result: failed.length === 0 ? 'ok' : 'error',
		severity: failed.length === 0 ? 'info' : 'warn',
		details: {
			message: 'Abuse watch complete',
			alerts: alerts.length,
			failedSignals: failed,
			watchListSize: fragments.length,
			gatedRefusalThreshold: threshold,
		},
	});
}
