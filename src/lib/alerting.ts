// SPDX-License-Identifier: BUSL-1.1

/**
 * Webhook alerting for Slack and Discord.
 *
 * Both platforms accept { "text": "..." } or { "content": "..." } payloads.
 * We use Slack's format ({ text }) which Discord also accepts via Slack-compatible webhooks.
 * All sends are fail-open — alert delivery failures are logged, never thrown.
 */

import { logError } from './log';
import type { FuzzingAlert } from '../schemas/alerting';
import { disposeUnreadResponseBody } from './response-body';

/** Bounded timeout for webhook alert delivery so a stalled endpoint can't hang the cron. */
const ALERT_WEBHOOK_TIMEOUT_MS = 5000;

export interface AlertPayloadInput {
	title: string;
	severity: 'warning' | 'critical';
	metrics: Record<string, unknown>;
	threshold: string;
}

export interface AlertPayload {
	text: string;
	content?: string;
}

/** Build a human-readable alert payload for webhook delivery. */
export function buildAlertPayload(input: AlertPayloadInput): AlertPayload {
	const severityLabel = input.severity === 'critical' ? 'Critical' : 'Warning';
	const metricsLines = Object.entries(input.metrics)
		.map(([key, value]) => `  ${key}: ${value}`)
		.join('\n');

	const text = `[Blackveil DNS] ${severityLabel}: ${input.title}\n\nMetrics:\n${metricsLines}\n\nThreshold: ${input.threshold}\nTime: ${new Date().toISOString()}`;

	return { text, content: text };
}

/**
 * Path prefix of bv-web-prod's bv-mcp alert ingest route
 * (`POST /api/internal/ops/bv-mcp-alerts/:token`).
 *
 * Matching on the PATH alone is deliberate: it is unique to that route, so the
 * predicate stays correct across hosts (www / apex / staging) without carrying a
 * hostname allowlist that would silently stop matching when a host changes. A
 * generic Slack/Discord webhook can never collide with it.
 */
const BV_WEB_INGEST_PATH_PREFIX = '/api/internal/ops/bv-mcp-alerts/';

export interface SendAlertOptions {
	/**
	 * bv-web-prod service binding. When present AND the webhook URL is the bv-web
	 * ingest route, delivery goes over the binding instead of the public URL.
	 */
	bvWeb?: Fetcher;
}

/** True when this webhook URL is bv-web-prod's own alert ingest route. */
export function isBvWebIngestUrl(webhookUrl: string): boolean {
	try {
		return new URL(webhookUrl).pathname.startsWith(BV_WEB_INGEST_PATH_PREFIX);
	} catch {
		return false;
	}
}

/**
 * Send an alert payload to a webhook URL. Fail-open — never throws.
 *
 * Returns whether the alert was ACCEPTED (2xx). Callers use this to emit a
 * delivery-failure signal on a channel that does not itself depend on the
 * webhook; a `void` return is what let a dead webhook go unnoticed for days.
 *
 * DISPATCH: when `options.bvWeb` is bound and the URL is bv-web's ingest route,
 * the POST goes over the service binding. Worker-originated fetches to the
 * public hostname are intercepted by the zone's Cloudflare bot challenge and
 * returned as 403 before ever reaching bv-web; service bindings bypass the edge.
 * Any other URL — and every deployment without the binding, e.g. BSL
 * self-hosts — keeps the generic global-`fetch` path unchanged.
 */
export async function sendAlert(webhookUrl: string, payload: AlertPayload, options?: SendAlertOptions): Promise<boolean> {
	if (!webhookUrl) return false;

	try {
		const parsed = new URL(webhookUrl);
		if (parsed.protocol !== 'https:') return false;
	} catch {
		return false;
	}

	return postWebhookJson(webhookUrl, payload, options, 'Failed to deliver alert webhook');
}

/**
 * Send a fuzzing alert as a JSON payload — a different payload shape from
 * {@link sendAlert}, but the SAME transport, guards, and dispatch rules.
 *
 * Lives here rather than in scheduled.ts so it shares one dispatch path (it
 * previously hand-rolled its own and, critically, discarded the response
 * entirely — a rejected fuzzing alert was completely silent, not even logged).
 */
export async function sendFuzzingAlert(webhookUrl: string, payload: FuzzingAlert, options?: SendAlertOptions): Promise<boolean> {
	if (!webhookUrl) return false;

	try {
		const parsed = new URL(webhookUrl);
		if (parsed.protocol !== 'https:') return false;
	} catch {
		return false;
	}

	return postWebhookJson(webhookUrl, payload, options, 'fuzz_alert_dispatch_failed');
}

/**
 * Shared POST used by every webhook sender. Fail-open: returns whether the
 * endpoint ACCEPTED the payload (2xx), never throws.
 *
 * `transport` is recorded on both failure paths because "403 over public_url"
 * and "403 over service_binding" have completely different causes — the former
 * is the edge bot challenge, the latter would be a real bv-web rejection.
 */
async function postWebhookJson(
	webhookUrl: string,
	body: unknown,
	options: SendAlertOptions | undefined,
	failureMessage: string
): Promise<boolean> {
	const binding = options?.bvWeb && isBvWebIngestUrl(webhookUrl) ? options.bvWeb : undefined;
	const transport = binding ? 'service_binding' : 'public_url';

	try {
		const init: RequestInit = {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
			redirect: 'manual',
			signal: AbortSignal.timeout(ALERT_WEBHOOK_TIMEOUT_MS),
		};
		const response = binding ? await binding.fetch(webhookUrl, init) : await fetch(webhookUrl, init);
		try {
			if (!response.ok) {
				logError(`Alert webhook returned HTTP ${response.status}`, {
					severity: 'warn',
					category: 'alerting',
					details: { transport },
				});
				return false;
			}
			return true;
		} finally {
			await disposeUnreadResponseBody(response);
		}
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'warn',
			category: 'alerting',
			details: { message: failureMessage, transport },
		});
		return false;
	}
}

export interface TierDigestRow {
	tier?: string;
	total_calls?: number;
	unique_domains?: number;
	unique_keys?: number;
	error_rate?: number;
	avg_latency_ms?: number;
}

/** Build a daily digest payload summarizing per-tier usage. */
export function buildDigestPayload(rows: TierDigestRow[], days: number): AlertPayload {
	const header = `[Blackveil DNS] Daily Tier Digest (${days}d)\n`;
	const timestamp = `Time: ${new Date().toISOString()}\n`;

	if (!rows.length) {
		const text = `${header}\nNo activity in the last ${days} day(s).\n\n${timestamp}`;
		return { text, content: text };
	}

	const tierLines = rows.map((r) => {
		const tier = r.tier ?? 'unknown';
		const calls = r.total_calls ?? 0;
		const domains = r.unique_domains ?? 0;
		const keys = r.unique_keys ?? 0;
		const errRate = r.error_rate != null ? `${(Number(r.error_rate) * 100).toFixed(1)}%` : 'n/a';
		const latency = r.avg_latency_ms != null ? `${Math.round(Number(r.avg_latency_ms))}ms` : 'n/a';
		return `  ${tier}: ${calls} calls, ${domains} domains, ${keys} keys, err=${errRate}, p50=${latency}`;
	});

	const totalCalls = rows.reduce((sum, r) => sum + (r.total_calls ?? 0), 0);
	const text = `${header}\nTotal: ${totalCalls} calls across ${rows.length} tier(s)\n\n${tierLines.join('\n')}\n\n${timestamp}`;

	return { text, content: text };
}
