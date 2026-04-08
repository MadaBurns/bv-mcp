// SPDX-License-Identifier: BUSL-1.1

/**
 * Webhook alerting for Slack and Discord.
 *
 * Both platforms accept { "text": "..." } or { "content": "..." } payloads.
 * We use Slack's format ({ text }) which Discord also accepts via Slack-compatible webhooks.
 * All sends are fail-open — alert delivery failures are logged, never thrown.
 */

import { logError } from './log';

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

/** Send an alert payload to a webhook URL. Fail-open. */
export async function sendAlert(webhookUrl: string, payload: AlertPayload): Promise<void> {
	if (!webhookUrl) return;

	try {
		const parsed = new URL(webhookUrl);
		if (parsed.protocol !== 'https:') return;
	} catch {
		return;
	}

	try {
		const response = await fetch(webhookUrl, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload),
			redirect: 'manual',
		});
		if (!response.ok) {
			logError(`Alert webhook returned HTTP ${response.status}`, {
				severity: 'warn',
				category: 'alerting',
			});
		}
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'warn',
			category: 'alerting',
			details: { message: 'Failed to deliver alert webhook' },
		});
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
