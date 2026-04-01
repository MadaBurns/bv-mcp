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
		await fetch(webhookUrl, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload),
		});
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'warn',
			category: 'alerting',
			details: { message: 'Failed to deliver alert webhook' },
		});
	}
}
