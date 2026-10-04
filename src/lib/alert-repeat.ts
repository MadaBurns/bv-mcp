// SPDX-License-Identifier: BUSL-1.1
import type { ScheduledEnv } from '../scheduled';
import { buildAlertPayload, sendAlert } from './alerting';
import { logError } from './log';

/**
 * Repeat-alert suppression window (#1164): a persistent condition (an outage that
 * hasn't been fixed yet, an unprovisioned table) re-evaluates true on every 15-min
 * cron tick, so an alert whose REASON is unchanged would otherwise page forever
 * instead of once. Keyed on `<threshold>:<hash(normalised reason)>` so a genuinely
 * CHANGED reason under the same threshold (a different query broke) still pages
 * immediately rather than waiting out the old reason's cooldown. 24h TTL caps a
 * persistent condition to one reminder per day.
 */
const ALERT_REPEAT_COOLDOWN_SECONDS = 24 * 60 * 60;

/** KV key for a repeatable alert's cooldown marker: `<threshold>:<hash(normalised reason)>`. */
async function repeatAlertKey(threshold: string, reason: string): Promise<string> {
	const normalized = reason.replace(/\s+/g, ' ').trim().toLowerCase();
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(normalized)));
	const hash = Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
	return `alert-repeat:${threshold}:${hash}`;
}

/**
 * Gate for a repeatable alert: resolves true when the alert should be SENT this tick
 * (first occurrence of `reason` under `threshold`, or the previous occurrence's
 * cooldown has expired) and false when an identical alert already fired within the
 * window. READ-ONLY: it does not arm the cooldown. Callers send the alert and then
 * call {@link armRepeatCooldown} only if `sendAlert` reports the webhook ACCEPTED it
 * — arming before delivery let a down webhook suppress the same alert for 24 h after
 * it recovered (same delivery-gated shape as `handleClientIpHeaderAudit`).
 *
 * FAIL-OPEN TO SENDING, never suppress on a KV fault: an unbound `RATE_LIMIT`, or a
 * `get` that throws, both resolve true. A missed suppression costs one extra
 * page; a false suppression costs a silent incident — same posture as the
 * fuzzing-scan and client-ip cooldowns above/below.
 */
export async function shouldSendRepeat(env: ScheduledEnv, threshold: string, reason: string): Promise<boolean> {
	if (!env.RATE_LIMIT) return true;

	try {
		const existing = await env.RATE_LIMIT.get(await repeatAlertKey(threshold, reason));
		if (existing !== null) return false; // identical reason already paged within the window
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'warn',
			category: 'scheduled',
			details: { message: 'alert_repeat_kv_get_failed', threshold },
		});
	}
	return true; // not seen, or KV down — send rather than risk a silent suppression
}

/**
 * Arm the {@link shouldSendRepeat} cooldown for `reason` under `threshold`. Call ONLY
 * after the webhook accepted the alert. A failed write is logged and swallowed: the
 * next tick re-alerts, which is the acceptable degradation (fail open).
 */
export async function armRepeatCooldown(env: ScheduledEnv, threshold: string, reason: string, nowMs: number): Promise<void> {
	if (!env.RATE_LIMIT) return;
	try {
		const previousReason = await env.RATE_LIMIT.get(`alert-active:${threshold}`);
		if (previousReason !== null && previousReason !== reason) {
			await env.RATE_LIMIT.delete(await repeatAlertKey(threshold, previousReason));
		}
		await env.RATE_LIMIT.put(`alert-active:${threshold}`, reason);
		await env.RATE_LIMIT.put(await repeatAlertKey(threshold, reason), String(nowMs), { expirationTtl: ALERT_REPEAT_COOLDOWN_SECONDS });
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'warn',
			category: 'scheduled',
			details: { message: 'alert_repeat_kv_put_failed', threshold },
		});
	}
}

/** Retain incident state beyond the daily reminder TTL; clear only after recovery delivery. */
export async function recoverRepeatAlert(env: ScheduledEnv, webhookUrl: string, threshold: string): Promise<void> {
	if (!env.RATE_LIMIT) return;
	try {
		const key = `alert-active:${threshold}`;
		const reason = await env.RATE_LIMIT.get(key);
		if (reason === null) return;
		const delivered = await sendAlert(
			webhookUrl,
			buildAlertPayload({ title: `Alert recovered: ${threshold}`, severity: 'warning', metrics: { previous_reason: reason }, threshold }),
			{ bvWeb: env.BV_WEB },
		);
		if (delivered) {
			await env.RATE_LIMIT.delete(await repeatAlertKey(threshold, reason));
			await env.RATE_LIMIT.delete(key);
		}
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'warn',
			category: 'scheduled',
			details: { message: 'alert_recovery_failed', threshold },
		});
	}
}
