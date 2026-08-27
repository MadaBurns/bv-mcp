// SPDX-License-Identifier: BUSL-1.1
/**
 * Fail-soft resolver for the shared operator alert webhook URL. Calls
 * bv-web-prod's admin-managed value over the existing BV_WEB service binding,
 * falling back through a KV last-known-good cache to the static
 * ALERT_WEBHOOK_URL secret when the dynamic path is absent, confirmed-empty,
 * or ambiguously failing.
 *
 * Deliberately deviates from the two-state (`T | null`) pattern in
 * src/lib/recon-binding.ts / src/lib/tls-probe-binding.ts: the internal
 * endpoint's contract requires distinguishing "confirmed nothing configured"
 * (200 {webhookUrl: null}) from "couldn't tell" (401/5xx/timeout/throw) — a
 * two-state result would collapse that distinction and either poison the
 * last-known-good cache with emptiness or treat a real outage as configured-
 * empty. See the design spec's "Architecture" section for the full rationale:
 * docs/superpowers/specs/2026-07-08-operator-alert-webhook-admin-design.md
 * (bv-web-prod repo).
 */
import type { ScheduledEnv } from './scheduled-env-types';
import { logError } from './log';
import { disposeUnreadResponseBody, readJsonResponseCapped } from './response-body';

const OPERATOR_WEBHOOK_TIMEOUT_MS = 8_000;
const OPERATOR_WEBHOOK_CACHE_KEY = 'operator-webhook:last-known-good';
const OPERATOR_WEBHOOK_URL = 'https://bv-web-internal/api/internal/ops/operator-alert-webhook';
const OPERATOR_WEBHOOK_MAX_BODY_BYTES = 16 * 1024;

function usableWebhookUrl(value: unknown): string | undefined {
	if (typeof value !== 'string') return undefined;
	const normalized = value.trim();
	return normalized.length > 0 ? normalized : undefined;
}

/**
 * Resolves the operator alert webhook URL for this cron tick. The fetch is
 * inline (not a separate `fetchOperatorWebhook` helper) because the 401-vs-
 * 5xx distinction the design requires (401 skips the KV cache read entirely,
 * 5xx consults it) needs `res.status` directly — a helper returning only the
 * three-state `string | '' | undefined` result would lose that distinction.
 *
 * PRECEDENCE IS DELIBERATE: when the dynamic fetch returns a real URL, it
 * wins even if env.ALERT_WEBHOOK_URL is also set. Do not flip this to
 * "static overrides dynamic" — that would silently revert the whole
 * rotation-without-redeploy benefit this feature exists to provide. See
 * test/operator-webhook-binding.spec.ts's precedence-regression test.
 */
export async function resolveAlertWebhookUrl(env: ScheduledEnv): Promise<string | undefined> {
	if (env.BV_WEB) {
		let res: Response | undefined;
		try {
			res = await env.BV_WEB.fetch(OPERATOR_WEBHOOK_URL, {
				method: 'GET',
				headers: env.BV_WEB_INTERNAL_KEY ? { Authorization: `Bearer ${env.BV_WEB_INTERNAL_KEY}` } : {},
				signal: AbortSignal.timeout(OPERATOR_WEBHOOK_TIMEOUT_MS),
			});
		} catch (error) {
			logError(error instanceof Error ? error : 'operator webhook fetch failed', { category: 'operator_webhook' });
		}

		if (res?.status === 401) {
			await disposeUnreadResponseBody(res);
			// Definitive client error — skip the cache entirely, straight to static var.
			return usableWebhookUrl(env.ALERT_WEBHOOK_URL);
		}

		if (res?.ok) {
			const body = await readJsonResponseCapped<{ webhookUrl?: unknown }>(res, OPERATOR_WEBHOOK_MAX_BODY_BYTES);
			const dynamicUrl = body ? usableWebhookUrl(body.webhookUrl) : undefined;
			if (dynamicUrl) {
				try {
					await env.SCAN_CACHE?.put(OPERATOR_WEBHOOK_CACHE_KEY, dynamicUrl, { expirationTtl: 86_400 });
				} catch (error) {
					// Cache health must never suppress a freshly resolved alert target.
					logError(error instanceof Error ? error : 'operator webhook cache write failed', { category: 'operator_webhook' });
				}
				return dynamicUrl;
			}
			if (body && body.webhookUrl === null) {
				// Only an explicit schema-valid null is confirmed-empty. Do not let
				// malformed, oversized, unreadable, or blank 2xx responses suppress a
				// last-known-good alert destination.
				return usableWebhookUrl(env.ALERT_WEBHOOK_URL);
			}
			// Ambiguous 2xx: consult last-known-good below.
		} else if (res) {
			await disposeUnreadResponseBody(res);
		}

		// Ambiguous (invalid 2xx, 5xx, timeout, or network throw) — consult LKG.
		try {
			const cached = usableWebhookUrl(await env.SCAN_CACHE?.get(OPERATOR_WEBHOOK_CACHE_KEY));
			if (cached) return cached;
		} catch (error) {
			// Fall through to static configuration when the optional LKG store is down.
			logError(error instanceof Error ? error : 'operator webhook cache read failed', { category: 'operator_webhook' });
		}
	}

	return usableWebhookUrl(env.ALERT_WEBHOOK_URL);
}
