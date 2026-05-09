// SPDX-License-Identifier: BUSL-1.1
import { TenantCycleAlertSchema, type TenantCycleAlert } from '../../schemas/tenant-alerts';
import { SERVER_VERSION } from '../../lib/server-version';

/**
 * Fail-soft webhook delivery for the Phase 3 tenant cycle-diff alert.
 *
 * Mirrors `sendFuzzingAlert` in src/scheduled.ts: never throws on network
 * failure — alerts are best-effort and a failed delivery must NOT cascade
 * into the cron handler. The cron itself is wired in Wave D.
 *
 * Behaviour summary:
 *   - Validates the payload via Zod first (throws on invalid producer output —
 *     defensive, indicates a bug, not a runtime issue).
 *   - Returns `{ delivered: false }` if `env.ALERT_WEBHOOK_URL` is unset
 *     (fail-open, matches existing convention).
 *   - 3-second timeout via Promise.race. Times out → `{ delivered: false }`.
 *   - Single retry on 5xx after 500 ms backoff. 4xx is terminal.
 *   - Network errors are caught, logged via console.warn, and surface as
 *     `{ delivered: false }`.
 *   - Test seam: `opts.fetchFn` lets the webhook tests inject mocks without
 *     touching global fetch.
 */

export interface TenantAlertEnv {
	ALERT_WEBHOOK_URL?: string;
}

export interface SendTenantAlertOptions {
	/** Test seam — defaults to global fetch. */
	fetchFn?: typeof fetch;
	/** Test seam — defaults to setTimeout. Used for the retry backoff. */
	sleepFn?: (ms: number) => Promise<void>;
	/** Test seam — defaults to 3000 ms. */
	timeoutMs?: number;
	/** Test seam — defaults to 500 ms. */
	retryDelayMs?: number;
}

export interface SendTenantAlertResult {
	delivered: boolean;
	status?: number;
}

const DEFAULT_TIMEOUT_MS = 3_000;
const DEFAULT_RETRY_DELAY_MS = 500;

function defaultSleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function postWithTimeout(
	url: string,
	body: string,
	fetchFn: typeof fetch,
	timeoutMs: number,
): Promise<Response | null> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const timeout = new Promise<null>((resolve) => {
			timer = setTimeout(() => resolve(null), timeoutMs);
		});
		const request = fetchFn(url, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'User-Agent': `bv-mcp/${SERVER_VERSION}`,
			},
			body,
			redirect: 'manual',
		});
		const result = await Promise.race([request, timeout]);
		return result;
	} catch (err) {
		console.warn('tenant_alert_dispatch_failed', err instanceof Error ? err.message : String(err));
		return null;
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}

/**
 * Deliver a tenant cycle-diff alert to the configured webhook.
 *
 * Throws ONLY if the payload fails Zod validation (producer bug). All
 * runtime/network failures are swallowed and surfaced as
 * `{ delivered: false }`.
 */
export async function sendTenantAlert(
	payload: TenantCycleAlert,
	env: TenantAlertEnv,
	opts: SendTenantAlertOptions = {},
): Promise<SendTenantAlertResult> {
	// Validate first — defensive guard against producer regressions.
	const parsed = TenantCycleAlertSchema.parse(payload);

	if (!env.ALERT_WEBHOOK_URL) {
		return { delivered: false };
	}

	// Sanity-check the URL up-front. Mirrors `sendFuzzingAlert` — refuse
	// non-https endpoints to avoid leaking payloads over plaintext to a
	// misconfigured webhook.
	let webhookUrl: URL;
	try {
		webhookUrl = new URL(env.ALERT_WEBHOOK_URL);
	} catch {
		return { delivered: false };
	}
	if (webhookUrl.protocol !== 'https:') return { delivered: false };

	const fetchFn = opts.fetchFn ?? fetch;
	const sleepFn = opts.sleepFn ?? defaultSleep;
	const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const retryDelayMs = opts.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;

	const body = JSON.stringify(parsed);

	const first = await postWithTimeout(env.ALERT_WEBHOOK_URL, body, fetchFn, timeoutMs);
	if (!first) {
		// Timeout or network error — fail-soft. Do not retry: timeouts on Slack
		// are typically not transient, and a second 3 s wait risks blocking the
		// cron tick.
		return { delivered: false };
	}
	if (first.status >= 200 && first.status < 300) {
		return { delivered: true, status: first.status };
	}
	if (first.status >= 500) {
		// 5xx → single retry after backoff
		await sleepFn(retryDelayMs);
		const second = await postWithTimeout(env.ALERT_WEBHOOK_URL, body, fetchFn, timeoutMs);
		if (!second) return { delivered: false };
		if (second.status >= 200 && second.status < 300) {
			return { delivered: true, status: second.status };
		}
		return { delivered: false, status: second.status };
	}
	// 3xx / 4xx → terminal fail, no retry
	return { delivered: false, status: first.status };
}
