// SPDX-License-Identifier: BUSL-1.1
import { TenantCycleAlertSchema, type TenantCycleAlert } from '../../schemas/tenant-alerts';
import { SERVER_VERSION } from '../../lib/server-version';
import { logError } from '../../lib/log';
import { isBvWebIngestUrl } from '../../lib/alerting';

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
 *   - Every non-delivered outcome (timeout, network error, or a non-2xx
 *     status after retry) emits exactly one structured warn log carrying the
 *     cycle id and the reason — never the payload body.
 *   - When the resolved webhook URL is bv-web-prod's own alert ingest route
 *     and an `opts.bvWeb` service binding is supplied, delivery goes over the
 *     binding instead of the public URL — mirrors `sendAlert` in
 *     `src/lib/alerting.ts`, reusing its `isBvWebIngestUrl` host/path match.
 *   - Test seam: `opts.fetchFn` lets the webhook tests inject mocks without
 *     touching global fetch (the public-URL path only).
 */

export interface TenantAlertEnv {
	ALERT_WEBHOOK_URL?: string;
}

export interface SendTenantAlertOptions {
	/** Test seam — defaults to global fetch. Used only when not dispatched over `bvWeb`. */
	fetchFn?: typeof fetch;
	/** Test seam — defaults to setTimeout. Used for the retry backoff. */
	sleepFn?: (ms: number) => Promise<void>;
	/** Test seam — defaults to 3000 ms. */
	timeoutMs?: number;
	/** Test seam — defaults to 500 ms. */
	retryDelayMs?: number;
	/**
	 * bv-web-prod service binding, mirrors `SendAlertOptions.bvWeb`. When present
	 * AND the resolved webhook URL is bv-web's ingest route, delivery goes over
	 * the binding instead of the public URL (see module docblock).
	 */
	bvWeb?: Fetcher;
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

/** Outcome of one POST attempt — distinguishes a real response from the two silent failure modes. */
type PostOutcome = { kind: 'response'; response: Response } | { kind: 'timeout' } | { kind: 'network' };

async function postWithTimeout(
	url: string,
	body: string,
	fetchFn: typeof fetch,
	timeoutMs: number,
	bvWeb: Fetcher | undefined,
): Promise<PostOutcome> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const timeout = new Promise<PostOutcome>((resolve) => {
			timer = setTimeout(() => resolve({ kind: 'timeout' }), timeoutMs);
		});
		// Mirrors `sendAlert`'s dispatch rule exactly: the bv-web ingest route goes
		// over the service binding (bypasses the zone's bot-challenge 403), any
		// other URL keeps the injectable `fetchFn` seam.
		const transport = bvWeb && isBvWebIngestUrl(url) ? bvWeb.fetch.bind(bvWeb) : fetchFn;
		const request = transport(url, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'User-Agent': `bv-mcp/${SERVER_VERSION}`,
			},
			body,
			redirect: 'manual',
		}).then((response): PostOutcome => ({ kind: 'response', response }));
		return await Promise.race([request, timeout]);
	} catch {
		return { kind: 'network' };
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
	const bvWeb = opts.bvWeb;

	const body = JSON.stringify(parsed);
	const cycleId = parsed.current_cycle_id;

	// One structured warn log per non-delivered outcome — never the payload body.
	const logNotDelivered = (reason: 'timeout' | 'network' | number): void => {
		logError('Tenant cycle alert webhook not delivered', {
			severity: 'warn',
			category: 'tenant_alert',
			details: { result: 'webhook_not_delivered', cycleId, reason },
		});
	};

	const first = await postWithTimeout(env.ALERT_WEBHOOK_URL, body, fetchFn, timeoutMs, bvWeb);
	if (first.kind !== 'response') {
		// Timeout or network error — fail-soft. Do not retry: timeouts on Slack
		// are typically not transient, and a second 3 s wait risks blocking the
		// cron tick.
		logNotDelivered(first.kind);
		return { delivered: false };
	}
	if (first.response.status >= 200 && first.response.status < 300) {
		return { delivered: true, status: first.response.status };
	}
	if (first.response.status >= 500) {
		// 5xx → single retry after backoff
		await sleepFn(retryDelayMs);
		const second = await postWithTimeout(env.ALERT_WEBHOOK_URL, body, fetchFn, timeoutMs, bvWeb);
		if (second.kind !== 'response') {
			logNotDelivered(second.kind);
			return { delivered: false };
		}
		if (second.response.status >= 200 && second.response.status < 300) {
			return { delivered: true, status: second.response.status };
		}
		logNotDelivered(second.response.status);
		return { delivered: false, status: second.response.status };
	}
	// 3xx / 4xx → terminal fail, no retry
	logNotDelivered(first.response.status);
	return { delivered: false, status: first.response.status };
}
