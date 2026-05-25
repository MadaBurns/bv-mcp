// SPDX-License-Identifier: BUSL-1.1

/**
 * Tenant scanner-queue consumer (Phase 2).
 *
 * Counterpart to the producer in `src/tenants/routes.ts` (`/internal/tenants/scan`,
 * `mode === 'queue'`). For each message in a `MessageBatch`:
 *
 *   1. Validate the body against `ScanQueueMessageSchema`.
 *   2. Resolve the tenant via the existing `resolveTenant()` cache.
 *   3. Skip if a scan row for `(cycle_id, domain)` already exists (idempotent
 *      across retries — design doc §7.1).
 *   4. Call `handleToolsCall('scan_domain', {domain})` with a 20s budget.
 *   5. Persist the scan + findings rows to the per-tenant D1.
 *   6. ack() on success. throw() on transient error so Cloudflare Queue
 *      retries — until `attempts >= MAX_ATTEMPTS`, at which point we write a
 *      DLQ findings row and ack() to drain.
 *
 * Out-of-scope (deliberate): a separate writer queue. The design doc §2.2
 * leaves the door open for splitting D1 writes onto a second queue once
 * per-message Worker CPU budget proves tight; for the first cut we fold writes
 * into the scanner consumer to keep the blast radius small. If this becomes a
 * bottleneck, introduce `BV_SCAN_WRITER_QUEUE` and have the scanner emit its
 * captured `CheckResult` to it instead of inserting directly.
 */

import { ZodError } from 'zod';
import { handleToolsCall } from '../handlers/tools';
import { createAnalyticsClient } from '../lib/analytics';
import { parseScoringConfigCached } from '../lib/scoring-config';
import { parseCacheTtl, parsePerCheckTimeout, parseScanTimeout } from '../lib/config';
import { ScanQueueMessageSchema, type ScanQueueMessage } from '../schemas/tenant-internal';
import { streamScanResult } from '../lib/hooks/analytics-stream';
import { resolveTenant, type ResolverEnv } from './tenant-resolver';
import type { CheckResult } from '../lib/scoring';

/** Wall-clock budget for one message — covers handleToolsCall + the D1 inserts. */
export const QUEUE_MESSAGE_TIMEOUT_MS = 20_000;
/** After this many delivery attempts, the consumer writes a DLQ row and acks. */
export const MAX_ATTEMPTS = 3;

const SCAN_PROBE_BY_DOMAIN_SQL = 'SELECT id FROM scans WHERE cycle_id = ? AND domain = ? LIMIT 1';
const SCANS_INSERT_SQL =
	'INSERT INTO scans (id, domain, scan_at, score, grade, maturity_stage, finding_count, result_json, cycle_id) ' +
	'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
const FINDINGS_INSERT_SQL =
	'INSERT INTO findings (id, scan_id, domain, category, severity, title, detail, metadata) ' +
	'VALUES (?, ?, ?, ?, ?, ?, ?, ?)';

export type ScanQueueConsumerEnv = ResolverEnv & {
	SCAN_CACHE?: KVNamespace;
	PROFILE_ACCUMULATOR?: DurableObjectNamespace;
	MCP_ANALYTICS?: AnalyticsEngineDataset;
	PROVIDER_SIGNATURES_URL?: string;
	PROVIDER_SIGNATURES_ALLOWED_HOSTS?: string;
	PROVIDER_SIGNATURES_SHA256?: string;
	SCORING_CONFIG?: string;
	CACHE_TTL_SECONDS?: string;
	SCAN_TIMEOUT_MS?: string;
	PER_CHECK_TIMEOUT_MS?: string;
	BV_DOH_ENDPOINT?: string;
	BV_DOH_TOKEN?: string;
};

/**
 * Phase 3 cycle-progress hook. After persistScan succeeds (or after a DLQ row
 * is written) we increment tenant_cycles.completed_total so the alert sweep can
 * tell when a cycle has settled.
 *
 * Fail-soft: 0 rows affected when there's no matching tenant_cycles entry (e.g.
 * the cycle was driven by /internal/tenants/scan rather than the weekly rescan).
 * Registry D1 errors are swallowed — the scan itself already landed in the
 * tenant DB so we MUST NOT cause a queue retry on a registry hiccup.
 */
const INCREMENT_COMPLETED_SQL =
	'UPDATE tenant_cycles SET completed_total = completed_total + 1 WHERE id = ?';

async function incrementCompletedTotalIfTracked(
	env: ScanQueueConsumerEnv,
	cycleId: string,
): Promise<void> {
	const registry = (env as Record<string, unknown>).TENANT_REGISTRY_DB as D1Database | undefined;
	if (!registry) return;
	try {
		await registry.prepare(INCREMENT_COMPLETED_SQL).bind(cycleId).run();
	} catch {
		// Registry write failed — ignored intentionally.
	}
}

/** Generate a per-row id (scans, findings). */
function newRowId(): string {
	return crypto.randomUUID();
}

/** Race a promise against a wall-clock budget. Rejects with `queue_timeout` on miss. */
async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
	return Promise.race<T>([
		promise,
		new Promise<T>((_, reject) => setTimeout(() => reject(new Error('queue_timeout')), ms)),
	]);
}

/** Persist a DLQ marker so the cycle report still includes the domain. */
async function writeDlqRow(
	tenantDb: D1Database,
	msg: ScanQueueMessage,
	reason: string,
): Promise<void> {
	const scanId = newRowId();
	try {
		await tenantDb
			.prepare(SCANS_INSERT_SQL)
			.bind(scanId, msg.domain, Date.now(), 0, null, null, 1, JSON.stringify({ error: reason }), msg.cycle_id)
			.run();
		await tenantDb
			.prepare(FINDINGS_INSERT_SQL)
			.bind(newRowId(), scanId, msg.domain, 'queue', 'high', 'queue_dlq', reason, JSON.stringify({ source: 'queue_dlq', reason }))
			.run();
	} catch {
		// If even the DLQ write fails, swallow — we've exhausted retries; better
		// to drop than to wedge the queue.
	}
}

/** Persist a successful scan + its findings to the per-tenant D1. */
async function persistScan(
	tenantDb: D1Database,
	msg: ScanQueueMessage,
	captured: CheckResult | null,
): Promise<void> {
	const scanId = newRowId();
	const score = captured?.score ?? null;
	const grade = (captured as unknown as { grade?: string } | null)?.grade ?? null;
	const findingCount = captured?.findings?.length ?? 0;
	await tenantDb
		.prepare(SCANS_INSERT_SQL)
		.bind(
			scanId,
			msg.domain,
			Date.now(),
			score,
			grade,
			null,
			findingCount,
			captured ? JSON.stringify(captured) : null,
			msg.cycle_id,
		)
		.run();

	if (captured?.findings) {
		for (const f of captured.findings) {
			await tenantDb
				.prepare(FINDINGS_INSERT_SQL)
				.bind(
					newRowId(),
					scanId,
					msg.domain,
					f.category ?? 'unknown',
					f.severity ?? 'info',
					f.title ?? '',
					f.detail ?? null,
					f.metadata ? JSON.stringify(f.metadata) : null,
				)
				.run();
		}
	}
}

/**
 * Process one message. Returns:
 *   - `'ack'`     → caller should `message.ack()`
 *   - `'retry'`   → caller should rethrow to trigger Cloudflare retry
 *
 * Idempotency: a duplicate `(cycle_id, domain)` row short-circuits with `'ack'`.
 * DLQ: when `attempts >= MAX_ATTEMPTS`, writes a marker row and returns `'ack'`
 * so the queue drains. The cycle report will surface it via the high-severity
 * `queue_dlq` finding.
 */
export async function processScanMessage(
	rawBody: unknown,
	attempts: number,
	env: ScanQueueConsumerEnv,
	ctx: { waitUntil: (p: Promise<unknown>) => void },
): Promise<'ack' | 'retry'> {
	let parsed: ScanQueueMessage;
	try {
		parsed = ScanQueueMessageSchema.parse(rawBody);
	} catch (err) {
		// Malformed message — never retry-able. Try to log via DLQ if we know
		// enough to identify the tenant; otherwise just ack and drop.
		if (err instanceof ZodError) {
			// We couldn't even parse the message, so we have no tenant binding to
			// write to. Drop on the floor (queue retains delivery audit logs).
			return 'ack';
		}
		return 'ack';
	}

	let tenant;
	try {
		tenant = await resolveTenant(env, parsed.sub_tenant_id);
	} catch {
		// Tenant missing or registry unreachable — without a tenant DB we can't
		// even write a DLQ row. The cycle report won't include the domain; the
		// surrounding system already logs orchestrator-level errors.
		return 'ack';
	}

	const tenantDb = (env as Record<string, unknown>)[tenant.dbBinding] as D1Database | undefined;
	if (!tenantDb) {
		return 'ack';
	}

	// Idempotency probe — survives retries and re-deliveries without producing
	// duplicate scan rows.
	try {
		const existing = await tenantDb
			.prepare(SCAN_PROBE_BY_DOMAIN_SQL)
			.bind(parsed.cycle_id, parsed.domain)
			.first<{ id: string }>();
		if (existing) return 'ack';
	} catch {
		// Probe failed — fall through to the full path. Worst case we get a UNIQUE
		// constraint violation on insert and the message retries; better than
		// silently dropping work.
	}

	// On the LAST allowed attempt the budget can still time out — record a DLQ
	// row before acking so the cycle isn't silently incomplete.
	const isLastAttempt = attempts >= MAX_ATTEMPTS;

	const cacheTtlSeconds = parsed.runtime_options?.cacheTtlSeconds ?? parseCacheTtl(env.CACHE_TTL_SECONDS);
	const runtimeOptions = {
		providerSignaturesUrl: env.PROVIDER_SIGNATURES_URL,
		providerSignaturesAllowedHosts: env.PROVIDER_SIGNATURES_ALLOWED_HOSTS?.split(',')
			.map((h) => h.trim())
			.filter(Boolean),
		providerSignaturesSha256: env.PROVIDER_SIGNATURES_SHA256,
		analytics: createAnalyticsClient(env.MCP_ANALYTICS),
		profileAccumulator: env.PROFILE_ACCUMULATOR,
		waitUntil: ctx.waitUntil,
		scoringConfig: parseScoringConfigCached(env.SCORING_CONFIG),
		cacheTtlSeconds,
		scanTimeoutMs: parseScanTimeout(env.SCAN_TIMEOUT_MS),
		perCheckTimeoutMs: parsePerCheckTimeout(env.PER_CHECK_TIMEOUT_MS),
		secondaryDoh: env.BV_DOH_ENDPOINT ? { endpoint: env.BV_DOH_ENDPOINT, token: env.BV_DOH_TOKEN } : undefined,
	};

	let captured: CheckResult | null = null;
	try {
		// Phase 6: Fingerprint pre-flight
		if (!parsed.force_refresh) {
			try {
				const lastScan = await tenantDb
					.prepare('SELECT result_json, scan_at FROM scans WHERE domain = ? ORDER BY scan_at DESC LIMIT 1')
					.bind(parsed.domain)
					.first<{ result_json: string; scan_at: number }>();

				if (lastScan && lastScan.result_json) {
					const domainRow = await tenantDb
						.prepare('SELECT fingerprint FROM domains WHERE domain = ?')
						.bind(parsed.domain)
						.first<{ fingerprint: string | null }>();

					const now = Date.now();
					const oneDayMs = 24 * 3600 * 1000;
					const isRecent = now - lastScan.scan_at < oneDayMs;

					if (isRecent) {
						const { computeFingerprint, fingerprintsDiffer } = await import('./dns-fingerprint');
						const fp = await computeFingerprint(parsed.domain);
						if (fp.kind === 'ok' && !fingerprintsDiffer(fp.fingerprint, domainRow?.fingerprint ?? null)) {
							// Successfully skipped full scan.
							// Note: We don't re-persist the scan row for the new cycle_id here
							// to keep the cycle consistent with the skip logic.
							// But wait, the cycle alert sweep needs a scan row for THIS cycle_id
							// to find the findings. So we DO need to persist it.
							captured = JSON.parse(lastScan.result_json) as CheckResult;
						}
					}
				}
			} catch {
				// Fingerprint pre-flight is best-effort.
			}
		}

		if (!captured) {
			const result = await withTimeout(
				handleToolsCall(
					{ name: 'scan_domain', arguments: { domain: parsed.domain } },
					env.SCAN_CACHE,
					{
						...runtimeOptions,
						resultCapture: (r) => {
							captured = r;
						},
					},
				),
				QUEUE_MESSAGE_TIMEOUT_MS,
			);
			if (result.isError) {
				if (isLastAttempt) {
					await writeDlqRow(tenantDb, parsed, 'queue_dlq');
					await incrementCompletedTotalIfTracked(env, parsed.cycle_id);
					return 'ack';
				}
				return 'retry';
			}
		}
	} catch (err) {
		const reason = err instanceof Error ? err.message : 'queue_error';
		if (isLastAttempt) {
			await writeDlqRow(tenantDb, parsed, reason === 'queue_timeout' ? 'queue_timeout' : 'queue_dlq');
			await incrementCompletedTotalIfTracked(env, parsed.cycle_id);
			return 'ack';
		}
		return 'retry';
	}

	try {
		await persistScan(tenantDb, parsed, captured as CheckResult | null);
		ctx.waitUntil(streamScanResult(env, {
			domain: parsed.domain,
			grade: (captured as unknown as { grade?: string } | null)?.grade ?? null,
			score: captured?.score ?? null,
			sub_tenant_id: parsed.sub_tenant_id,
			cycle_id: parsed.cycle_id
		}));
	} catch {
		// Persistence failure is transient (D1 contention, throttling). Retry.
		if (isLastAttempt) {
			await writeDlqRow(tenantDb, parsed, 'persist_failed');
			// Even DLQ counts toward completed_total — otherwise a cycle with N
			// permanently-stuck domains never settles and the alert never fires.
			await incrementCompletedTotalIfTracked(env, parsed.cycle_id);
			return 'ack';
		}
		return 'retry';
	}

	// Phase 3 cycle-progress hook. Fail-soft: a registry hiccup must NOT cause
	// a redelivery, so this swallows its own errors.
	await incrementCompletedTotalIfTracked(env, parsed.cycle_id);
	return 'ack';
}

/**
 * Cloudflare Queue consumer entrypoint. Iterates a batch of scan messages,
 * defers each to `processScanMessage`, and acks/retries individually.
 *
 * Throwing from this function before all messages are explicitly acked tells
 * Cloudflare Queue to retry only the un-acked ones (per their docs). We use
 * `message.ack()` / `message.retry()` for individual control rather than
 * relying on default whole-batch behavior.
 */
export async function handleScanQueue(
	batch: MessageBatch<unknown>,
	env: ScanQueueConsumerEnv,
	ctx: ExecutionContext,
): Promise<void> {
	for (const message of batch.messages) {
		const attempts = message.attempts ?? 1;
		let outcome: 'ack' | 'retry';
		try {
			outcome = await processScanMessage(message.body, attempts, env, {
				waitUntil: (p) => ctx.waitUntil(p),
			});
		} catch {
			// Defensive: any unexpected throw is treated as transient retry.
			outcome = 'retry';
		}
		if (outcome === 'ack') {
			message.ack();
		} else {
			message.retry();
		}
	}
}
