// SPDX-License-Identifier: BUSL-1.1

import { DNS_CHECKS_PACKAGE_VERSION } from '../lib/dns-checks-version';
import { SCORING_MODEL_VERSION, computeScoringConfigHash } from '../lib/scoring-version';
import { sanitizeDomain, validateDomain } from '../lib/sanitize';
import { batchScan, compactBatchScanResults, type CompactBatchScanResult } from './batch-scan';
import type { ScanRuntimeOptions } from './scan/post-processing';

export const ASYNC_BATCH_RESULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const JOB_PREFIX = 'async-batch:v1:';
const RUNNING_LEASE_MS = 2 * 60 * 1000;
/**
 * Wall-clock budget for the queue job's batch scan. The 25s default of `batchScan` is sized for the
 * synchronous tool path under the Worker request cap; a queue consumer has no such cap, and ten cold
 * domains at 3-wide concurrency need ~60s. Kept below RUNNING_LEASE_MS so a live job never looks
 * stale to a duplicate delivery.
 */
const ASYNC_BATCH_BUDGET_MS = 90_000;

export type AsyncBatchStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface AsyncBatchJob {
	jobId: string;
	principalId: string;
	status: AsyncBatchStatus;
	domains: string[];
	forceRefresh: boolean;
	createdAt: number;
	updatedAt: number;
	expiresAt: number;
	scoringModelVersion: string;
	dnsChecksPackageVersion: string;
	scoringConfigHash: string;
	result?: CompactBatchScanResult;
	/** Set with `status: 'completed'`: TRUE when the batch budget cut off a tail of domains that were never scanned. */
	incomplete?: boolean;
	/** Domains that were never scanned (input order); empty when the batch finished. */
	unscanned?: string[];
	error?: string;
}

export interface AsyncBatchQueueMessage {
	version: 1;
	jobId: string;
	principalId: string;
}

export interface AsyncBatchQueueProducer {
	send(message: AsyncBatchQueueMessage, options?: { contentType?: 'json' }): Promise<void>;
}

function jobKey(jobId: string): string {
	return `${JOB_PREFIX}${jobId}`;
}

async function sha256(value: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function normalizeDomains(domains: readonly string[]): string[] {
	const normalized = new Set<string>();
	for (const raw of domains) {
		const validation = validateDomain(raw);
		if (!validation.valid) throw new Error(`Invalid domain: ${raw}`);
		normalized.add(sanitizeDomain(raw));
	}
	return [...normalized].sort();
}

export async function startAsyncBatchScan(
	input: { domains: readonly string[]; forceRefresh?: boolean; idempotencyKey: string },
	principalId: string,
	deps: { kv: KVNamespace; queue: AsyncBatchQueueProducer; scoringConfig?: ScanRuntimeOptions['scoringConfig']; now?: () => number },
): Promise<Pick<AsyncBatchJob, 'jobId' | 'status' | 'createdAt' | 'expiresAt'>> {
	if (!principalId || principalId === 'anonymous') throw new Error('Authentication required');
	if (!input.idempotencyKey || input.idempotencyKey.length > 128) throw new Error('A valid idempotency_key is required');
	const domains = normalizeDomains(input.domains);
	if (domains.length === 0 || domains.length > 10) throw new Error('domains must contain 1 to 10 unique domains');
	const scoringConfigHash = computeScoringConfigHash(deps.scoringConfig);
	const fingerprint = JSON.stringify({
		principalId,
		domains,
		forceRefresh: input.forceRefresh === true,
		idempotencyKey: input.idempotencyKey,
		scoringModelVersion: SCORING_MODEL_VERSION,
		dnsChecksPackageVersion: DNS_CHECKS_PACKAGE_VERSION,
		scoringConfigHash,
	});
	const jobId = `bs_${(await sha256(fingerprint)).slice(0, 40)}`;
	// Same read-path deadline as batch_scan_status: a job abandoned past the stale bound reads as
	// `failed` here too, so a reused key starts a new job instead of replaying a dead one (SQ-577).
	const existing = await getAsyncBatchJobForRead(jobId, principalId, deps.kv, deps.now);
	if (existing && existing.status !== 'failed') return existing;

	const now = (deps.now ?? Date.now)();
	const job: AsyncBatchJob = {
		jobId,
		principalId,
		status: 'queued',
		domains,
		forceRefresh: input.forceRefresh === true,
		createdAt: now,
		updatedAt: now,
		expiresAt: now + ASYNC_BATCH_RESULT_TTL_SECONDS * 1000,
		scoringModelVersion: SCORING_MODEL_VERSION,
		dnsChecksPackageVersion: DNS_CHECKS_PACKAGE_VERSION,
		scoringConfigHash,
	};
	await deps.kv.put(jobKey(jobId), JSON.stringify(job), { expirationTtl: ASYNC_BATCH_RESULT_TTL_SECONDS });
	try {
		await deps.queue.send({ version: 1, jobId, principalId }, { contentType: 'json' });
	} catch (error) {
		job.status = 'failed';
		job.updatedAt = (deps.now ?? Date.now)();
		job.error = 'queue_unavailable';
		await deps.kv.put(jobKey(jobId), JSON.stringify(job), { expirationTtl: ASYNC_BATCH_RESULT_TTL_SECONDS });
		throw error;
	}
	return job;
}

export async function getAsyncBatchJob(jobId: string, principalId: string, kv: KVNamespace): Promise<AsyncBatchJob | null> {
	if (!/^bs_[a-f0-9]{40}$/.test(jobId)) return null;
	const job = await kv.get<AsyncBatchJob>(jobKey(jobId), 'json');
	return job?.principalId === principalId ? job : null;
}

/** What the queue consumer should do with a message: ack it, or redeliver it after `delaySeconds`. */
export type AsyncBatchVerdict = { action: 'ack' } | { action: 'retry'; delaySeconds: number };

const ACK: AsyncBatchVerdict = { action: 'ack' };

/**
 * Total deliveries a message gets: the first delivery plus `max_retries` (3) from
 * docs/provisioning/wrangler.async-batch-queues.json. Queues counts `message.attempts` from 1.
 */
export const ASYNC_BATCH_MAX_ATTEMPTS = 4;
/** Redelivery delay after a thrown scan, so the retries are not all spent within seconds. */
const SCAN_FAILURE_RETRY_DELAY_SECONDS = 30;
/** KV is eventually consistent: wait this long (per attempt) before re-reading a job that was just written. */
const JOB_MISSING_RETRY_DELAY_SECONDS = 15;

/**
 * A non-terminal job whose last write is older than this has lost its consumer on every delivery
 * (isolate eviction, CPU/memory limit or subrequest ceiling kills the invocation before it can write
 * `failed`, and the DLQ has no consumer). Derived from the retry numbers above: each of the
 * ASYNC_BATCH_MAX_ATTEMPTS deliveries can sit for a full running lease before a redelivery may reclaim
 * it, plus the retry delay between deliveries, plus one more lease as margin so a live job on its last
 * attempt is never failed by a polling read. 4 x (120s + 30s) + 120s = 12 minutes.
 */
export const ASYNC_BATCH_STALE_AFTER_MS =
	ASYNC_BATCH_MAX_ATTEMPTS * (RUNNING_LEASE_MS + SCAN_FAILURE_RETRY_DELAY_SECONDS * 1000) + RUNNING_LEASE_MS;
/** Machine-readable `error` for a job failed by the read-path deadline (same field the consumer writes). */
export const ASYNC_BATCH_ABANDONED_ERROR = 'consumer_abandoned';

/**
 * Status-read variant of {@link getAsyncBatchJob} (read-path deadline, mirroring brand_audit_status).
 * A queued/running job past {@link ASYNC_BATCH_STALE_AFTER_MS} is returned as terminally `failed` and the
 * terminal state is persisted best-effort so later reads agree; a persist failure never changes what is
 * returned. `updatedAt` stays the job's last real activity so repeated polls render identically.
 * The queue consumer keeps using the raw {@link getAsyncBatchJob} so its retry behaviour is unchanged.
 */
export async function getAsyncBatchJobForRead(
	jobId: string,
	principalId: string,
	kv: KVNamespace,
	now: () => number = Date.now,
): Promise<AsyncBatchJob | null> {
	const job = await getAsyncBatchJob(jobId, principalId, kv);
	if (!job || !isStaleAsyncBatchJob(job, now())) return job;
	const failed: AsyncBatchJob = { ...job, status: 'failed', error: ASYNC_BATCH_ABANDONED_ERROR };
	await persistAbandonedJob(failed, kv);
	return failed;
}

/** The one stale deadline: a queued/running job whose last write is older than {@link ASYNC_BATCH_STALE_AFTER_MS}. */
function isStaleAsyncBatchJob(job: AsyncBatchJob, nowMs: number): boolean {
	const inFlight = job.status === 'queued' || job.status === 'running';
	return inFlight && nowMs - job.updatedAt > ASYNC_BATCH_STALE_AFTER_MS;
}

async function persistAbandonedJob(failed: AsyncBatchJob, kv: KVNamespace): Promise<void> {
	try {
		await kv.put(jobKey(failed.jobId), JSON.stringify(failed), { expirationTtl: ASYNC_BATCH_RESULT_TTL_SECONDS });
	} catch {
		// Best effort: the next read recomputes the same verdict.
	}
}

function retryAfter(delaySeconds: number): AsyncBatchVerdict {
	return { action: 'retry', delaySeconds };
}

/** Seconds until a fresh running lease turns stale, at least 1 and at most the whole lease. */
function remainingLeaseSeconds(job: AsyncBatchJob, nowMs: number): number {
	const remainingMs = RUNNING_LEASE_MS - (nowMs - job.updatedAt);
	return Math.min(RUNNING_LEASE_MS / 1000, Math.max(1, Math.ceil(remainingMs / 1000)));
}

/**
 * A null read is usually KV lag on a job that was just written, so retry with a short delay and only
 * ack once the attempts are exhausted (acking early would strand the job `queued`).
 */
function missingJobVerdict(attempts: number): AsyncBatchVerdict {
	return attempts >= ASYNC_BATCH_MAX_ATTEMPTS ? ACK : retryAfter(JOB_MISSING_RETRY_DELAY_SECONDS);
}

/**
 * Verdict for deliveries that must not (re)run the scan, or `null` when the scan should run.
 * Queue delivery is at-least-once: terminal jobs are acked untouched, a duplicate is deferred until
 * the first delivery's lease would go stale, and a stale lease is intentionally reclaimable after an
 * isolate crash so jobs cannot remain stuck in `running` forever.
 */
function verdictWithoutRunning(job: AsyncBatchJob, nowMs: number): AsyncBatchVerdict | null {
	if (job.status === 'completed' || job.status === 'failed') return ACK;
	if (job.status === 'running' && nowMs - job.updatedAt < RUNNING_LEASE_MS) return retryAfter(remainingLeaseSeconds(job, nowMs));
	return null;
}

export async function processAsyncBatchMessage(
	body: unknown,
	deps: { kv: KVNamespace; runtimeOptions?: ScanRuntimeOptions; now?: () => number; runBatchScan?: typeof batchScan; attempts?: number },
): Promise<AsyncBatchVerdict> {
	if (!body || typeof body !== 'object') return ACK;
	const message = body as Partial<AsyncBatchQueueMessage>;
	if (message.version !== 1 || typeof message.jobId !== 'string' || typeof message.principalId !== 'string') return ACK;
	const attempts = deps.attempts ?? 1;
	const job = await getAsyncBatchJob(message.jobId, message.principalId, deps.kv);
	const now = deps.now ?? Date.now;
	if (!job) return missingJobVerdict(attempts);
	const early = verdictWithoutRunning(job, now());
	if (early) return early;
	job.status = 'running';
	job.updatedAt = now();
	delete job.error;
	await deps.kv.put(jobKey(job.jobId), JSON.stringify(job), { expirationTtl: ASYNC_BATCH_RESULT_TTL_SECONDS });
	try {
		const results = await (deps.runBatchScan ?? batchScan)(job.domains, {
			force_refresh: job.forceRefresh,
			kv: deps.kv,
			runtimeOptions: deps.runtimeOptions,
			budgetMs: ASYNC_BATCH_BUDGET_MS,
		});
		job.result = compactBatchScanResults(results);
		// Recorded on the job itself so `batch_scan_status` can say "completed, but these
		// domains were never scanned" without a caller having to fetch the findings (SQ-291).
		job.incomplete = job.result.incomplete;
		job.unscanned = job.result.unscanned;
		job.status = 'completed';
		job.updatedAt = now();
		await deps.kv.put(jobKey(job.jobId), JSON.stringify(job), { expirationTtl: ASYNC_BATCH_RESULT_TTL_SECONDS });
		return ACK;
	} catch (error) {
		return recordScanFailure(job, error, attempts, deps.kv, now());
	}
}

/**
 * The last delivery has nothing left to retry into: record a terminal `failed` state (with the error)
 * instead of leaving a `queued` job that nobody will ever pick up again. Earlier attempts stay
 * `queued` and are redelivered after a delay so the retries are not all spent within seconds.
 */
async function recordScanFailure(
	job: AsyncBatchJob,
	error: unknown,
	attempts: number,
	kv: KVNamespace,
	nowMs: number,
): Promise<AsyncBatchVerdict> {
	const exhausted = attempts >= ASYNC_BATCH_MAX_ATTEMPTS;
	job.status = exhausted ? 'failed' : 'queued';
	job.updatedAt = nowMs;
	job.error = error instanceof Error ? error.message.slice(0, 300) : 'batch_scan_failed';
	await kv.put(jobKey(job.jobId), JSON.stringify(job), { expirationTtl: ASYNC_BATCH_RESULT_TTL_SECONDS });
	return exhausted ? ACK : retryAfter(SCAN_FAILURE_RETRY_DELAY_SECONDS);
}
