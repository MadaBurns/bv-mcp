// SPDX-License-Identifier: BUSL-1.1

import { DNS_CHECKS_PACKAGE_VERSION } from '../lib/dns-checks-version';
import { SCORING_MODEL_VERSION, computeScoringConfigHash } from '../lib/scoring-version';
import { sanitizeDomain, validateDomain } from '../lib/sanitize';
import { batchScan, compactBatchScanResults, type CompactBatchScanResult } from './batch-scan';
import type { ScanRuntimeOptions } from './scan/post-processing';

export const ASYNC_BATCH_RESULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const JOB_PREFIX = 'async-batch:v1:';
const RUNNING_LEASE_MS = 2 * 60 * 1000;

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
	const existing = await deps.kv.get<AsyncBatchJob>(jobKey(jobId), 'json');
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

export async function processAsyncBatchMessage(
	body: unknown,
	deps: { kv: KVNamespace; runtimeOptions?: ScanRuntimeOptions; now?: () => number; runBatchScan?: typeof batchScan },
): Promise<'ack' | 'retry'> {
	if (!body || typeof body !== 'object') return 'ack';
	const message = body as Partial<AsyncBatchQueueMessage>;
	if (message.version !== 1 || typeof message.jobId !== 'string' || typeof message.principalId !== 'string') return 'ack';
	const job = await getAsyncBatchJob(message.jobId, message.principalId, deps.kv);
	if (!job || job.status === 'completed') return 'ack';
	const now = deps.now ?? Date.now;
	// Queue delivery is at-least-once. Defer a duplicate while its first delivery
	// still owns a fresh execution lease; a stale lease is intentionally reclaimable
	// after an isolate crash so jobs cannot remain stuck in `running` forever.
	if (job.status === 'running' && now() - job.updatedAt < RUNNING_LEASE_MS) return 'retry';
	job.status = 'running';
	job.updatedAt = now();
	delete job.error;
	await deps.kv.put(jobKey(job.jobId), JSON.stringify(job), { expirationTtl: ASYNC_BATCH_RESULT_TTL_SECONDS });
	try {
		const results = await (deps.runBatchScan ?? batchScan)(job.domains, {
			force_refresh: job.forceRefresh,
			kv: deps.kv,
			runtimeOptions: deps.runtimeOptions,
		});
		job.result = compactBatchScanResults(results);
		job.status = 'completed';
		job.updatedAt = now();
		await deps.kv.put(jobKey(job.jobId), JSON.stringify(job), { expirationTtl: ASYNC_BATCH_RESULT_TTL_SECONDS });
		return 'ack';
	} catch (error) {
		job.status = 'queued';
		job.updatedAt = now();
		job.error = error instanceof Error ? error.message.slice(0, 300) : 'batch_scan_failed';
		await deps.kv.put(jobKey(job.jobId), JSON.stringify(job), { expirationTtl: ASYNC_BATCH_RESULT_TTL_SECONDS });
		return 'retry';
	}
}
