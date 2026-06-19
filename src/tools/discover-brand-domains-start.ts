// SPDX-License-Identifier: BUSL-1.1

/**
 * discover_brand_domains_start — async producer for brand-domain discovery.
 *
 * The synchronous `discover_brand_domains` tool runs ~24s for tier-1 brands and
 * times out interactive clients (Claude Desktop's ~25s tool-call ceiling). This
 * tool starts the same discovery on the proven brand-audit Cloudflare Queue +
 * D1 store and returns immediately with an `auditId` the caller polls via
 * `discover_brand_domains_status` and fetches via `discover_brand_domains_findings`.
 *
 * It REUSES the brand-audit infrastructure (the `brand_audits` parent +
 * `brand_audit_targets` child rows, the `brand-audit-queue`), creating ONE
 * target and enqueuing ONE message carrying the discovery args plus a
 * `phase: 'discover_only'` discriminator. The consumer's `discover_only` branch
 * runs `discoverBrandDomains` directly and writes the resulting `CheckResult`
 * to `brand_audit_targets.result_json`.
 *
 * Returns a `CheckResult` whose summary metadata carries `{ auditId, queuedAt,
 * etaSeconds }` (single target). Mirrors `brandAuditBatchStart` (total_targets: 1).
 *
 * Failure modes mirror `brandAuditBatchStart`:
 *   - Invalid domain → `invalidInput` finding, no D1 write, no enqueue
 *   - D1 insert fails → `persistenceFailure` finding, no enqueue
 *   - queue.send fails → `enqueueFailure` finding; the audit row is flipped to
 *     `'failed'` so the polling tool stops claiming progress
 */

import { buildCheckResult, createFinding, type CheckResult } from '../lib/scoring';
import { sanitizeDomain, validateDomain } from '../lib/sanitize';

const CATEGORY = 'brand_discovery';

/**
 * ETA for a single discovery run. The sync path averages ~24s wall clock for
 * tier-1 brands; the queue consumer has more headroom (300s budget) but most
 * brands settle in well under a minute. Used so the caller polls at a sensible
 * interval rather than tight-looping.
 */
const ETA_SECONDS = 60;

/** Discovery args forwarded onto the queue message. Mirrors DiscoverBrandDomainsOptions inputs. */
export interface DiscoverBrandDomainsStartOptions {
	signals?: string[];
	depth?: 'standard' | 'deep';
	planner_mode?: 'off' | 'observe' | 'enforce';
	brand_aliases?: string[];
	candidate_domains?: string[];
	dkim_selectors?: string[];
	min_confidence?: number;
	discovery_mode?: 'classic' | 'tiered';
	ownership_verified?: boolean;
}

/** Wire shape of the `discover_only` queue message. */
export interface DiscoverOnlyQueueMessage extends DiscoverBrandDomainsStartOptions {
	auditId: string;
	target: string;
	phase: 'discover_only';
}

export interface DiscoverBrandDomainsStartQueueProducer {
	send(message: DiscoverOnlyQueueMessage, options?: { contentType?: 'json' }): Promise<void>;
}

/** Injectable deps. Production wiring threads env bindings; tests pass mocks. */
export interface DiscoverBrandDomainsStartDeps {
	db: D1Database;
	queue: DiscoverBrandDomainsStartQueueProducer;
	/** UUID generator override for deterministic tests. */
	generateId?: () => string;
	/** Clock override for deterministic tests. */
	now?: () => number;
}

function buildErrorResult(
	flag: 'invalidInput' | 'persistenceFailure' | 'enqueueFailure',
	message: string,
	extra: Record<string, unknown> = {},
): CheckResult {
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Discover brand domains start: ${flag}`, 'high', message, {
			[flag]: true,
			...extra,
		}),
	]);
}

export async function discoverBrandDomainsStart(
	domain: string,
	options: DiscoverBrandDomainsStartOptions,
	ownerId: string,
	deps: DiscoverBrandDomainsStartDeps,
): Promise<CheckResult> {
	const validation = validateDomain(domain);
	if (!validation.valid) {
		return buildErrorResult('invalidInput', `Invalid seed domain: ${validation.error ?? 'invalid domain'}`, { domain });
	}
	const target = sanitizeDomain(domain);
	if (!target) {
		return buildErrorResult('invalidInput', 'No usable seed domain after normalisation.', { domain });
	}

	const auditId = (deps.generateId ?? defaultGenerateId)();
	const now = (deps.now ?? Date.now)();

	try {
		await deps.db
			.prepare(
				'INSERT INTO brand_audits (id, owner_id, status, total_targets, completed_targets, format, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
			)
			.bind(auditId, ownerId, 'queued', 1, 0, 'json', now, now)
			.run();

		await deps.db
			.prepare('INSERT INTO brand_audit_targets (audit_id, target, status, created_at) VALUES (?, ?, ?, ?)')
			.bind(auditId, target, 'queued', now)
			.run();
	} catch (err) {
		return buildErrorResult(
			'persistenceFailure',
			`Failed to persist discovery row: ${err instanceof Error ? err.message : String(err)}`,
			{ auditId },
		);
	}

	try {
		await deps.queue.send(
			{
				auditId,
				target,
				phase: 'discover_only',
				signals: options.signals,
				depth: options.depth,
				planner_mode: options.planner_mode,
				brand_aliases: options.brand_aliases,
				candidate_domains: options.candidate_domains,
				dkim_selectors: options.dkim_selectors,
				min_confidence: options.min_confidence,
				discovery_mode: options.discovery_mode,
				ownership_verified: options.ownership_verified,
			},
			{ contentType: 'json' },
		);
	} catch (err) {
		// Mark the audit failed so the polling tool stops claiming progress
		// against a target no consumer will pick up. Best-effort.
		try {
			await deps.db.prepare("UPDATE brand_audits SET status = 'failed', updated_at = ? WHERE id = ?").bind(now, auditId).run();
		} catch {
			// Best-effort — the enqueueFailure finding still surfaces the truth.
		}
		return buildErrorResult(
			'enqueueFailure',
			`Failed to enqueue discovery job: ${err instanceof Error ? err.message : String(err)}`,
			{ auditId, target },
		);
	}

	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Brand-domain discovery queued: ${target}`, 'info', `auditId=${auditId} queuedAt=${new Date(now).toISOString()} etaSeconds=${ETA_SECONDS}`, {
			summary: true,
			auditId,
			queuedAt: now,
			targetCount: 1,
			etaSeconds: ETA_SECONDS,
			target,
		}),
	]);
}

function defaultGenerateId(): string {
	return crypto.randomUUID();
}

interface DiscoverAuditRow {
	id: string;
	owner_id: string;
	status: 'queued' | 'running' | 'completed' | 'failed';
}

interface DiscoverTargetRow {
	target: string;
	status: 'queued' | 'running' | 'completed' | 'failed';
	result_json: string | null;
	error: string | null;
	completed_at: number | null;
}

function findingsError(flag: string, message: string, extra: Record<string, unknown> = {}): CheckResult {
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Discover brand domains findings: ${flag}`, 'high', message, { [flag]: true, ...extra }),
	]);
}

function safeParse(json: string | null): unknown {
	if (!json) return null;
	try {
		return JSON.parse(json);
	} catch {
		return null;
	}
}

/**
 * discover_brand_domains_findings reader — owner-scoped lookup of the single
 * discovery target's CheckResult. Returns `notReady` while in-flight, `notFound`
 * for an unknown or other-owner operationId (ID-enumeration defense), and the
 * parsed discovery result once complete.
 */
export async function discoverBrandDomainsFindings(
	operationId: string,
	ownerId: string,
	deps: { db: D1Database },
): Promise<CheckResult> {
	if (typeof operationId !== 'string' || operationId.trim().length === 0) {
		return findingsError('invalidInput', 'operationId is required.');
	}

	const audit = (await deps.db
		.prepare('SELECT id, owner_id, status FROM brand_audits WHERE id = ? LIMIT 1')
		.bind(operationId)
		.first()) as DiscoverAuditRow | null;

	if (!audit || audit.owner_id !== ownerId) {
		return findingsError('notFound', `No discovery operation found with id ${operationId}.`, { operationId });
	}

	const targetRow = (await deps.db
		.prepare('SELECT target, status, result_json, error, completed_at FROM brand_audit_targets WHERE audit_id = ? ORDER BY created_at ASC LIMIT 1')
		.bind(operationId)
		.first()) as DiscoverTargetRow | null;

	if (!targetRow) {
		return findingsError('notFound', `No discovery target found for operation ${operationId}.`, { operationId });
	}

	if (targetRow.status !== 'completed' && targetRow.status !== 'failed') {
		return findingsError(
			'notReady',
			`Discovery operation ${operationId} is currently ${targetRow.status}. Poll again with discover_brand_domains_status.`,
			{ operationId, currentStatus: targetRow.status },
		);
	}

	const parsed = safeParse(targetRow.result_json);
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Brand-domain discovery ${operationId}: ${targetRow.status}`, 'info', `status=${targetRow.status} target=${targetRow.target}`, {
			summary: true,
			auditId: operationId,
			operationId,
			target: targetRow.target,
			status: targetRow.status,
			result: parsed,
			error: targetRow.error,
		}),
	]);
}
