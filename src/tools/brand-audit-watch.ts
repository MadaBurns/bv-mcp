// SPDX-License-Identifier: BUSL-1.1

/**
 * Brand-audit watch tools — register / list / delete recurring brand-audit watches.
 *
 * Originally a single `action`-discriminated `brand_audit_watch` tool; split
 * into three single-purpose MCP tools (`register_brand_audit_watch`,
 * `list_brand_audit_watches`, `delete_brand_audit_watch`) so that read and
 * destructive operations live in separate tools per the Anthropic Directory
 * review criteria. Owner-scoped: a caller's principalId is bound at every
 * operation, and any cross-owner attempt surfaces as `notFound` (never
 * `accessDenied`) to defend against ID enumeration.
 *
 * Watch storage: `brand_audit_watches` in BRAND_AUDIT_DB. The cron tick in
 * `src/scheduled.ts` enumerates active rows, enqueues
 * `brand_audit_batch_start` for each due watch, and POSTs a diff webhook on
 * classification drift.
 *
 * SSRF defense at register time: `validateOutboundUrl` rejects private-IP
 * targets, userinfo-bearing URLs, non-https schemes (Cloudflare browser
 * rendering quirk aside, we don't accept http for webhooks). Re-validated at
 * delivery time in `src/scheduled.ts:handleBrandAuditWatches` via safeFetch.
 *
 * Per-principal cap: 20 active watches. Prevents a single API key from
 * scheduling unbounded recurring cost.
 */

import { buildCheckResult, createFinding, type CheckResult } from '../lib/scoring';
import { validateOutboundUrl, validateDomain, sanitizeDomain } from '../lib/sanitize';
import type { BrandAuditWatchInterval, BrandAuditWatchRow } from '../lib/db/brand-audit-schema';

import { BRAND_DISCOVERY_CATEGORY as CATEGORY } from '../lib/brand-audit-category';

/** Hard cap on active watches per principal. */
const MAX_WATCHES_PER_OWNER = 20;

export interface RegisterBrandAuditWatchArgs {
	/** Domain to watch. */
	domain?: string;
	/** Recurrence interval. */
	interval?: BrandAuditWatchInterval;
	/** Optional webhook URL; null/undefined → logging-only watch. */
	webhook_url?: string;
}

export interface DeleteBrandAuditWatchArgs {
	/** Watch ID returned by register_brand_audit_watch. */
	watchId?: string;
}

export interface BrandAuditWatchDeps {
	db: D1Database;
	/** UUID generator override for deterministic tests. */
	generateId?: () => string;
	/** Clock override for tests (epoch ms). */
	now?: () => number;
}

function errorResult(flag: string, message: string, extra: Record<string, unknown> = {}): CheckResult {
	return buildCheckResult(CATEGORY, [createFinding(CATEGORY, `Brand audit watch: ${flag}`, 'high', message, { [flag]: true, ...extra })]);
}

/** Create a new recurring brand-audit watch. */
export async function registerBrandAuditWatch(
	args: RegisterBrandAuditWatchArgs,
	ownerId: string,
	deps: BrandAuditWatchDeps,
): Promise<CheckResult> {
	if (!args.domain || typeof args.domain !== 'string') {
		return errorResult('invalidInput', 'domain is required.');
	}
	if (!args.interval || !['daily', 'weekly', 'monthly'].includes(args.interval)) {
		return errorResult('invalidInput', 'interval must be one of daily|weekly|monthly.');
	}
	// SSRF/blocklist guard at register time. The watched domain is scanned on a
	// recurring cron cadence, so reject reserved/IP/blocklisted targets here
	// rather than storing a row that fails every cycle (#198).
	const domainValidation = validateDomain(args.domain);
	if (!domainValidation.valid) {
		return errorResult('invalidInput', `Invalid domain: ${domainValidation.error ?? 'not allowed'}`);
	}
	if (args.webhook_url) {
		const v = validateOutboundUrl(args.webhook_url);
		if (!v.valid) {
			return errorResult('invalidInput', `webhook_url failed SSRF validation: ${v.error ?? 'invalid URL'}`);
		}
	}

	const watchId = (deps.generateId ?? defaultGenerateId)();
	const now = (deps.now ?? Date.now)();
	const domain = sanitizeDomain(args.domain);

	try {
		// Keep the cap check and mutation in one SQLite statement. D1 serializes
		// statements for a database, so concurrent registrations cannot all pass a
		// stale preflight COUNT before inserting. A successful no-op is reported as
		// meta.changes=0 and means the principal was at the cap when this statement ran.
		const insertResult = await deps.db
			.prepare(
				`INSERT INTO brand_audit_watches (id, owner_id, domain, interval, webhook_url, active, created_at)
				 SELECT ?, ?, ?, ?, ?, ?, ?
				 WHERE (
				   SELECT COUNT(*)
				   FROM brand_audit_watches
				   WHERE owner_id = ? AND active = 1
				 ) < ?`,
			)
			.bind(watchId, ownerId, domain, args.interval, args.webhook_url ?? null, 1, now, ownerId, MAX_WATCHES_PER_OWNER)
			.run();

		if (insertResult.meta.changes === 0) {
			return errorResult(
				'watchLimitExceeded',
				`Per-principal cap of ${MAX_WATCHES_PER_OWNER} active watches reached. Delete an existing watch before registering another.`,
				{ current: MAX_WATCHES_PER_OWNER, limit: MAX_WATCHES_PER_OWNER },
			);
		}
	} catch (err) {
		return errorResult('persistenceFailure', `Failed to register watch: ${err instanceof Error ? err.message : String(err)}`);
	}

	return buildCheckResult(CATEGORY, [
		createFinding(
			CATEGORY,
			`Brand audit watch registered: ${domain} (${args.interval})`,
			'info',
			`watchId=${watchId} interval=${args.interval} webhook=${args.webhook_url ? 'set' : 'none'}`,
			{
				summary: true,
				watchId,
				domain,
				interval: args.interval,
				hasWebhook: Boolean(args.webhook_url),
				createdAt: now,
			},
		),
	]);
}

/**
 * One-way correlation for bv-web's high-entropy callback credential. This lets
 * entitlement cleanup identify a registration whose success response was lost
 * without returning the webhook URL or its bearer token from the list tool.
 */
async function webhookTokenFingerprint(webhookUrl: string | null): Promise<string | null> {
	if (!webhookUrl) return null;
	try {
		const token = new URL(webhookUrl).searchParams.get('t');
		// Only fingerprint high-entropy URL-safe tokens; do not make low-entropy
		// customer query values available to offline guessing through this field.
		if (!token || !/^[A-Za-z0-9_-]{20,128}$/.test(token)) return null;
		const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
		return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
	} catch {
		return null;
	}
}

/** List the caller's recurring brand-audit watches. */
export async function listBrandAuditWatches(ownerId: string, deps: BrandAuditWatchDeps): Promise<CheckResult> {
	const rows = await deps.db
		.prepare(
			'SELECT id, owner_id, domain, interval, webhook_url, last_run_at, last_classification_hash, active, created_at FROM brand_audit_watches WHERE owner_id = ? ORDER BY created_at DESC',
		)
		.bind(ownerId)
		.all<BrandAuditWatchRow>();
	const watches = await Promise.all(
		(rows.results ?? []).map(async (r) => ({
			watchId: r.id,
			domain: r.domain,
			interval: r.interval,
			hasWebhook: r.webhook_url !== null,
			webhookTokenFingerprint: await webhookTokenFingerprint(r.webhook_url),
			lastRunAt: r.last_run_at,
			lastClassificationHash: r.last_classification_hash,
			active: Boolean(r.active),
			createdAt: r.created_at,
		})),
	);

	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Brand audit watches: ${watches.length}`, 'info', `${watches.length} watch(es) for principal.`, {
			summary: true,
			count: watches.length,
			watches,
		}),
	]);
}

/** Delete a recurring brand-audit watch the caller owns. */
export async function deleteBrandAuditWatch(
	args: DeleteBrandAuditWatchArgs,
	ownerId: string,
	deps: BrandAuditWatchDeps,
): Promise<CheckResult> {
	if (!args.watchId || typeof args.watchId !== 'string') {
		return errorResult('invalidInput', 'watchId is required.');
	}

	const existing = (await deps.db.prepare('SELECT owner_id FROM brand_audit_watches WHERE id = ? LIMIT 1').bind(args.watchId).first()) as {
		owner_id: string;
	} | null;

	if (!existing || existing.owner_id !== ownerId) {
		// notFound — never confirm existence of a row the caller doesn't own.
		return errorResult('notFound', `No watch with id ${args.watchId}.`, { watchId: args.watchId });
	}

	await deps.db.prepare('DELETE FROM brand_audit_watches WHERE id = ? AND owner_id = ?').bind(args.watchId, ownerId).run();

	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Brand audit watch deleted: ${args.watchId}`, 'info', '', {
			summary: true,
			deleted: true,
			watchId: args.watchId,
		}),
	]);
}

function defaultGenerateId(): string {
	return crypto.randomUUID();
}
