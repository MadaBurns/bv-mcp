// SPDX-License-Identifier: BUSL-1.1

import { computeClassificationHash } from './brand-audit-classification-diff';
import type { CheckResult } from './scoring';

/** Legacy authenticated owner IDs were the first 16 hex characters of a credential hash. */
const LEGACY_OWNER_ID = /^[0-9a-f]{16}$/;

/** Legacy trusted web delegation used the literal validated tenant identifier. */
const LEGACY_TENANT_OWNER_ID = /^tenant:[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

/** Canonical authenticated principals are full SHA-256 hex digests. */
const CANONICAL_OWNER_ID = /^[0-9a-f]{64}$/;

/** Stored watch IDs are UUIDs today; this also permits existing safe opaque IDs. */
const WATCH_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

/** Only high-entropy URL-safe callback tokens are eligible for ownership adoption. */
const WEBHOOK_TOKEN = /^[A-Za-z0-9_-]{20,128}$/;

const MAX_ANONYMOUS_WATCH_CANDIDATES = 200;
const MAX_ANONYMOUS_BASELINE_CANDIDATES = 500;

export interface BrandAuditOwnerReconciliation {
	/** True when the transactional D1 batch was executed. False means no migration was needed. */
	attempted: boolean;
}

const MAX_LEGACY_OWNER_IDS_PER_RECONCILIATION = 2;

/**
 * Atomically move brand-audit rows from one legacy credential owner to a
 * canonical authenticated principal.
 *
 * Callers MUST await this function before running an owner-scoped operation.
 * Database failures deliberately propagate so a caller cannot continue with a
 * partially reconciled identity. D1 `batch()` executes both statements as one
 * transaction, rolling both back if either statement fails.
 *
 * A legacy owner must be either a 16-hex public credential prefix or the exact
 * `tenant:<validated-id>` value previously minted by the trusted internal web
 * door. A canonical owner passed as `legacyOwnerId` is accepted only when it
 * is exactly equal to `canonicalOwnerId`; that makes repeated reconciliation
 * at an integration boundary a cheap no-op without allowing arbitrary 64-hex
 * ownership transfers.
 */
export async function reconcileLegacyBrandAuditOwner(
	db: D1Database,
	legacyOwnerId: string | null | undefined,
	canonicalOwnerId: string,
): Promise<BrandAuditOwnerReconciliation> {
	return reconcileLegacyBrandAuditOwners(
		db,
		legacyOwnerId === null || legacyOwnerId === undefined ? [] : [legacyOwnerId],
		canonicalOwnerId,
	);
}

/**
 * Atomically reconcile the current raw-token owner alias plus at most one
 * cryptographically proven historical alias. Multiple historical tokens are
 * recovered by repeating the request with one proof at a time; the small fixed
 * bound prevents an authenticated caller from amplifying D1 batch work.
 */
export async function reconcileLegacyBrandAuditOwners(
	db: D1Database,
	legacyOwnerIds: readonly string[],
	canonicalOwnerId: string,
): Promise<BrandAuditOwnerReconciliation> {
	if (!CANONICAL_OWNER_ID.test(canonicalOwnerId)) {
		throw new TypeError('Invalid canonical brand-audit owner ID');
	}

	if (legacyOwnerIds.length > MAX_LEGACY_OWNER_IDS_PER_RECONCILIATION) {
		throw new TypeError('Too many legacy brand-audit owner IDs');
	}
	const uniqueLegacyOwnerIds = [...new Set(legacyOwnerIds)].filter((ownerId) => ownerId !== canonicalOwnerId);
	if (uniqueLegacyOwnerIds.length === 0) return { attempted: false };

	for (const legacyOwnerId of uniqueLegacyOwnerIds) {
		if (!LEGACY_OWNER_ID.test(legacyOwnerId) && !LEGACY_TENANT_OWNER_ID.test(legacyOwnerId)) {
			throw new TypeError('Invalid legacy brand-audit owner ID');
		}
	}

	const results = await db.batch(
		uniqueLegacyOwnerIds.flatMap((legacyOwnerId) => [
			db.prepare('UPDATE brand_audits SET owner_id = ? WHERE owner_id = ?').bind(canonicalOwnerId, legacyOwnerId),
			db.prepare('UPDATE brand_audit_watches SET owner_id = ? WHERE owner_id = ?').bind(canonicalOwnerId, legacyOwnerId),
		]),
	);

	// D1 normally rejects the entire batch on statement failure. Retain an
	// explicit result check so a malformed adapter cannot turn a partial failure
	// into an authorised owner-scoped continuation.
	if (results.length !== uniqueLegacyOwnerIds.length * 2 || results.some((result) => result.success !== true)) {
		throw new Error('Brand-audit owner reconciliation failed');
	}

	return { attempted: true };
}

export type AnonymousWatchAdoptionResult = { status: 'reconciled'; watchId: string } | { status: 'no_match' } | { status: 'ambiguous' };

interface AnonymousWatchCandidate {
	id: string;
	webhook_url: string | null;
	domain: string;
	last_classification_hash: string | null;
	last_classification_result_json: string | null;
	pending_webhook_json: string | null;
}

function parseClassificationResult(raw: string | null): CheckResult | null {
	if (!raw) return null;
	try {
		const parsed = JSON.parse(raw) as { findings?: unknown };
		return parsed && typeof parsed === 'object' && Array.isArray(parsed.findings) ? (parsed as CheckResult) : null;
	} catch {
		return null;
	}
}

async function recoverAnonymousWatchBaseline(db: D1Database, watch: AnonymousWatchCandidate): Promise<string | null> {
	if (watch.last_classification_hash === null || watch.pending_webhook_json !== null) {
		return watch.last_classification_result_json;
	}

	const stored = parseClassificationResult(watch.last_classification_result_json);
	if (stored && (await computeClassificationHash(stored)) === watch.last_classification_hash) {
		return watch.last_classification_result_json;
	}

	// The callback token proves the exact watch before this lookup. Recover only
	// a completed target for that watch's domain whose digest exactly matches the
	// persisted hash. Parent audit status is deliberately irrelevant: legacy code
	// could persist the watch hash before a later audit-counter/finalization error.
	const history = await db
		.prepare(
			"SELECT t.result_json FROM brand_audit_targets t JOIN brand_audits a ON a.id = t.audit_id WHERE t.target = ? AND a.owner_id = 'anonymous' AND t.status = 'completed' AND t.result_json IS NOT NULL ORDER BY a.created_at DESC LIMIT ?",
		)
		.bind(watch.domain, MAX_ANONYMOUS_BASELINE_CANDIDATES)
		.all<{ result_json: string | null }>();
	if (history.success !== true) throw new Error('Anonymous brand-audit baseline lookup failed');
	for (const row of history.results ?? []) {
		const candidate = parseClassificationResult(row.result_json);
		if (candidate && (await computeClassificationHash(candidate)) === watch.last_classification_hash) {
			return row.result_json;
		}
	}
	throw new Error('Anonymous brand-audit watch baseline recovery failed');
}

async function sha256Hex(value: string): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
	return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function fingerprintWebhookToken(webhookUrl: string | null): Promise<string | null> {
	if (!webhookUrl) return null;
	try {
		const token = new URL(webhookUrl).searchParams.get('t');
		if (!token || !WEBHOOK_TOKEN.test(token)) return null;
		return sha256Hex(token);
	} catch {
		return null;
	}
}

function fingerprintsEqual(left: string, right: string): boolean {
	let different = left.length ^ right.length;
	const width = Math.max(left.length, right.length);
	for (let index = 0; index < width; index += 1) {
		different |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
	}
	return different === 0;
}

/**
 * INTERNAL ONLY: safely adopt a pre-identity recurring watch that is still
 * owned by the historical `anonymous` principal.
 *
 * The trusted web service supplies a one-way fingerprint of its high-entropy
 * callback token. This helper never returns webhook URLs, callback tokens, or
 * domains. Broad adoption is impossible: exactly one eligible row must match,
 * and the final conditional update loses safely if ownership or activity
 * changes after the read.
 */
export async function adoptAnonymousBrandAuditWatchInternal(
	db: D1Database,
	input: { canonicalOwnerId: string; webhookTokenFingerprint: string; watchId?: string },
): Promise<AnonymousWatchAdoptionResult> {
	if (!CANONICAL_OWNER_ID.test(input.canonicalOwnerId)) {
		throw new TypeError('Invalid canonical brand-audit owner ID');
	}
	if (!CANONICAL_OWNER_ID.test(input.webhookTokenFingerprint)) {
		throw new TypeError('Invalid webhook token fingerprint');
	}
	if (input.watchId !== undefined && !WATCH_ID.test(input.watchId)) {
		throw new TypeError('Invalid brand-audit watch ID');
	}

	const statement = input.watchId
		? db
				.prepare(
					"SELECT id, webhook_url, domain, last_classification_hash, last_classification_result_json, pending_webhook_json FROM brand_audit_watches WHERE owner_id = 'anonymous' AND active = 1 AND id = ? LIMIT ?",
				)
				.bind(input.watchId, MAX_ANONYMOUS_WATCH_CANDIDATES + 1)
		: db
				.prepare(
					"SELECT id, webhook_url, domain, last_classification_hash, last_classification_result_json, pending_webhook_json FROM brand_audit_watches WHERE owner_id = 'anonymous' AND active = 1 ORDER BY id LIMIT ?",
				)
				.bind(MAX_ANONYMOUS_WATCH_CANDIDATES + 1);
	const candidates = await statement.all<AnonymousWatchCandidate>();
	if (candidates.success !== true) throw new Error('Anonymous brand-audit watch lookup failed');

	const rows = candidates.results ?? [];
	if (rows.length > MAX_ANONYMOUS_WATCH_CANDIDATES) {
		throw new Error('Anonymous brand-audit watch candidate limit exceeded');
	}

	const matches: AnonymousWatchCandidate[] = [];
	for (const row of rows) {
		if (!WATCH_ID.test(row.id)) continue;
		const fingerprint = await fingerprintWebhookToken(row.webhook_url);
		if (fingerprint && fingerprintsEqual(fingerprint, input.webhookTokenFingerprint)) matches.push(row);
	}

	if (matches.length === 0) return { status: 'no_match' };
	if (matches.length !== 1) return { status: 'ambiguous' };

	const matched = matches[0];
	const recoveredBaseline = await recoverAnonymousWatchBaseline(db, matched);
	const update = await db
		.prepare(
			"UPDATE brand_audit_watches SET owner_id = ?, last_classification_result_json = ? WHERE id = ? AND owner_id = 'anonymous' AND active = 1 AND webhook_url = ? AND domain = ? AND last_classification_hash IS ? AND last_classification_result_json IS ? AND pending_webhook_json IS ?",
		)
		.bind(
			input.canonicalOwnerId,
			recoveredBaseline,
			matched.id,
			matched.webhook_url,
			matched.domain,
			matched.last_classification_hash,
			matched.last_classification_result_json,
			matched.pending_webhook_json,
		)
		.run();
	if (update.success !== true) throw new Error('Anonymous brand-audit watch adoption failed');
	if (update.meta.changes === 0) return { status: 'no_match' };
	if (update.meta.changes !== 1) throw new Error('Anonymous brand-audit watch adoption changed an unexpected number of rows');

	return { status: 'reconciled', watchId: matched.id };
}
