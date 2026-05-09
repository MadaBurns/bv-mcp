// SPDX-License-Identifier: BUSL-1.1

/**
 * Fail-soft writer for the cross-tenant audit log
 * (`audit_events` table in the shared registry D1, defined in
 * `src/tenants/db/schema/registry.ts`).
 *
 * Architectural notes (tenant-Scalable-Architecture-Design.md §6, §7):
 *  - Audit failure must NEVER fail the originating request — the auth/authz
 *    decision has already happened by the time we write. We catch + log, never
 *    throw. This module is the canonical place that fail-soft happens.
 *  - Blob is sanitized (sensitive keys redacted, control chars stripped, hard
 *    cap at 4 KB) before persist. We never trust callers to have done this.
 *  - When an `ExecutionContext` is supplied, the insert is dispatched via
 *    `ctx.waitUntil()` so a slow registry write doesn't add latency to the
 *    user-visible request path.
 */

import type { DrizzleD1Database } from 'drizzle-orm/d1';
import * as registrySchema from './db/schema/registry';
import { auditEvents } from './db/schema/registry';
import { AuditEventSchema, type AuditEvent } from '../schemas/audit';
import { isSensitiveKey, sanitizeString } from '../lib/log';

const REDACTED = '[redacted]';
const MAX_BLOB_BYTES = 4096;
const MAX_BLOB_STRING_LENGTH = 1024;

type AuditDb = DrizzleD1Database<typeof registrySchema>;

/**
 * Record a single audit event. Always resolves — never throws.
 *
 * @param db    Drizzle handle bound to the shared registry D1.
 * @param event Caller-supplied event (validated against `AuditEventSchema`).
 * @param ctx   Optional Worker `ExecutionContext`. When provided, the actual
 *              insert is dispatched via `ctx.waitUntil()` so the call site is
 *              non-blocking. Without a ctx, the insert is awaited inline.
 */
export async function recordAuditEvent(db: AuditDb, event: AuditEvent, ctx?: ExecutionContext): Promise<void> {
	const parsed = AuditEventSchema.safeParse(event);
	if (!parsed.success) {
		console.warn('[audit] invalid event — dropped', { issues: parsed.error.issues });
		return;
	}

	const row = buildRow(parsed.data);

	const work = (async () => {
		try {
			await db.insert(auditEvents).values(row);
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			console.warn('[audit] insert failed (fail-soft)', { error: message, action: row.action });
		}
	})();

	if (ctx && typeof ctx.waitUntil === 'function') {
		ctx.waitUntil(work);
		return;
	}
	await work;
}

function buildRow(event: AuditEvent) {
	const id = crypto.randomUUID();
	const timestamp = Date.now();
	const blobString = event.blob ? serializeBlob(event.blob) : null;

	return {
		id,
		timestamp,
		actor_principal: event.actorPrincipal,
		actor_tier: event.actorTier,
		super_tenant_id: event.superTenantId ?? null,
		sub_tenant_id: event.subTenantId ?? null,
		action: event.action,
		resource_type: event.resourceType,
		resource_id: event.resourceId ?? null,
		outcome: event.outcome,
		request_id: event.requestId ?? null,
		cf_ray: event.cfRay ?? null,
		ip_hash: event.ipHash ?? null,
		blob: blobString,
	};
}

function serializeBlob(blob: Record<string, unknown>): string {
	const sanitized = sanitizeBlobValue(blob, undefined, 0) as Record<string, unknown>;
	let serialized: string;
	try {
		serialized = JSON.stringify(sanitized);
	} catch {
		serialized = JSON.stringify({ error: 'blob_unserializable' });
	}
	if (serialized.length > MAX_BLOB_BYTES) {
		// Truncate and tag — preserves shape for grep without exploding D1 row size.
		return serialized.slice(0, MAX_BLOB_BYTES - 16) + '..."truncated"}';
	}
	return serialized;
}

const MAX_BLOB_DEPTH = 6;

function sanitizeBlobValue(value: unknown, key: string | undefined, depth: number): unknown {
	if (depth > MAX_BLOB_DEPTH) return '[truncated:depth]';
	if (key && isSensitiveKey(key)) return REDACTED;

	if (typeof value === 'string') {
		return sanitizeString(value, MAX_BLOB_STRING_LENGTH);
	}
	if (Array.isArray(value)) {
		return value.map((v) => sanitizeBlobValue(v, undefined, depth + 1));
	}
	if (value && typeof value === 'object') {
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
			out[k] = sanitizeBlobValue(v, k, depth + 1);
		}
		return out;
	}
	return value;
}
