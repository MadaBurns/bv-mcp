// SPDX-License-Identifier: BUSL-1.1

/**
 * Enterprise Managed Auth (EMA) tenant records — the per-tenant allowlist of
 * trusted IdP issuers. An identity assertion whose `iss` is not allowlisted here
 * must be rejected even with a valid signature.
 */

import { z } from 'zod';
import { CLAUDE_WEB_CIMD_CLIENT_ID } from '../oauth/cimd';

const HttpsUrlSchema = z
	.string()
	.max(512)
	.refine((value) => {
		try {
			return new URL(value).protocol === 'https:';
		} catch {
			return false;
		}
	}, 'must be an https URL');

/** How many rejected issuers a tenant remembers; the oldest is dropped past it. */
export const EMA_REJECTED_ISSUER_LIMIT = 16;

export const EMA_TENANT_ID_PATTERN = /^[a-z0-9][a-z0-9-]{2,47}$/;

/**
 * A self-serve tenant id: `web-` plus the bv-web tenant id (a UUID there), at least 8 characters of it so a
 * short guessable suffix cannot name a tenant. The whole id still fits EMA_TENANT_ID_PATTERN (48 characters).
 */
export const EMA_SELF_SERVE_TENANT_ID_PATTERN = /^web-[a-z0-9-]{8,44}$/;

/**
 * Operator sign-off on a tenant. Only an approved tenant mints, owns its issuer, or backs tokens it
 * issued earlier. 'rejected' is sticky: only a self-serve move to another issuer returns it to pending.
 */
export const EmaApprovalSchema = z.enum(['pending', 'approved', 'rejected']);
export type EmaApproval = z.infer<typeof EmaApprovalSchema>;

const EmaTenantFieldsSchema = {
	tenant_id: z.string().regex(EMA_TENANT_ID_PATTERN),
	name: z.string().min(1).max(120),
	issuer: HttpsUrlSchema,
	/** Defaults to the Claude web/Desktop/mobile CIMD client. */
	allowed_client_ids: z.array(z.string().min(1).max(512)).min(1).max(8).default([CLAUDE_WEB_CIMD_CLIENT_ID]),
	tier: z.enum(['developer', 'enterprise']),
	enabled: z.boolean(),
	/** Epoch SECONDS. Absent = no expiry. */
	entitlement_expires_at: z.number().int().positive().optional(),
};

export const EmaTenantRecordSchema = z
	.object({
		...EmaTenantFieldsSchema,
		jwks_uri: HttpsUrlSchema,
		created_at: z.number().int(),
		updated_at: z.number().int(),
		/**
		 * Server-managed, never accepted from a caller: the tenant's token epoch. Every EMA access token
		 * carries it as `tep`, and the registry moves it (only ever up) in the same transaction as any write
		 * that revokes, so every token minted before that write dies. Absent only on a legacy KV record
		 * (then `created_at` stands in).
		 */
		token_epoch: z.number().int().positive().optional(),
		/**
		 * Server-managed: the record's revision, raised by every registry write. The approve compare-and-set
		 * names it, so it catches any change the operator did not review, two in one second included.
		 * Absent only on a legacy KV record.
		 */
		rev: z.number().int().nonnegative().optional(),
		/**
		 * sha256 (hex) of every normalized issuer the operator rejected for this tenant, oldest first, at most
		 * EMA_REJECTED_ISSUER_LIMIT. A self-serve write naming one stays rejected, so moving to another issuer
		 * and back cannot launder a refusal. Server-managed; the operator approving that issuer removes it.
		 */
		rejected_issuer_hashes: z
			.array(z.string().regex(/^[a-f0-9]{64}$/))
			.max(EMA_REJECTED_ISSUER_LIMIT)
			.optional(),
		/** Absent = approved for an operator record (seeded before approval existed), pending for a self-serve one. */
		approval: EmaApprovalSchema.optional(),
		/**
		 * Who manages the record, server-managed. Absent = operator (the only writer before the
		 * self-serve route existed). The self-serve route only ever touches 'self-serve' records.
		 */
		source: z.enum(['operator', 'self-serve']).optional(),
	})
	.strict();
export type EmaTenantRecord = z.infer<typeof EmaTenantRecordSchema>;

/** PUT /internal/oauth/ema-tenants request body. `jwks_uri` is resolved from issuer discovery when absent. */
export const EmaTenantUpsertRequestSchema = z
	.object({
		...EmaTenantFieldsSchema,
		jwks_uri: HttpsUrlSchema.optional(),
		/** Omitted = keep the stored approval (none on a new record, which reads as approved). */
		approval: EmaApprovalSchema.optional(),
	})
	.strict();
export type EmaTenantUpsertRequest = z.infer<typeof EmaTenantUpsertRequestSchema>;

const { name, issuer, tier, enabled } = EmaTenantFieldsSchema;

/** The furthest ahead a self-serve entitlement may reach; bv-web renews it from the subscription. */
export const EMA_SELF_SERVE_MAX_ENTITLEMENT_SECONDS = 400 * 24 * 60 * 60;

/**
 * PUT /internal/oauth/ema-self-serve/:tenant_id request body: the customer-editable subset. tenant_id
 * comes from the path; jwks_uri (always discovered), allowed_client_ids (always the default), approval,
 * source and token_epoch are server-decided, so a body naming any of them is a 400. The entitlement is
 * required and bounded; a past value is allowed and simply lapses the tenant (bv-web's revoke).
 */
export const EmaSelfServeUpsertRequestSchema = z
	.object({
		name,
		issuer,
		enabled,
		tier,
		entitlement_expires_at: z
			.number()
			.int()
			.positive()
			.refine((value) => value <= Math.floor(Date.now() / 1000) + EMA_SELF_SERVE_MAX_ENTITLEMENT_SECONDS, 'must be at most 400 days ahead'),
		/**
		 * Optional compare-and-set: the `rev` the caller last read (GET answers it). The registry applies the write only while
		 * the stored record is still at that rev, else 409 ema_record_changed. A precondition, never stored; omitted = latest write wins.
		 */
		expected_rev: z.number().int().nonnegative().optional(),
	})
	.strict();
export type EmaSelfServeUpsertRequest = z.infer<typeof EmaSelfServeUpsertRequestSchema>;

/**
 * POST /internal/oauth/ema-tenants/:tenant_id/approve body: the snapshot the operator reviewed (the record's
 * issuer, jwks_uri and rev, as GET answers them). The approval lands only while the stored record still
 * matches it on all three fields (else 409 approval_stale).
 */
export const EmaApproveRequestSchema = z
	.object({ issuer: z.string().max(512), jwks_uri: z.string().max(512), rev: z.number().int().nonnegative() })
	.strict();
export type EmaApproveRequest = z.infer<typeof EmaApproveRequestSchema>;

// ─── The EMA registry protocol: the QuotaCoordinator `ema-*` request kinds (oauth/ema-tenants.ts) ───

/** The most records one `ema-list` page returns (the operator list route's page size). */
export const EMA_LIST_PAGE_LIMIT = 100;

/** The most legacy KV tenants the one-time import moves; more refuses the import (every EMA call stays 503). */
export const EMA_MIGRATE_LIMIT = 500;

const EmaRegistryTenantIdSchema = z.string().regex(EMA_TENANT_ID_PATTERN);

/** An operator upsert as the registry takes it: jwks_uri resolved, and still no server-managed field. */
export const EmaOperatorUpsertSchema = EmaTenantUpsertRequestSchema.extend({ jwks_uri: HttpsUrlSchema }).strict();
export type EmaOperatorUpsert = z.infer<typeof EmaOperatorUpsertSchema>;

/**
 * One write. Each body is the strict route body, so a caller can never set a server-managed field
 * (token_epoch, rev, created_at, updated_at, rejected_issuer_hashes, source; approval only through the
 * operator upsert): the registry derives them from the fresh record.
 */
export const EmaWriteSchema = z.discriminatedUnion('op', [
	z.object({ op: z.literal('operator-upsert'), body: EmaOperatorUpsertSchema }).strict(),
	z
		.object({
			op: z.literal('self-serve-upsert'),
			body: EmaSelfServeUpsertRequestSchema,
			/** The jwks_uri the Worker discovered, and the issuer it discovered it for. */
			discovered: z.object({ issuer: HttpsUrlSchema, jwks_uri: HttpsUrlSchema }).strict().optional(),
		})
		.strict(),
	z.object({ op: z.literal('approve'), reviewed: EmaApproveRequestSchema }).strict(),
	z.object({ op: z.literal('reject') }).strict(),
]);
export type EmaWrite = z.infer<typeof EmaWriteSchema>;

/** Every `ema-*` request. The coordinator refuses anything else at the door, and the registry parses it again. */
export const EmaRegistryRequestSchema = z.discriminatedUnion('kind', [
	z.object({ kind: z.literal('ema-get'), tenantId: EmaRegistryTenantIdSchema }).strict(),
	z
		.object({
			kind: z.literal('ema-list'),
			limit: z.number().int().min(1).max(EMA_LIST_PAGE_LIMIT),
			approval: EmaApprovalSchema.optional(),
			cursor: EmaRegistryTenantIdSchema.optional(),
		})
		.strict(),
	z.object({ kind: z.literal('ema-resolve-issuer'), issuer: z.string().max(512) }).strict(),
	z.object({ kind: z.literal('ema-write'), tenantId: EmaRegistryTenantIdSchema, write: EmaWriteSchema }).strict(),
	z.object({ kind: z.literal('ema-delete'), tenantId: EmaRegistryTenantIdSchema, mode: z.enum(['operator', 'self-serve']) }).strict(),
	z.object({ kind: z.literal('ema-migrate'), records: z.array(EmaTenantRecordSchema).max(EMA_MIGRATE_LIMIT) }).strict(),
]);
/** A request as a caller builds it (defaults not yet applied). */
export type EmaRegistryRequest = z.input<typeof EmaRegistryRequestSchema>;
