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

export const EMA_TENANT_ID_PATTERN = /^[a-z0-9][a-z0-9-]{2,47}$/;

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
		 * Epoch MILLISECONDS, server-managed: set by the upsert route, never accepted in a PUT body.
		 * Every EMA access token carries the tenant's epoch as `tep`, so moving it revokes every token
		 * minted before. Absent on records written before it existed (the epoch is then `created_at`).
		 */
		token_epoch: z.number().int().positive().optional(),
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
	})
	.strict();
export type EmaSelfServeUpsertRequest = z.infer<typeof EmaSelfServeUpsertRequestSchema>;

/**
 * POST /internal/oauth/ema-tenants/:tenant_id/approve body: the snapshot the operator reviewed. The
 * approval lands only while the stored record still matches it on all three fields (else 409).
 */
export const EmaApproveRequestSchema = z
	.object({ issuer: z.string().max(512), jwks_uri: z.string().max(512), updated_at: z.number().int() })
	.strict();
export type EmaApproveRequest = z.infer<typeof EmaApproveRequestSchema>;
