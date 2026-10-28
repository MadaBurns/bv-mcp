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
	})
	.strict();
export type EmaTenantRecord = z.infer<typeof EmaTenantRecordSchema>;

/** PUT /internal/oauth/ema-tenants request body. `jwks_uri` is resolved from issuer discovery when absent. */
export const EmaTenantUpsertRequestSchema = z
	.object({
		...EmaTenantFieldsSchema,
		jwks_uri: HttpsUrlSchema.optional(),
	})
	.strict();
export type EmaTenantUpsertRequest = z.infer<typeof EmaTenantUpsertRequestSchema>;
