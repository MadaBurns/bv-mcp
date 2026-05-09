// SPDX-License-Identifier: BUSL-1.1

/**
 * Zod schema for cross-tenant audit-log events.
 *
 * Source of truth for the input contract of `recordAuditEvent()`
 * (`src/tenant/audit.ts`) and the persisted `audit_events` table
 * (`src/tenant/db/schema/registry.ts`).
 *
 * `actorTier` reuses the same six-value enum as `lib/auth.ts` rather than
 * importing `TierSchema` from `primitives.ts` — the audit log records
 * historical state, so we want the enum baked into the audit contract
 * rather than coupled to a future expansion of `TierSchema`.
 */

import { z } from 'zod';

export const AuditOutcomeSchema = z.enum(['success', 'denied', 'error']);
export type AuditOutcome = z.infer<typeof AuditOutcomeSchema>;

export const AuditActorTierSchema = z.enum(['free', 'agent', 'developer', 'enterprise', 'partner', 'owner']);
export type AuditActorTier = z.infer<typeof AuditActorTierSchema>;

export const AuditEventSchema = z.object({
	actorPrincipal: z.string().min(1).max(128),
	actorTier: AuditActorTierSchema,
	superTenantId: z.string().min(1).max(128).optional(),
	subTenantId: z.string().min(1).max(128).optional(),
	action: z.string().min(1).max(64),
	resourceType: z.string().min(1).max(64),
	resourceId: z.string().min(1).max(256).optional(),
	outcome: AuditOutcomeSchema,
	requestId: z.string().min(1).max(128).optional(),
	cfRay: z.string().min(1).max(64).optional(),
	ipHash: z.string().min(1).max(64).optional(),
	blob: z.record(z.string(), z.unknown()).optional(),
});

export type AuditEvent = z.infer<typeof AuditEventSchema>;
