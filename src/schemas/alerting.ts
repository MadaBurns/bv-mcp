// SPDX-License-Identifier: BUSL-1.1
import { z } from 'zod';
import type { FuzzVerdict } from '../lib/fuzzing-detector';

/**
 * Inter-service contract for fuzzing-detection alerts pushed to ALERT_WEBHOOK_URL.
 * Consumers (Slack/Discord/PagerDuty bridges) parse against this schema.
 *
 * Hard rule: principalIdHash must be 16 hex chars (matching the existing
 * `keyHash` truncation pattern from src/lib/tier-auth.ts). A raw IP MUST NEVER
 * appear in the payload — privacy invariant; enforced by regex.
 */
export const FuzzingAlertSchema = z.object({
	type: z.literal('fuzzing_suspected'),
	principalKind: z.enum(['ip', 'keyHash']),
	principalIdHash: z.string().regex(/^[a-f0-9]{16}$/),
	kind: z.enum(['unknown_tool', 'unknown_method', 'zod_arg', 'auth_fail', 'mixed']),
	count: z.number().int().positive(),
	windowSeconds: z.number().int().positive(),
	observedAt: z.string().datetime(),
});
export type FuzzingAlert = z.infer<typeof FuzzingAlertSchema>;

export interface BuildAlertContext {
	principalKind: 'ip' | 'keyHash';
	principalIdHash: string;
	observedAt: string;
}

/**
 * Build a webhook payload from a verdict + principal context.
 * Throws if the result fails schema validation — defensive guarantee that
 * the producer cannot accidentally leak a raw IP.
 */
export function buildFuzzingAlertPayload(verdict: FuzzVerdict, ctx: BuildAlertContext): FuzzingAlert {
	if (!verdict.suspected || !verdict.kind || !verdict.count || !verdict.windowSeconds) {
		throw new Error('buildFuzzingAlertPayload requires a suspected verdict');
	}
	const candidate = {
		type: 'fuzzing_suspected' as const,
		principalKind: ctx.principalKind,
		principalIdHash: ctx.principalIdHash,
		kind: verdict.kind,
		count: verdict.count,
		windowSeconds: verdict.windowSeconds,
		observedAt: ctx.observedAt,
	};
	return FuzzingAlertSchema.parse(candidate);
}
