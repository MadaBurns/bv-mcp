// SPDX-License-Identifier: BUSL-1.1
import { z } from 'zod';
import { CodeRecordSchema, PaidOAuthEntitlementResponseSchema, type CodeRecord, type PaidOAuthEntitlementResponse } from '../schemas/oauth';

export const PaidOAuthEntitlementRequestSchema = z.object({
	clientId: z.string().min(1).max(200),
	redirectUri: z.string().url().max(2048),
	codeChallenge: z.string().min(43).max(128),
	scope: z.string().min(1).max(200).optional(),
});
export type PaidOAuthEntitlementRequest = z.infer<typeof PaidOAuthEntitlementRequestSchema>;

export interface PaidOAuthEntitlementEnv {
	BV_WEB?: Fetcher;
	BV_WEB_INTERNAL_KEY?: string;
}

/**
 * Ask bv-web, the identity and Stripe billing authority, for a customer OAuth entitlement.
 */
export async function fetchPaidOAuthEntitlement(
	env: PaidOAuthEntitlementEnv,
	request: PaidOAuthEntitlementRequest,
): Promise<PaidOAuthEntitlementResponse | null> {
	const parsedRequest = PaidOAuthEntitlementRequestSchema.parse(request);
	if (!env.BV_WEB || !env.BV_WEB_INTERNAL_KEY) {
		throw new Error('BV_WEB OAuth entitlement binding is not configured');
	}

	const response = await env.BV_WEB.fetch(
		new Request('https://internal/api/internal/mcp/oauth/authorize', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Authorization': `Bearer ${env.BV_WEB_INTERNAL_KEY}`,
			},
			body: JSON.stringify(parsedRequest),
		}),
	);

	if (response.status === 401 || response.status === 403 || response.status === 404) {
		return null;
	}
	if (!response.ok) {
		throw new Error(`OAuth entitlement lookup failed with status ${response.status}`);
	}

	const entitlement = PaidOAuthEntitlementResponseSchema.safeParse(await response.json());
	if (!entitlement.success) {
		throw new Error('Invalid OAuth entitlement response');
	}
	return entitlement.data;
}

/** Convert a validated bv-web entitlement into a one-time OAuth code record. */
export function buildCodeRecordFromEntitlement(params: {
	clientId: string;
	redirectUri: string;
	codeChallenge: string;
	scope?: string;
	entitlement: PaidOAuthEntitlementResponse;
}): CodeRecord {
	return CodeRecordSchema.parse({
		client_id: params.clientId,
		redirect_uri: params.redirectUri,
		code_challenge: params.codeChallenge,
		issued_at: Math.floor(Date.now() / 1000),
		...(params.scope ? { scope: params.scope } : {}),
		subject: params.entitlement.subject,
		tier: params.entitlement.tier,
		...(params.entitlement.emailHash ? { emailHash: params.entitlement.emailHash } : {}),
		...(params.entitlement.stripeCustomerId ? { stripeCustomerId: params.entitlement.stripeCustomerId } : {}),
		...(params.entitlement.stripeSubscriptionId ? { stripeSubscriptionId: params.entitlement.stripeSubscriptionId } : {}),
		subscriptionStatus: params.entitlement.subscriptionStatus,
		...(params.entitlement.entitlementExpiresAt ? { entitlementExpiresAt: params.entitlement.entitlementExpiresAt } : {}),
	});
}
