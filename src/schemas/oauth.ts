// SPDX-License-Identifier: BUSL-1.1
import { z } from 'zod';

const RedirectUriSchema = z.string().url().max(2048);
const SafeOAuthIdentifierSchema = z.string().min(1).max(128).regex(/^[A-Za-z0-9:_-]+$/);
const StripeIdSchema = z.string().min(4).max(128).regex(/^[a-z]+_[A-Za-z0-9]+$/);
const EmailHashSchema = z.string().length(64).regex(/^[a-f0-9]{64}$/i);

/**
 * Tiers reachable via OAuth (bv-web Stripe entitlements).
 *
 * Per CLAUDE.md "Paid OAuth Tiers": only paid plans flow through OAuth, mapping to
 * `developer` (Pro / Business / MCP-Developer) or `enterprise` (Enterprise /
 * MCP-Enterprise). The `agent` tier is reserved for static API keys and is never
 * minted by bv-web; `owner` is privileged and never customer-facing. Keeping this
 * union narrow prevents a misconfigured bv-web response from silently escalating an
 * OAuth principal into a tier the rate limiter / quota coordinator never expected.
 */
export const CustomerOAuthTierSchema = z.enum(['developer', 'enterprise']);
export const ActiveStripeSubscriptionStatusSchema = z.enum(['active', 'trialing']);

export const PaidOAuthEntitlementResponseSchema = z.object({
	subject: SafeOAuthIdentifierSchema,
	emailHash: EmailHashSchema.optional(),
	tier: CustomerOAuthTierSchema,
	stripeCustomerId: StripeIdSchema.optional(),
	stripeSubscriptionId: StripeIdSchema.optional(),
	subscriptionStatus: ActiveStripeSubscriptionStatusSchema,
	scopes: z.array(z.string().min(1).max(64).regex(/^[a-z0-9:_-]+$/i)).min(1).max(20),
	entitlementExpiresAt: z.number().int().positive().optional(),
});
export type PaidOAuthEntitlementResponse = z.infer<typeof PaidOAuthEntitlementResponseSchema>;

export const InternalOAuthGrantRequestSchema = z
	.object({
		clientId: z.string().min(1).max(200),
		redirectUri: RedirectUriSchema,
		state: z.string().min(1).max(1024),
		scope: z.string().min(1).max(200).optional(),
		codeChallenge: z.string().min(43).max(128),
		codeChallengeMethod: z.literal('S256'),
		entitlement: PaidOAuthEntitlementResponseSchema,
	})
	.passthrough();
export type InternalOAuthGrantRequest = z.infer<typeof InternalOAuthGrantRequestSchema>;

export const RegisterRequestSchema = z
	.object({
		client_name: z.string().min(1).max(200).optional(),
		redirect_uris: z.array(RedirectUriSchema).min(1).max(10),
		grant_types: z.array(z.string()).optional(),
		response_types: z.array(z.string()).optional(),
		token_endpoint_auth_method: z.literal('none').optional().default('none'),
		scope: z.string().max(200).optional(),
		software_id: z.string().max(200).optional(),
		software_version: z.string().max(100).optional(),
	})
	.passthrough();
export type RegisterRequest = z.infer<typeof RegisterRequestSchema>;

export const AuthorizeQuerySchema = z
	.object({
		client_id: z.string().min(1).max(200),
		redirect_uri: RedirectUriSchema,
		response_type: z.literal('code'),
		state: z.string().min(1).max(1024),
		scope: z.string().max(200).optional(),
		code_challenge: z.string().min(43).max(128),
		code_challenge_method: z.literal('S256'),
	})
	.passthrough();
export type AuthorizeQuery = z.infer<typeof AuthorizeQuerySchema>;

export const TokenRequestSchema = z
	.object({
		grant_type: z.literal('authorization_code'),
		code: z.string().min(1).max(512),
		redirect_uri: RedirectUriSchema,
		client_id: z.string().min(1).max(200),
		code_verifier: z.string().min(43).max(128),
	})
	.passthrough();
export type TokenRequest = z.infer<typeof TokenRequestSchema>;

export const ClientRecordSchema = z.object({
	client_id: z.string(),
	client_id_issued_at: z.number(),
	redirect_uris: z.array(z.string()),
	client_name: z.string().optional(),
	software_id: z.string().optional(),
	software_version: z.string().optional(),
});
export type ClientRecord = z.infer<typeof ClientRecordSchema>;

export const CodeRecordSchema = z
	.object({
		client_id: z.string(),
		redirect_uri: z.string(),
		code_challenge: z.string(),
		issued_at: z.number(),
		scope: z.string().optional(),
		subject: SafeOAuthIdentifierSchema.optional(),
		tier: CustomerOAuthTierSchema.optional(),
		emailHash: EmailHashSchema.optional(),
		stripeCustomerId: StripeIdSchema.optional(),
		stripeSubscriptionId: StripeIdSchema.optional(),
		subscriptionStatus: ActiveStripeSubscriptionStatusSchema.optional(),
		entitlementExpiresAt: z.number().int().positive().optional(),
	})
	.superRefine((rec, ctx) => {
		const hasCustomerIdentity = rec.subject !== undefined || rec.tier !== undefined;
		if (hasCustomerIdentity && (!rec.subject || !rec.tier)) {
			ctx.addIssue({
				code: 'custom',
				path: ['subject'],
				message: 'Customer OAuth code records require both subject and tier',
			});
		}
	});
export type CodeRecord = z.infer<typeof CodeRecordSchema>;
