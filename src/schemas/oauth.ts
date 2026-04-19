// SPDX-License-Identifier: BUSL-1.1
import { z } from 'zod';

const RedirectUriSchema = z.string().url().max(2048);

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

export const CodeRecordSchema = z.object({
	client_id: z.string(),
	redirect_uri: z.string(),
	code_challenge: z.string(),
	issued_at: z.number(),
	scope: z.string().optional(),
});
export type CodeRecord = z.infer<typeof CodeRecordSchema>;
