// SPDX-License-Identifier: BUSL-1.1

import type { TierAuthResult } from '../lib/tier-auth';
import { jsonRpcError, JSON_RPC_ERRORS, type JsonRpcRequest } from '../lib/json-rpc';
import { normalizeToolName } from '../handlers/tool-args';
import { GetAccessContextArgs } from '../schemas/tool-args';
import { validateJsonRpcRequest } from './request';

export interface AccessContextOptions {
	serverVersion: string;
	pseudonymSecret?: string;
}

export interface AccessContextResponse {
	payload: unknown;
	httpStatus: 200 | 400 | 503;
	headers: Record<string, string>;
}

export function isAccessContextToolCall(body: unknown): boolean {
	if (!body || typeof body !== 'object' || Array.isArray(body)) return false;
	const value = body as Record<string, unknown>;
	if (value.method !== 'tools/call' || !value.params || typeof value.params !== 'object' || Array.isArray(value.params)) return false;
	const name = (value.params as Record<string, unknown>).name;
	return typeof name === 'string' && normalizeToolName(name) === 'get_access_context';
}

export function unavailableAccessContextResult(serverVersion: string) {
	const receipt = {
		available: false,
		reason: 'verified_request_context_unavailable',
		authenticated: null,
		effectiveTier: null,
		ownerVerified: false,
		ownerIpGate: 'unknown',
		principalReference: null,
		principalReferenceStatus: 'unavailable',
		serverVersion,
		observedAt: new Date().toISOString(),
	};
	return {
		content: [{ type: 'text' as const, text: JSON.stringify(receipt) }],
		structuredContent: receipt,
		isError: true,
	};
}

/** Derive a receipt reference, never expose the security principal/hash itself. */
async function principalReference(secret: string, principal: string): Promise<string> {
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const signed = await crypto.subtle.sign('HMAC', key, encoder.encode(`blackveil-mcp/access-context/principal/v1\0${principal}`));
	return `acp_v1_${Array.from(new Uint8Array(signed), (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

/** Pure metadata response over an already verified, read-only authentication result. */
export async function handleAccessContextRequest(
	body: JsonRpcRequest,
	auth: TierAuthResult,
	options: AccessContextOptions,
): Promise<AccessContextResponse> {
	const headers = { 'cache-control': 'no-store' };
	const invalid = validateJsonRpcRequest(body);
	if (invalid) return { payload: invalid.payload, httpStatus: 400, headers };
	const params = body.params as Record<string, unknown> | undefined;
	const args = params && Object.hasOwn(params, 'arguments') ? params.arguments : {};
	if (!isAccessContextToolCall(body) || !Object.hasOwn(body, 'id') || !GetAccessContextArgs.safeParse(args).success) {
		return {
			payload: jsonRpcError(
				body.id,
				JSON_RPC_ERRORS.INVALID_PARAMS,
				'Invalid access context request: use a request id and empty arguments.',
			),
			httpStatus: 400,
			headers,
		};
	}
	if (auth.storageUnavailable) {
		return {
			payload: { jsonrpc: '2.0', id: body.id, result: unavailableAccessContextResult(options.serverVersion) },
			httpStatus: 503,
			headers,
		};
	}
	const effectiveTier = auth.authenticated ? (auth.tier ?? null) : null;
	const ownerIpGate = auth.ownerIpGate ?? (effectiveTier === 'owner' ? 'unknown' : 'not_applicable');
	const reference =
		auth.authenticated && auth.keyHash && options.pseudonymSecret ? await principalReference(options.pseudonymSecret, auth.keyHash) : null;
	const receipt = {
		available: true,
		authenticated: auth.authenticated,
		effectiveTier,
		ownerVerified: auth.authenticated && effectiveTier === 'owner' && (ownerIpGate === 'allowed' || ownerIpGate === 'not_required'),
		ownerIpGate,
		principalReference: reference,
		principalReferenceStatus: reference ? 'available' : auth.authenticated ? 'unavailable' : 'not_authenticated',
		serverVersion: options.serverVersion,
		observedAt: new Date().toISOString(),
	};
	return {
		payload: {
			jsonrpc: '2.0',
			id: body.id,
			result: { content: [{ type: 'text', text: JSON.stringify(receipt) }], structuredContent: receipt },
		},
		httpStatus: 200,
		headers,
	};
}
