// SPDX-License-Identifier: BUSL-1.1

import { JSON_RPC_ERRORS, jsonRpcError } from '../lib/json-rpc';
import type { JsonRpcRequest } from '../lib/json-rpc';

type RequestErrorStatus = 400 | 413 | 415;

export interface ParsedJsonRpcRequestResult {
	ok: boolean;
	body?: JsonRpcRequest | unknown[];
	isBatch?: boolean;
	status?: RequestErrorStatus;
	payload?: ReturnType<typeof jsonRpcError>;
}

export interface RequestBodyReadResult {
	ok: boolean;
	rawBody?: string;
	status?: RequestErrorStatus;
	payload?: ReturnType<typeof jsonRpcError>;
}

export function parseAllowedHosts(raw: string | undefined): string[] | undefined {
	const trimmed = raw?.trim();
	if (!trimmed) return undefined;
	return trimmed
		.split(',')
		.map((host) => host.trim().toLowerCase())
		.filter((host) => host.length > 0);
}

export function summarizeParamsForLog(params: unknown): Record<string, unknown> | undefined {
	if (!params || typeof params !== 'object' || Array.isArray(params)) return undefined;
	return {
		keys: Object.keys(params).sort().slice(0, 25),
	};
}

export function normalizeHeaders(headers: Headers): Record<string, string> {
	const normalized: Record<string, string> = {};
	headers.forEach((value, key) => {
		normalized[key.toLowerCase()] = value;
	});
	return normalized;
}

/**
 * Validate Content-Type for JSON-RPC POST requests.
 * Accepts: application/json (with optional params like charset), or missing Content-Type (client compat).
 * Rejects: text/plain, application/xml, multipart/form-data, etc. with 415 Unsupported Media Type.
 */
export function validateContentType(contentType: string | undefined | null): RequestBodyReadResult | undefined {
	// Missing Content-Type: allow for client compatibility (some MCP clients omit it)
	if (!contentType) return undefined;

	const mediaType = contentType.split(';')[0].trim().toLowerCase();
	if (mediaType === 'application/json') return undefined;

	return {
		ok: false,
		status: 415,
		payload: jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Unsupported Media Type: Content-Type must be application/json'),
	};
}

export async function readRequestBody(request: Request, maxBytes: number): Promise<RequestBodyReadResult> {
	let rawBody = '';
	const reader = request.body?.getReader();
	if (reader) {
		let total = 0;
		const decoder = new TextDecoder();
		while (true) {
			const { value, done } = await reader.read();
			if (done) break;
			total += value.length;
			if (total > maxBytes) {
				return {
					ok: false,
					status: 413,
					payload: jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Request body too large'),
				};
			}
			rawBody += decoder.decode(value, { stream: true });
		}
		rawBody += decoder.decode(); // flush any remaining buffered bytes
	} else {
		rawBody = await request.text();
		if (rawBody.length > maxBytes) {
			return {
				ok: false,
				status: 413,
				payload: jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Request body too large'),
			};
		}
	}

	return {
		ok: true,
		rawBody,
	};
}

export function parseJsonRpcRequest(rawBody: string): ParsedJsonRpcRequestResult {
	try {
		const parsed = JSON.parse(rawBody);
		if (Array.isArray(parsed)) {
			if (parsed.length === 0) {
				return {
					ok: false,
					status: 400,
					payload: jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC batch request: empty array'),
				};
			}
			return {
				ok: true,
				body: parsed,
				isBatch: true,
			};
		}
		return {
			ok: true,
			body: parsed as JsonRpcRequest, // validated by validateJsonRpcRequest above
			isBatch: false,
		};
	} catch {
		return {
			ok: false,
			status: 400,
			payload: jsonRpcError(null, JSON_RPC_ERRORS.PARSE_ERROR, 'Parse error: invalid JSON'),
		};
	}
}

export function validateJsonRpcRequest(body: JsonRpcRequest): { status: 400; payload: ReturnType<typeof jsonRpcError> } | undefined {
	if (body.jsonrpc !== '2.0' || typeof body.method !== 'string') {
		return {
			status: 400,
			payload: jsonRpcError(body.id, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC 2.0 request'),
		};
	}

	if (body.id !== undefined && body.id !== null && typeof body.id !== 'string' && typeof body.id !== 'number') {
		return {
			status: 400,
			payload: jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC id: must be string, number, or null'),
		};
	}

	return undefined;
}