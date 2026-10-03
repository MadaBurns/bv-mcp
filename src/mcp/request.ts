// SPDX-License-Identifier: BUSL-1.1

import { JSON_RPC_ERRORS, jsonRpcError } from '../lib/json-rpc';
import type { JsonRpcRequest } from '../lib/json-rpc';
import { JsonRpcRequestSchema } from '../schemas/json-rpc';
import { readBoundedText } from '../lib/request-body';

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
	const result = await readBoundedText(request, maxBytes);
	if (!result.ok) {
		return {
			ok: false,
			status: 413,
			payload: jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Request body too large'),
		};
	}

	return {
		ok: true,
		rawBody: result.text,
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
		// A bare `null` / primitive body is not a request object (JSON-RPC 2.0 §4). The batch
		// path rejects such entries per element, so the single path must too — otherwise
		// validateJsonRpcRequest dereferences `body.id` on null and the route 500s.
		if (parsed === null || typeof parsed !== 'object') {
			return {
				ok: false,
				status: 400,
				payload: jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC 2.0 request'),
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

/** Methods whose params the dispatcher dereferences unconditionally, with the string field each requires. */
const REQUIRED_STRING_PARAM = new Map<string, string>([
	['tools/call', 'name'],
	['resources/read', 'uri'],
	['prompts/get', 'name'],
]);

export function validateJsonRpcRequest(body: JsonRpcRequest): { status: 400; payload: ReturnType<typeof jsonRpcError> } | undefined {
	const result = JsonRpcRequestSchema.safeParse(body);
	if (!result.success) {
		const hasIdIssue = result.error.issues.some((i) => i.path.includes('id'));
		const message = hasIdIssue
			? 'Invalid JSON-RPC id: must be string, number, or null'
			: 'Invalid JSON-RPC 2.0 request';
		return {
			status: 400,
			// JSON-RPC 2.0 §5: when the id cannot be determined (here the id itself is the
			// invalid part), respond with id null rather than echoing the malformed value.
			payload: jsonRpcError(hasIdIssue ? null : (body?.id ?? null), JSON_RPC_ERRORS.INVALID_REQUEST, message),
		};
	}
	const requiredParam = REQUIRED_STRING_PARAM.get(result.data.method);
	if (requiredParam !== undefined && typeof result.data.params?.[requiredParam] !== 'string') {
		return {
			status: 400,
			payload: jsonRpcError(result.data.id ?? null, JSON_RPC_ERRORS.INVALID_PARAMS, `Invalid params: ${requiredParam} must be a string`),
		};
	}
	return undefined;
}
