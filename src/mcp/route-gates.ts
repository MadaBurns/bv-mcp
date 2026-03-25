// SPDX-License-Identifier: BUSL-1.1

import { checkControlPlaneRateLimit } from '../lib/rate-limiter';
import { validateSession } from '../lib/session';
import { JSON_RPC_ERRORS, jsonRpcError } from '../lib/json-rpc';
import { sseErrorResponse } from '../lib/sse';

export async function buildControlPlaneRateLimitResponse(
	ip: string,
	kv: KVNamespace | undefined,
	method: string,
	isAuthenticated: boolean,
	id: string | number | null | undefined,
	accept?: string,
	quotaCoordinator?: DurableObjectNamespace,
): Promise<Response | undefined> {
	// Exempt: authenticated users, tool calls (have their own rate limiter), notifications,
	// SSE streams, and all read-only protocol methods. Protocol methods are idempotent and
	// rate-limiting them causes mcp-remote reconnection storms to snowball — each reconnect
	// burns 4 requests (initialize + tools/list + resources/list + prompts/list), hitting
	// the 60/min control plane limit after ~15 cycles and creating a permanent dead connection.
	if (
		isAuthenticated ||
		method === 'tools/call' ||
		method.startsWith('notifications/') ||
		method === 'sse/stream' ||
		method === 'initialize' ||
		method === 'tools/list' ||
		method === 'resources/list' ||
		method === 'prompts/list' ||
		method === 'prompts/get' ||
		method === 'ping'
	)
		return undefined;

	const rateResult = await checkControlPlaneRateLimit(ip, kv, quotaCoordinator);
	if (rateResult.allowed) return undefined;

	const headers: Record<string, string> = {
		'x-ratelimit-limit': '60',
		'x-ratelimit-remaining': String(rateResult.minuteRemaining),
	};
	if (rateResult.retryAfterMs !== undefined) {
		headers['retry-after'] = String(Math.ceil(rateResult.retryAfterMs / 1000));
	}

	return sseErrorResponse(
		jsonRpcError(
			id,
			JSON_RPC_ERRORS.RATE_LIMITED,
			`Rate limit exceeded. Retry after ${Math.ceil((rateResult.retryAfterMs ?? 0) / 1000)}s`,
		),
		429,
		accept,
		headers,
		id != null ? String(id) : undefined,
	);
}

export interface SessionValidationError {
	status: 400 | 404;
	payload: ReturnType<typeof jsonRpcError>;
}

/**
 * Validate session for non-initialize requests.
 * Returns 400 for missing session header, 404 for expired/terminated sessions.
 */
export async function validateSessionRequest(
	sessionId: string | undefined,
	sessionStore: KVNamespace | undefined,
	id: string | number | null | undefined,
	message: string,
): Promise<SessionValidationError | undefined> {
	if (!sessionId) {
		return {
			status: 400,
			payload: jsonRpcError(id, JSON_RPC_ERRORS.INVALID_REQUEST, message),
		};
	}
	if (!(await validateSession(sessionId, sessionStore))) {
		return {
			status: 404,
			payload: jsonRpcError(id, JSON_RPC_ERRORS.INVALID_REQUEST, 'Not Found: session expired or terminated'),
		};
	}
	return undefined;
}

/**
 * Resolve session for GET /mcp SSE stream.
 * Requires an existing valid session — does not create sessions (use POST initialize for that).
 */
export async function resolveSseSession(options: {
	sessionId: string | undefined;
	ip: string;
	rateLimitKv?: KVNamespace;
	sessionStore?: KVNamespace;
}): Promise<{ response?: Response; sessionId?: string }> {
	if (!options.sessionId) {
		return {
			response: Response.json(
				jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Bad Request: missing session'),
				{ status: 400 },
			),
		};
	}

	if (!(await validateSession(options.sessionId, options.sessionStore))) {
		return {
			response: Response.json(
				jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Not Found: session expired or terminated'),
				{ status: 404 },
			),
		};
	}

	return { sessionId: options.sessionId };
}
