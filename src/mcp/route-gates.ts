import { checkControlPlaneRateLimit } from '../lib/rate-limiter';
import { validateSession } from '../lib/session';
import { JSON_RPC_ERRORS, jsonRpcError } from '../lib/json-rpc';

export async function buildControlPlaneRateLimitResponse(
	ip: string,
	kv: KVNamespace | undefined,
	method: string,
	isAuthenticated: boolean,
	id: string | number | null | undefined,
): Promise<Response | undefined> {
	if (isAuthenticated || method === 'tools/call') return undefined;

	const rateResult = await checkControlPlaneRateLimit(ip, kv);
	if (rateResult.allowed) return undefined;

	const headers: Record<string, string> = {
		'x-ratelimit-limit': '30',
		'x-ratelimit-remaining': String(rateResult.minuteRemaining),
	};
	if (rateResult.retryAfterMs !== undefined) {
		headers['retry-after'] = String(Math.ceil(rateResult.retryAfterMs / 1000));
	}

	return Response.json(
		jsonRpcError(
			id,
			JSON_RPC_ERRORS.RATE_LIMITED,
			`Rate limit exceeded. Retry after ${Math.ceil((rateResult.retryAfterMs ?? 0) / 1000)}s`,
		),
		{ status: 429, headers },
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
