/**
 * JSON-RPC 2.0 Protocol Utilities
 *
 * Shared types and helpers for constructing JSON-RPC 2.0
 * request/response/error objects used throughout the MCP server.
 */

/** JSON-RPC 2.0 request shape */
export interface JsonRpcRequest {
	jsonrpc: string;
	id?: string | number | null;
	method: string;
	params?: Record<string, unknown>;
}

/** JSON-RPC 2.0 error codes */
export const JSON_RPC_ERRORS = {
	PARSE_ERROR: -32700,
	INVALID_REQUEST: -32600,
	METHOD_NOT_FOUND: -32601,
	INVALID_PARAMS: -32602,
	INTERNAL_ERROR: -32603,
	UNAUTHORIZED: -32001,
	RATE_LIMITED: -32029,
} as const;

/** Build a JSON-RPC 2.0 error response object */
export function jsonRpcError(id: string | number | null | undefined, code: number, message: string) {
	return {
		jsonrpc: '2.0' as const,
		id: id ?? null,
		error: { code, message },
	};
}

/** Known safe error message prefixes that may be passed through to clients */
const SAFE_ERROR_PREFIXES = ['Missing required', 'Invalid', 'Domain ', 'Resource not found', 'Rate limit exceeded'];

/**
 * Sanitize an error for client-facing responses.
 * Returns the original message if it starts with a known safe prefix,
 * otherwise returns the generic fallback to prevent information leaks.
 *
 * @param error - The caught error (unknown type from catch blocks)
 * @param fallback - Generic message to return for unexpected errors
 */
export function sanitizeErrorMessage(error: unknown, fallback: string): string {
	if (error instanceof Error) {
		for (const prefix of SAFE_ERROR_PREFIXES) {
			if (error.message.startsWith(prefix)) {
				return error.message;
			}
		}
	}
	return fallback;
}

/** Build a JSON-RPC 2.0 success response object */
export function jsonRpcSuccess(id: string | number | null | undefined, result: unknown) {
	return {
		jsonrpc: '2.0' as const,
		id: id ?? null,
		result,
	};
}
