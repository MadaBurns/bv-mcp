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
} as const;

/** Build a JSON-RPC 2.0 error response object */
export function jsonRpcError(id: string | number | null | undefined, code: number, message: string) {
	return {
		jsonrpc: '2.0' as const,
		id: id ?? null,
		error: { code, message },
	};
}

/** Build a JSON-RPC 2.0 success response object */
export function jsonRpcSuccess(id: string | number | null | undefined, result: unknown) {
	return {
		jsonrpc: '2.0' as const,
		id: id ?? null,
		result,
	};
}
