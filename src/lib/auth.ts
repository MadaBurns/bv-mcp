/**
 * Authentication Helpers
 *
 * Constant-time bearer token validation and unauthorized response builder.
 * Used by the /mcp auth middleware and rate-limit bypass logic.
 */

import { jsonRpcError, JSON_RPC_ERRORS } from './json-rpc';

/** Validate a bearer token against the expected value using constant-time comparison */
export function isAuthorizedRequest(authHeader: string | undefined, expectedToken: string): boolean {
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return false;
	}
	const token = authHeader.slice('Bearer '.length).trim();
	if (token.length === 0 || token.length !== expectedToken.length) {
		return false;
	}
	// Constant-time comparison to prevent timing side-channel attacks.
	// XOR each byte and accumulate — always processes all bytes regardless of mismatch position.
	const encoder = new TextEncoder();
	const a = encoder.encode(token);
	const b = encoder.encode(expectedToken);
	let mismatch = a.byteLength ^ b.byteLength;
	for (let i = 0; i < a.byteLength; i++) {
		mismatch |= a[i] ^ b[i];
	}
	return mismatch === 0;
}

/** Build a 401 JSON response with a JSON-RPC unauthorized error */
export function unauthorizedResponse() {
	return Response.json(jsonRpcError(null, JSON_RPC_ERRORS.UNAUTHORIZED, 'Unauthorized: missing or invalid bearer token'), { status: 401 });
}
