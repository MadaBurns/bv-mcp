/**
 * Authentication Helpers
 *
 * Constant-time bearer token validation and unauthorized response builder.
 * Uses SHA-256 hashing to eliminate length-oracle timing side-channels,
 * then constant-time XOR comparison on the fixed-length digests.
 * Used by the /mcp auth middleware and rate-limit bypass logic.
 */

import { jsonRpcError, JSON_RPC_ERRORS } from './json-rpc';

/** Validate a bearer token against the expected value using constant-time comparison */
export async function isAuthorizedRequest(authHeader: string | undefined, expectedToken: string): Promise<boolean> {
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return false;
	}
	const token = authHeader.slice('Bearer '.length).trim();
	if (token.length === 0) {
		return false;
	}
	// Hash both values with SHA-256 to produce fixed-length digests.
	// This eliminates the length oracle — different-length inputs still
	// produce 32-byte hashes that are compared in constant time.
	const encoder = new TextEncoder();
	const [hashA, hashB] = await Promise.all([
		crypto.subtle.digest('SHA-256', encoder.encode(token)),
		crypto.subtle.digest('SHA-256', encoder.encode(expectedToken)),
	]);
	const a = new Uint8Array(hashA);
	const b = new Uint8Array(hashB);
	// Constant-time comparison: XOR each byte and accumulate.
	// Always processes all 32 bytes regardless of mismatch position.
	let mismatch = 0;
	for (let i = 0; i < a.byteLength; i++) {
		mismatch |= a[i] ^ b[i];
	}
	return mismatch === 0;
}

/** Build a 401 JSON response with a JSON-RPC unauthorized error */
export function unauthorizedResponse() {
	return Response.json(jsonRpcError(null, JSON_RPC_ERRORS.UNAUTHORIZED, 'Unauthorized: missing or invalid bearer token'), { status: 401 });
}
