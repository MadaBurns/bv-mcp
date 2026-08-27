// SPDX-License-Identifier: BUSL-1.1

import { jsonRpcError, JSON_RPC_ERRORS } from '../lib/json-rpc';
import { readJsonResponseCapped, readTextResponseCapped } from '../lib/response-body';

const JSON_RPC_ERROR_MAX_BODY_BYTES = 64 * 1024;

/** Preserve relevant protocol headers while excluding body-owned headers. */
export function extractProtocolHeaders(response: Response): Record<string, string> {
	const headers: Record<string, string> = {};
	response.headers.forEach((value, key) => {
		const lower = key.toLowerCase();
		if (lower === 'content-type' || lower === 'cache-control' || lower === 'content-length') return;
		headers[key] = value;
	});
	return headers;
}

/** Read a JSON-RPC error from either HTTP JSON or a one-event SSE response. */
export async function readJsonRpcErrorPayload(response: Response): Promise<ReturnType<typeof jsonRpcError>> {
	const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
	if (contentType.includes('text/event-stream')) {
		const text = await readTextResponseCapped(response, JSON_RPC_ERROR_MAX_BODY_BYTES);
		if (text === null) return jsonRpcError(null, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error');
		const dataLine = text.split('\n').find((line) => line.startsWith('data: '));
		if (!dataLine) return jsonRpcError(null, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error');
		try {
			return JSON.parse(dataLine.slice('data: '.length)) as ReturnType<typeof jsonRpcError>;
		} catch {
			return jsonRpcError(null, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error');
		}
	}
	return (
		(await readJsonResponseCapped<ReturnType<typeof jsonRpcError>>(response, JSON_RPC_ERROR_MAX_BODY_BYTES)) ??
		jsonRpcError(null, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error')
	);
}
