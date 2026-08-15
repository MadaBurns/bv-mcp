// SPDX-License-Identifier: BUSL-1.1

import { jsonRpcError, JSON_RPC_ERRORS } from '../lib/json-rpc';

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
		const text = await response.text();
		const dataLine = text.split('\n').find((line) => line.startsWith('data: '));
		if (!dataLine) return jsonRpcError(null, JSON_RPC_ERRORS.INTERNAL_ERROR, 'Internal server error');
		return JSON.parse(dataLine.slice('data: '.length)) as ReturnType<typeof jsonRpcError>;
	}
	return (await response.json()) as ReturnType<typeof jsonRpcError>;
}
