#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

import { parseJsonRpcRequest } from './mcp/request';
import { executeMcpRequest } from './mcp/execute';
import { JSON_RPC_ERRORS, jsonRpcError } from './lib/json-rpc';
import { SERVER_VERSION } from './lib/server-version';
import type { JsonRpcRequest } from './lib/json-rpc';

declare const process: {
	argv: string[];
	stdin: {
		setEncoding(encoding: string): void;
		resume(): void;
		on(event: 'data', listener: (chunk: string) => void): void;
		on(event: 'end', listener: () => void): void;
	};
	stdout: {
		write(chunk: string): boolean;
	};
	stderr: {
		write(chunk: string): boolean;
	};
	exitCode?: number;
};

type JsonRpcResponsePayload = ReturnType<typeof jsonRpcError> | ReturnType<typeof import('./lib/json-rpc').jsonRpcSuccess>;

export interface StdioServerState {
	initialized: boolean;
}

export interface StdioServer {
	readonly state: StdioServerState;
	handleMessage(rawMessage: string): Promise<string[]>;
}

function buildNotInitializedError(id: string | number | null | undefined): ReturnType<typeof jsonRpcError> {
	return jsonRpcError(id, JSON_RPC_ERRORS.INVALID_REQUEST, 'Server not initialized');
}

function buildInvalidBatchInitializeError(id: string | number | null | undefined): ReturnType<typeof jsonRpcError> {
	return jsonRpcError(id, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC batch request: initialize cannot be batched with other messages');
}

async function processRequest(
	request: JsonRpcRequest,
	state: StdioServerState,
	batchSize: number,
): Promise<JsonRpcResponsePayload | undefined> {
	const { id, method } = request;
	if (batchSize > 1 && method === 'initialize') {
		return buildInvalidBatchInitializeError(id);
	}

	const isNotification = id === undefined || id === null;
	if (method !== 'initialize' && !state.initialized) {
		return isNotification ? undefined : buildNotInitializedError(id);
	}

	if (isNotification) {
		if (method === 'notifications/initialized') {
			state.initialized = true;
		}
		return undefined;
	}

	const result = await executeMcpRequest({
		body: request,
		allowStreaming: false,
		batchMode: batchSize > 1,
		batchSize,
		responseTransport: 'json',
		startTime: Date.now(),
		ip: 'stdio',
		isAuthenticated: true,
		validateSession: false,
		createSessionOnInitialize: false,
		serverVersion: SERVER_VERSION,
	});
	if (result.kind === 'notification') {
		return undefined;
	}

	if (method === 'initialize') {
		state.initialized = true;
	}

	return result.payload as JsonRpcResponsePayload;
}

async function processUnknownRequest(
	entry: unknown,
	state: StdioServerState,
	batchSize: number,
): Promise<JsonRpcResponsePayload | undefined> {
	if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
		return jsonRpcError(null, JSON_RPC_ERRORS.INVALID_REQUEST, 'Invalid JSON-RPC 2.0 request');
	}

	return processRequest(entry as JsonRpcRequest, state, batchSize);
}

export function createStdioServer(): StdioServer {
	const state: StdioServerState = { initialized: false };

	return {
		state,
		async handleMessage(rawMessage: string): Promise<string[]> {
			const trimmed = rawMessage.trim();
			if (!trimmed) return [];

			const parsed = parseJsonRpcRequest(trimmed);
			if (!parsed.ok) {
				return [JSON.stringify(parsed.payload)];
			}

			if (parsed.isBatch) {
				const entries = parsed.body as unknown[];
				const payloads = await Promise.all(
					entries.map((entry) => processUnknownRequest(entry, state, entries.length)),
				);
				const responses = payloads.filter((payload): payload is JsonRpcResponsePayload => payload !== undefined);
				return responses.length > 0 ? [JSON.stringify(responses)] : [];
			}

			const payload = await processUnknownRequest(parsed.body, state, 1);
			return payload ? [JSON.stringify(payload)] : [];
		},
	};
}

export async function runStdioServer(): Promise<void> {
	const server = createStdioServer();
	let buffer = '';
	let pending = Promise.resolve();

	const flushLine = (line: string): void => {
		pending = pending
			.then(async () => {
				const outputs = await server.handleMessage(line);
				for (const output of outputs) {
					process.stdout.write(`${output}\n`);
				}
			})
			.catch((error: unknown) => {
				const message = error instanceof Error ? error.message : 'Unknown stdio server error';
				process.stderr.write(`[blackveil-dns-mcp] ${message}\n`);
				process.exitCode = 1;
			});
	};

	process.stdin.setEncoding('utf8');
	process.stdin.on('data', (chunk: string) => {
		buffer += chunk;
		const lines = buffer.split(/\r?\n/);
		buffer = lines.pop() ?? '';
		for (const line of lines) {
			flushLine(line);
		}
	});

	process.stdin.on('end', () => {
		if (buffer.trim().length > 0) {
			flushLine(buffer);
			buffer = '';
		}
	});

	process.stdin.resume();
	await pending;
}

const directRunCandidate = process.argv[1] ?? '';
const isDirectRun = typeof directRunCandidate === 'string' && import.meta.url === new URL(directRunCandidate, 'file:').href;

if (isDirectRun) {
	void runStdioServer();
}