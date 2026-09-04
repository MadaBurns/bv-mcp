// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';

export const DEFAULT_MCP_ENDPOINT = 'https://dns-mcp.blackveilsecurity.com/mcp';
const REQUESTED_PROTOCOL_VERSION = '2025-06-18';
const SUPPORTED_PROTOCOL_VERSIONS = new Set(['2025-06-18', '2025-03-26']);
export const MCP_RESPONSE_BODY_MAX_BYTES = 2 * 1024 * 1024;
export const MCP_SSE_EVENT_MAX_BYTES = 512 * 1024;

const ServerInfoSchema = z.object({ name: z.string().min(1), version: z.string().min(1) }).passthrough();
const InitializeResultSchema = z.object({ protocolVersion: z.string().min(1), serverInfo: ServerInfoSchema }).passthrough();
const ToolCallResultSchema = z
	.object({
		content: z.array(z.object({ type: z.string(), text: z.string().optional() }).passthrough()),
		structuredContent: z.record(z.string(), z.unknown()).optional(),
		isError: z.boolean().optional(),
	})
	.passthrough();
const ToolListSchema = z
	.object({
		tools: z.array(
			z
				.object({
					name: z.string().min(1),
					outputSchema: z.record(z.string(), z.unknown()).optional(),
					annotations: z.object({ readOnlyHint: z.boolean().optional() }).passthrough().optional(),
				})
				.passthrough(),
		),
	})
	.passthrough();

type RequestId = string | number;
type ParsedRpcResponse = { result?: unknown; error?: { code: number; message: string } };

export type ToolCallResult = z.infer<typeof ToolCallResultSchema>;
export type ListedTool = z.infer<typeof ToolListSchema>['tools'][number];

export class McpClientError extends Error {
	constructor(
		message: string,
		readonly kind: 'transport' | 'protocol' | 'remote',
		readonly status?: number,
		readonly rpcCode?: number,
	) {
		super(message);
		this.name = 'McpClientError';
	}
}

function requestIdKey(id: RequestId): string {
	return `${typeof id}:${String(id)}`;
}

function classifyJsonRpcMessage(value: unknown, expectedId: RequestId, seenIds: Set<string>): ParsedRpcResponse | undefined {
	if (!value || typeof value !== 'object' || Array.isArray(value))
		throw new McpClientError('MCP returned a malformed JSON-RPC message', 'protocol');
	const message = value as Record<string, unknown>;
	if (message.jsonrpc !== '2.0') throw new McpClientError('MCP returned a message with an invalid jsonrpc version', 'protocol');
	if (typeof message.method === 'string') {
		if (Object.hasOwn(message, 'id')) throw new McpClientError(`MCP sent unsupported server request ${message.method}`, 'protocol');
		return undefined;
	}
	if (!Object.hasOwn(message, 'id') || message.id === null) throw new McpClientError('MCP response omitted its JSON-RPC id', 'protocol');
	if (typeof message.id !== 'string' && (typeof message.id !== 'number' || !Number.isInteger(message.id))) {
		throw new McpClientError('MCP response contained an invalid JSON-RPC id', 'protocol');
	}
	const key = requestIdKey(message.id);
	if (seenIds.has(key)) throw new McpClientError(`MCP returned duplicate JSON-RPC id ${String(message.id)}`, 'protocol');
	seenIds.add(key);
	if (message.id !== expectedId) {
		throw new McpClientError(`MCP response id ${String(message.id)} did not match request id ${String(expectedId)}`, 'protocol');
	}
	const hasResult = Object.hasOwn(message, 'result');
	const hasError = Object.hasOwn(message, 'error');
	if (hasResult === hasError) throw new McpClientError('MCP response must contain exactly one of result or error', 'protocol');
	if (hasError) {
		const parsed = z.object({ code: z.number().int(), message: z.string() }).passthrough().safeParse(message.error);
		if (!parsed.success) throw new McpClientError('MCP returned a malformed JSON-RPC error', 'protocol');
		return { error: parsed.data };
	}
	return { result: message.result };
}

function parseSseEvent(event: string): unknown | undefined {
	const data = event
		.split(/\r?\n/)
		.filter((line) => line.startsWith('data:'))
		.map((line) => line.slice(5).trimStart())
		.join('\n');
	if (!data || data === '[DONE]') return undefined;
	try {
		return JSON.parse(data);
	} catch {
		throw new McpClientError('MCP response contained invalid SSE JSON', 'protocol');
	}
}

function drainCompleteSseEvents(buffer: string): { events: string[]; remainder: string } {
	const events: string[] = [];
	let remainder = buffer;
	for (;;) {
		const separator = /\r?\n\r?\n/.exec(remainder);
		if (!separator || separator.index === undefined) return { events, remainder };
		events.push(remainder.slice(0, separator.index));
		remainder = remainder.slice(separator.index + separator[0].length);
	}
}

async function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<void> {
	try {
		await reader.cancel();
	} catch {
		// Cancellation is best-effort; preserve the response or protocol error that led here.
	} finally {
		try {
			reader.releaseLock();
		} catch {
			// A hostile or already-detached stream must not mask the request outcome.
		}
	}
}

async function discardResponseBody(response: Response): Promise<void> {
	if (!response.body) return;
	let reader: ReadableStreamDefaultReader<Uint8Array>;
	try {
		reader = response.body.getReader();
	} catch {
		return;
	}
	await cancelReader(reader);
}

async function readResponseTextCapped(response: Response): Promise<string> {
	const contentLength = Number(response.headers.get('content-length'));
	if (Number.isFinite(contentLength) && contentLength > MCP_RESPONSE_BODY_MAX_BYTES) {
		await discardResponseBody(response);
		throw new McpClientError('MCP response exceeded the response body limit', 'protocol', response.status);
	}
	if (!response.body) return '';
	const reader = response.body.getReader();
	const decoder = new TextDecoder();
	let bytesRead = 0;
	let text = '';
	let complete = false;
	try {
		for (;;) {
			const chunk = await reader.read();
			if (chunk.value) {
				bytesRead += chunk.value.byteLength;
				if (bytesRead > MCP_RESPONSE_BODY_MAX_BYTES) {
					throw new McpClientError('MCP response exceeded the response body limit', 'protocol', response.status);
				}
				text += decoder.decode(chunk.value, { stream: true });
			}
			if (chunk.done) {
				text += decoder.decode();
				complete = true;
				return text;
			}
		}
	} finally {
		if (!complete) {
			await cancelReader(reader);
		} else {
			try {
				reader.releaseLock();
			} catch {
				// A hostile or already-detached stream must not mask the request outcome.
			}
		}
	}
}

/** Parse a complete JSON or SSE payload and, when given, correlate it to one request id. */
export function parseMcpResponseBody(text: string, expectedId?: RequestId): unknown {
	const trimmed = text.trim();
	if (!trimmed) return undefined;
	try {
		const parsed = JSON.parse(trimmed);
		if (expectedId === undefined) return parsed;
		const response = classifyJsonRpcMessage(parsed, expectedId, new Set());
		if (!response) throw new McpClientError('MCP response contained notifications but no matching response', 'protocol');
		return response;
	} catch (error) {
		if (error instanceof McpClientError) throw error;
	}
	const seen = new Set<string>();
	let matched: ParsedRpcResponse | undefined;
	for (const event of text.split(/\r?\n\r?\n/)) {
		const value = parseSseEvent(event);
		if (value === undefined) continue;
		if (expectedId === undefined) return value;
		const response = classifyJsonRpcMessage(value, expectedId, seen);
		if (response) {
			if (matched) throw new McpClientError(`MCP returned duplicate JSON-RPC id ${String(expectedId)}`, 'protocol');
			matched = response;
		}
	}
	if (!matched) throw new McpClientError('MCP response contained no matching JSON-RPC response', 'protocol');
	return matched;
}

async function readMatchingSseResponse(response: Response, expectedId: RequestId): Promise<ParsedRpcResponse> {
	if (!response.body) throw new McpClientError('MCP SSE response omitted its body', 'protocol', response.status);
	const reader = response.body.getReader();
	const decoder = new TextDecoder();
	const seen = new Set<string>();
	let buffer = '';
	let bytesRead = 0;
	try {
		for (;;) {
			const chunk = await reader.read();
			if (chunk.value) {
				bytesRead += chunk.value.byteLength;
				if (bytesRead > MCP_RESPONSE_BODY_MAX_BYTES) {
					throw new McpClientError('MCP SSE response exceeded the response body limit', 'protocol', response.status);
				}
			}
			buffer += decoder.decode(chunk.value, { stream: !chunk.done });
			const drained = drainCompleteSseEvents(buffer);
			buffer = drained.remainder;
			if (new TextEncoder().encode(buffer).byteLength > MCP_SSE_EVENT_MAX_BYTES) {
				throw new McpClientError('MCP SSE event exceeded the event limit', 'protocol', response.status);
			}
			if (chunk.done && buffer.trim()) {
				drained.events.push(buffer);
				buffer = '';
			}
			let matched: ParsedRpcResponse | undefined;
			for (const event of drained.events) {
				if (new TextEncoder().encode(event).byteLength > MCP_SSE_EVENT_MAX_BYTES) {
					throw new McpClientError('MCP SSE event exceeded the event limit', 'protocol', response.status);
				}
				const value = parseSseEvent(event);
				if (value === undefined) continue;
				const candidate = classifyJsonRpcMessage(value, expectedId, seen);
				if (candidate) {
					if (matched) throw new McpClientError(`MCP returned duplicate JSON-RPC id ${String(expectedId)}`, 'protocol');
					matched = candidate;
				}
			}
			if (matched) return matched;
			if (chunk.done) throw new McpClientError('MCP SSE stream ended without a matching JSON-RPC response', 'protocol');
		}
	} finally {
		await cancelReader(reader);
	}
}

function validateEndpoint(endpoint: string): URL {
	let url: URL;
	try {
		url = new URL(endpoint);
	} catch {
		throw new McpClientError('Invalid BLACKVEIL_MCP_URL', 'protocol');
	}
	if (url.username || url.password || url.search || url.hash) {
		throw new McpClientError('Invalid BLACKVEIL_MCP_URL: credentials, query strings, and fragments are not allowed', 'protocol');
	}
	const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
	if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
		throw new McpClientError('Invalid BLACKVEIL_MCP_URL: HTTPS is required except on loopback', 'protocol');
	}
	return url;
}

export interface McpHttpClientOptions {
	endpoint?: string;
	apiKey?: string;
	fetchFn?: typeof fetch;
	deadlineAt?: number;
	timeoutMs?: number;
	now?: () => number;
	signalFactory?: (remainingMs: number) => AbortSignal;
}

export class McpHttpClient {
	readonly endpoint: string;
	readonly endpointOrigin: string;
	serverInfo?: { name: string; version: string };
	private readonly fetchFn: typeof fetch;
	private readonly apiKey?: string;
	private readonly signalFactory: (remainingMs: number) => AbortSignal;
	private readonly now: () => number;
	private readonly deadlineAt: number;
	private sessionId?: string;
	private protocolVersion = REQUESTED_PROTOCOL_VERSION;
	private initialized = false;
	private sessionRecoveryUsed = false;
	private requestId = 1;

	constructor(options: McpHttpClientOptions = {}) {
		const endpoint = validateEndpoint(options.endpoint ?? DEFAULT_MCP_ENDPOINT);
		this.endpoint = endpoint.toString();
		this.endpointOrigin = endpoint.origin;
		this.fetchFn = options.fetchFn ?? fetch;
		this.apiKey = options.apiKey;
		this.now = options.now ?? Date.now;
		this.deadlineAt = options.deadlineAt ?? this.now() + (options.timeoutMs ?? 45_000);
		this.signalFactory = options.signalFactory ?? ((remainingMs) => AbortSignal.timeout(Math.max(1, Math.ceil(remainingMs))));
	}

	private headers(includeSession: boolean): Headers {
		const headers = new Headers({ accept: 'application/json, text/event-stream', 'content-type': 'application/json' });
		if (includeSession) headers.set('mcp-protocol-version', this.protocolVersion);
		if (includeSession && this.sessionId) headers.set('mcp-session-id', this.sessionId);
		if (this.apiKey) headers.set('authorization', `Bearer ${this.apiKey}`);
		return headers;
	}

	private remainingSignal(): AbortSignal {
		const remainingMs = this.deadlineAt - this.now();
		if (remainingMs <= 0) throw new McpClientError('MCP command deadline exceeded', 'transport');
		return this.signalFactory(remainingMs);
	}

	private async request(body: Record<string, unknown>, includeSession: boolean, expectPayload: boolean) {
		let response: Response;
		try {
			response = await this.fetchFn(this.endpoint, {
				method: 'POST',
				headers: this.headers(includeSession),
				body: JSON.stringify(body),
				signal: this.remainingSignal(),
			});
		} catch (error) {
			if (error instanceof McpClientError) throw error;
			const message = error instanceof Error ? error.message : 'request failed';
			throw new McpClientError(`MCP transport failed: ${message}`, 'transport');
		}
		if (response.ok && !expectPayload) {
			await discardResponseBody(response);
			return { result: undefined, headers: response.headers };
		}
		const expectedId = body.id;
		if (expectPayload && typeof expectedId !== 'string' && (typeof expectedId !== 'number' || !Number.isInteger(expectedId))) {
			throw new McpClientError('MCP client request omitted a valid JSON-RPC id', 'protocol');
		}
		if (!response.ok) {
			const text = await readResponseTextCapped(response);
			let remote: ParsedRpcResponse | undefined;
			if (text.trim() && expectedId !== undefined) {
				try {
					remote = parseMcpResponseBody(text, expectedId as RequestId) as ParsedRpcResponse;
				} catch {
					remote = undefined;
				}
			}
			throw new McpClientError(
				remote?.error ? `MCP error ${remote.error.code}: ${remote.error.message}` : `MCP returned HTTP ${response.status}`,
				'remote',
				response.status,
				remote?.error?.code,
			);
		}
		const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
		const parsed = contentType.includes('text/event-stream')
			? await readMatchingSseResponse(response, expectedId as RequestId)
			: (parseMcpResponseBody(await readResponseTextCapped(response), expectedId as RequestId) as ParsedRpcResponse);
		if (!parsed) throw new McpClientError('MCP response contained no matching JSON-RPC response', 'protocol', response.status);
		if (parsed.error) {
			throw new McpClientError(`MCP error ${parsed.error.code}: ${parsed.error.message}`, 'remote', response.status, parsed.error.code);
		}
		return { result: parsed.result, headers: response.headers };
	}

	async connect(): Promise<{ name: string; version: string }> {
		this.initialized = false;
		this.sessionId = undefined;
		this.serverInfo = undefined;
		this.protocolVersion = REQUESTED_PROTOCOL_VERSION;
		const initialized = await this.request(
			{
				jsonrpc: '2.0',
				id: this.requestId++,
				method: 'initialize',
				params: {
					protocolVersion: REQUESTED_PROTOCOL_VERSION,
					capabilities: {},
					clientInfo: { name: 'blackveil-cli', version: '1.0.0' },
				},
			},
			false,
			true,
		);
		const result = InitializeResultSchema.safeParse(initialized.result);
		if (!result.success) throw new McpClientError('MCP initialize omitted valid protocolVersion or serverInfo', 'protocol');
		if (!SUPPORTED_PROTOCOL_VERSIONS.has(result.data.protocolVersion)) {
			throw new McpClientError(`MCP negotiated unsupported protocol version ${result.data.protocolVersion}`, 'protocol');
		}
		this.protocolVersion = result.data.protocolVersion;
		this.serverInfo = result.data.serverInfo;
		const sessionId = initialized.headers.get('mcp-session-id');
		if (sessionId) {
			if (!/^[\x21-\x7e]+$/.test(sessionId)) throw new McpClientError('MCP initialize returned an invalid session id', 'protocol');
			this.sessionId = sessionId;
		}
		await this.request({ jsonrpc: '2.0', method: 'notifications/initialized' }, true, false);
		this.initialized = true;
		return this.serverInfo;
	}

	private requireConnected(): void {
		if (!this.initialized || !this.serverInfo) throw new McpClientError('MCP client is not initialized', 'protocol');
	}

	private async readOnlyRequest(factory: () => ReturnType<McpHttpClient['request']>) {
		const hadSession = this.sessionId !== undefined;
		try {
			return await factory();
		} catch (error) {
			if (!(error instanceof McpClientError) || error.status !== 404 || !hadSession || this.sessionRecoveryUsed) throw error;
			this.sessionRecoveryUsed = true;
			await this.connect();
			return factory();
		}
	}

	async listTools(): Promise<ListedTool[]> {
		this.requireConnected();
		const response = await this.readOnlyRequest(() =>
			this.request({ jsonrpc: '2.0', id: this.requestId++, method: 'tools/list', params: {} }, true, true),
		);
		const parsed = ToolListSchema.safeParse(response.result);
		if (!parsed.success) throw new McpClientError('MCP tools/list returned a malformed tool list', 'protocol');
		return parsed.data.tools;
	}

	async callTool(name: string, args: Record<string, unknown>, options: { readOnly?: boolean } = {}): Promise<ToolCallResult> {
		this.requireConnected();
		const call = () =>
			this.request(
				{
					jsonrpc: '2.0',
					id: this.requestId++,
					method: 'tools/call',
					params: { name, arguments: args },
				},
				true,
				true,
			);
		const response = options.readOnly ? await this.readOnlyRequest(call) : await call();
		const parsed = ToolCallResultSchema.safeParse(response.result);
		if (!parsed.success) throw new McpClientError(`MCP tool ${name} returned a malformed result`, 'protocol');
		return parsed.data;
	}
}
