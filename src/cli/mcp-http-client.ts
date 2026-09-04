// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';

export const DEFAULT_MCP_ENDPOINT = 'https://dns-mcp.blackveilsecurity.com/mcp';
const MCP_PROTOCOL_VERSION = '2025-06-18';

const JsonRpcEnvelopeSchema = z
	.object({
		jsonrpc: z.literal('2.0'),
		result: z.unknown().optional(),
		error: z
			.object({
				code: z.number().int(),
				message: z.string(),
			})
			.passthrough()
			.optional(),
	})
	.passthrough();

const ServerInfoSchema = z.object({ name: z.string().min(1), version: z.string().min(1) }).passthrough();

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

function parseSsePayload(text: string): unknown {
	for (const event of text.split(/\r?\n\r?\n/)) {
		const data = event
			.split(/\r?\n/)
			.filter((line) => line.startsWith('data:'))
			.map((line) => line.slice(5).trimStart())
			.join('\n');
		if (!data || data === '[DONE]') continue;
		try {
			return JSON.parse(data);
		} catch {
			continue;
		}
	}
	throw new McpClientError('MCP response contained no valid SSE data event', 'protocol');
}

export function parseMcpResponseBody(text: string): unknown {
	const trimmed = text.trim();
	if (!trimmed) return undefined;
	try {
		return JSON.parse(trimmed);
	} catch {
		return parseSsePayload(trimmed);
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
	signalFactory?: () => AbortSignal;
}

export class McpHttpClient {
	readonly endpoint: string;
	readonly endpointOrigin: string;
	serverInfo?: { name: string; version: string };
	private readonly fetchFn: typeof fetch;
	private readonly apiKey?: string;
	private readonly signalFactory: () => AbortSignal;
	private sessionId?: string;
	private requestId = 1;

	constructor(options: McpHttpClientOptions = {}) {
		const endpoint = validateEndpoint(options.endpoint ?? DEFAULT_MCP_ENDPOINT);
		this.endpoint = endpoint.toString();
		this.endpointOrigin = endpoint.origin;
		this.fetchFn = options.fetchFn ?? fetch;
		this.apiKey = options.apiKey;
		this.signalFactory = options.signalFactory ?? (() => AbortSignal.timeout(45_000));
	}

	private headers(includeSession: boolean): Headers {
		const headers = new Headers({
			accept: 'application/json, text/event-stream',
			'content-type': 'application/json',
		});
		if (includeSession) headers.set('mcp-protocol-version', MCP_PROTOCOL_VERSION);
		if (includeSession && this.sessionId) headers.set('mcp-session-id', this.sessionId);
		if (this.apiKey) headers.set('authorization', `Bearer ${this.apiKey}`);
		return headers;
	}

	private async request(body: Record<string, unknown>, includeSession: boolean, expectPayload: boolean) {
		let response: Response;
		try {
			response = await this.fetchFn(this.endpoint, {
				method: 'POST',
				headers: this.headers(includeSession),
				body: JSON.stringify(body),
				signal: this.signalFactory(),
			});
		} catch (error) {
			const message = error instanceof Error ? error.message : 'request failed';
			throw new McpClientError(`MCP transport failed: ${message}`, 'transport');
		}

		const text = await response.text();
		let parsed: unknown;
		try {
			parsed = parseMcpResponseBody(text);
		} catch (error) {
			if (!response.ok) throw new McpClientError(`MCP returned HTTP ${response.status}`, 'remote', response.status);
			throw error;
		}

		if (!response.ok) {
			const envelope = JsonRpcEnvelopeSchema.safeParse(parsed);
			const remote = envelope.success ? envelope.data.error : undefined;
			throw new McpClientError(
				remote ? `MCP error ${remote.code}: ${remote.message}` : `MCP returned HTTP ${response.status}`,
				'remote',
				response.status,
				remote?.code,
			);
		}
		if (!expectPayload) return { result: undefined, headers: response.headers };

		const envelope = JsonRpcEnvelopeSchema.safeParse(parsed);
		if (!envelope.success) throw new McpClientError('MCP returned a malformed JSON-RPC response', 'protocol', response.status);
		if (envelope.data.error) {
			throw new McpClientError(
				`MCP error ${envelope.data.error.code}: ${envelope.data.error.message}`,
				'remote',
				response.status,
				envelope.data.error.code,
			);
		}
		return { result: envelope.data.result, headers: response.headers };
	}

	async connect(): Promise<{ name: string; version: string }> {
		const initialized = await this.request(
			{
				jsonrpc: '2.0',
				id: this.requestId++,
				method: 'initialize',
				params: {
					protocolVersion: MCP_PROTOCOL_VERSION,
					capabilities: {},
					clientInfo: { name: 'blackveil-cli', version: '1.0.0' },
				},
			},
			false,
			true,
		);
		const sessionId = initialized.headers.get('mcp-session-id');
		if (!sessionId) throw new McpClientError('MCP initialize omitted Mcp-Session-Id', 'protocol');
		this.sessionId = sessionId;
		const result = z.object({ serverInfo: ServerInfoSchema }).passthrough().safeParse(initialized.result);
		if (!result.success) throw new McpClientError('MCP initialize omitted valid serverInfo', 'protocol');
		this.serverInfo = result.data.serverInfo;

		await this.request({ jsonrpc: '2.0', method: 'notifications/initialized' }, true, false);
		return this.serverInfo;
	}

	private requireConnected(): void {
		if (!this.sessionId || !this.serverInfo) throw new McpClientError('MCP client is not initialized', 'protocol');
	}

	async listTools(): Promise<ListedTool[]> {
		this.requireConnected();
		const response = await this.request({ jsonrpc: '2.0', id: this.requestId++, method: 'tools/list', params: {} }, true, true);
		const parsed = ToolListSchema.safeParse(response.result);
		if (!parsed.success) throw new McpClientError('MCP tools/list returned a malformed tool list', 'protocol');
		return parsed.data.tools;
	}

	async callTool(name: string, args: Record<string, unknown>): Promise<ToolCallResult> {
		this.requireConnected();
		const response = await this.request(
			{
				jsonrpc: '2.0',
				id: this.requestId++,
				method: 'tools/call',
				params: { name, arguments: args },
			},
			true,
			true,
		);
		const parsed = ToolCallResultSchema.safeParse(response.result);
		if (!parsed.success) throw new McpClientError(`MCP tool ${name} returned a malformed result`, 'protocol');
		return parsed.data;
	}
}
