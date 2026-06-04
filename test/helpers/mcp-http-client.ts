// SPDX-License-Identifier: BUSL-1.1
/**
 * Minimal MCP HTTP client used by the discovery report runner when
 * `BV_MCP_ENDPOINT` is set. Lets the runner exercise the *deployed* worker
 * (with its service bindings — BV_CERTSTREAM, BV_WHOIS, BV_BROWSER_RENDERER)
 * instead of the local Node-runtime function calls.
 *
 * Streamable HTTP transport per MCP 2025-06-18: one POST to initialize,
 * one to `notifications/initialized`, then per-tool `tools/call` POSTs.
 * Session ID is captured from the initialize response and reused across calls.
 */

interface JsonRpcResponse<T = unknown> {
	jsonrpc: '2.0';
	id: number | string | null;
	result?: T;
	error?: { code: number; message: string; data?: unknown };
}

interface ToolCallContent {
	type: 'text';
	text: string;
}

interface ToolCallResult {
	content: ToolCallContent[];
	structuredContent?: unknown;
	isError?: boolean;
}

interface CheckResultLike {
	category: string;
	passed: boolean;
	score: number;
	findings: Array<{
		category: string;
		title: string;
		severity: string;
		detail: string;
		metadata?: Record<string, unknown>;
	}>;
}

const STRUCTURED_RE = /<!-- STRUCTURED_RESULT\n([\s\S]*?)\nSTRUCTURED_RESULT -->/;

export class McpHttpClient {
	private sessionId: string | undefined;
	private nextId = 1;
	private readonly endpoint: string;
	private readonly token: string | undefined;
	private readonly userAgent: string;

	constructor(endpoint: string, token?: string, userAgent = 'bv-discovery-runner/1.0') {
		this.endpoint = endpoint;
		this.token = token || undefined;
		this.userAgent = userAgent;
	}

	private headers(): Record<string, string> {
		const h: Record<string, string> = {
			'Content-Type': 'application/json',
			Accept: 'application/json, text/event-stream',
			'MCP-Protocol-Version': '2025-06-18',
			'User-Agent': this.userAgent,
		};
		if (this.sessionId) h['Mcp-Session-Id'] = this.sessionId;
		if (this.token) h['Authorization'] = `Bearer ${this.token}`;
		return h;
	}

	async initialize(): Promise<void> {
		const id = this.nextId++;
		const body = {
			jsonrpc: '2.0',
			id,
			method: 'initialize',
			params: {
				protocolVersion: '2025-06-18',
				capabilities: {},
				clientInfo: { name: 'bv-discovery-runner', version: '1.0' },
			},
		};
		const resp = await fetch(this.endpoint, {
			method: 'POST',
			headers: this.headers(),
			body: JSON.stringify(body),
		});
		if (!resp.ok) {
			throw new Error(`initialize failed: HTTP ${resp.status} ${await resp.text()}`);
		}
		this.sessionId = resp.headers.get('mcp-session-id') ?? undefined;
		if (!this.sessionId) throw new Error('initialize response missing Mcp-Session-Id');
		await resp.text();

		await fetch(this.endpoint, {
			method: 'POST',
			headers: this.headers(),
			body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
		});
	}

	/**
	 * Call a tool and return the parsed structured result from the
	 * `<!-- STRUCTURED_RESULT ... -->` comment the worker embeds when
	 * `format: 'full'`. Throws if no structured payload is present.
	 *
	 * Retries on the worker's per-tool wall-budget timeout (28s). The worker
	 * caches partial work, so a retry warms up faster than the cold call.
	 */
	async callToolStructured<T = CheckResultLike>(name: string, args: Record<string, unknown>, maxAttempts = 4): Promise<T> {
		if (!this.sessionId) throw new Error('Client not initialized — call initialize() first');

		let lastTimeoutError = '';
		for (let attempt = 1; attempt <= maxAttempts; attempt++) {
			const id = this.nextId++;
			const body = {
				jsonrpc: '2.0',
				id,
				method: 'tools/call',
				params: { name, arguments: { format: 'full', ...args } },
			};
			const resp = await fetch(this.endpoint, {
				method: 'POST',
				headers: this.headers(),
				body: JSON.stringify(body),
			});
			const text = await resp.text();
			if (!resp.ok) throw new Error(`tools/call ${name} failed: HTTP ${resp.status} ${text.slice(0, 200)}`);

			const dataLine = text
				.split('\n')
				.map((l) => l.trim())
				.find((l) => l.startsWith('data: '));
			const payloadText = dataLine ? dataLine.slice(6) : text;
			const payload = JSON.parse(payloadText) as JsonRpcResponse<ToolCallResult>;
			if (payload.error) throw new Error(`tools/call ${name} JSON-RPC error: ${payload.error.message}`);
			if (!payload.result) throw new Error(`tools/call ${name} missing result`);

			// Prefer the MCP-standard structuredContent channel. The worker drops the redundant
			// `<!-- STRUCTURED_RESULT -->` comment for structuredContent-capable clients (this client
			// sends MCP-Protocol-Version: 2025-06-18), so the comment regex is now only a fallback.
			if (payload.result.structuredContent !== undefined) return payload.result.structuredContent as T;
			for (const content of payload.result.content) {
				const m = STRUCTURED_RE.exec(content.text);
				if (m) return JSON.parse(m[1]) as T;
			}

			const errText = payload.result.content.map((c) => c.text).join(' ');
			const isTimeout = payload.result.isError === true && /timed out after \d+s/i.test(errText);
			if (!isTimeout) {
				throw new Error(`tools/call ${name} response had no STRUCTURED_RESULT block: ${errText.slice(0, 200)}`);
			}
			lastTimeoutError = errText;
			if (attempt < maxAttempts) {
				console.log(`  retry ${attempt}/${maxAttempts - 1} for ${name} (server cached partials): ${errText.slice(0, 100)}`);
				await new Promise((r) => setTimeout(r, 500));
			}
		}
		throw new Error(`tools/call ${name} kept timing out after ${maxAttempts} attempts: ${lastTimeoutError.slice(0, 200)}`);
	}

	/**
	 * Call a tool and return the concatenated text of all content entries.
	 * Used for tools (like `brand_audit_batch_start`) whose markdown response
	 * carries machine-readable identifiers inline (e.g., `auditId=...`).
	 */
	async callToolText(name: string, args: Record<string, unknown>): Promise<string> {
		if (!this.sessionId) throw new Error('Client not initialized — call initialize() first');
		const id = this.nextId++;
		const body = {
			jsonrpc: '2.0',
			id,
			method: 'tools/call',
			params: { name, arguments: args },
		};
		const resp = await fetch(this.endpoint, {
			method: 'POST',
			headers: this.headers(),
			body: JSON.stringify(body),
		});
		const text = await resp.text();
		if (!resp.ok) throw new Error(`tools/call ${name} failed: HTTP ${resp.status} ${text.slice(0, 200)}`);

		const dataLine = text
			.split('\n')
			.map((l) => l.trim())
			.find((l) => l.startsWith('data: '));
		const payloadText = dataLine ? dataLine.slice(6) : text;
		const payload = JSON.parse(payloadText) as JsonRpcResponse<ToolCallResult>;
		if (payload.error) throw new Error(`tools/call ${name} JSON-RPC error: ${payload.error.message}`);
		if (!payload.result) throw new Error(`tools/call ${name} missing result`);
		const combined = payload.result.content.map((c) => c.text).join('\n');
		if (payload.result.isError === true) {
			throw new Error(`tools/call ${name} returned isError: ${combined.slice(0, 300)}`);
		}
		return combined;
	}
}

/** Shape returned by `discover_brand_domains` — only the fields the runner reads. */
export interface BrandDiscoveryResult extends CheckResultLike {
	findings: Array<{
		category: string;
		title: string;
		severity: string;
		detail: string;
		metadata?: {
			candidate?: string;
			combinedConfidence?: number;
			signals?: string[];
			registrar?: string;
			[k: string]: unknown;
		};
	}>;
}

/** Shape returned by `rdap_lookup` — only the fields the runner reads. */
export interface RdapResult extends CheckResultLike {
	findings: Array<{
		category: string;
		title: string;
		severity: string;
		detail: string;
		metadata?: { registrar?: string | null; registrarSource?: string | null; registrant?: string | null; [k: string]: unknown };
	}>;
}

/** Finding shape inside the embedded brand_audit_single result. */
export interface BrandAuditCandidateFinding {
	category: string;
	title: string;
	severity: string;
	detail: string;
	metadata?: {
		summary?: boolean;
		candidate?: string;
		bucket?: 'consolidated' | 'shadowIt' | 'indeterminate' | 'impersonation';
		signals?: string[];
		combinedConfidence?: number;
		registrar?: string;
		registrarSource?: string;
		registrant?: string | null;
		targetRegistrar?: string;
		targetRegistrarSource?: string;
		[k: string]: unknown;
	};
}

/** Shape of `brand_audit_get_report` STRUCTURED_RESULT payload. */
export interface BrandAuditReportEnvelope extends CheckResultLike {
	findings: Array<{
		metadata?: {
			summary?: boolean;
			auditId?: string;
			target?: string;
			status?: 'queued' | 'running' | 'completed' | 'failed';
			error?: string | null;
			pdfUrl?: string | null;
			result?: {
				category: string;
				passed: boolean;
				score: number;
				findings: BrandAuditCandidateFinding[];
			};
		};
	}>;
}

/** Shape of `brand_audit_status` STRUCTURED_RESULT payload. */
export interface BrandAuditStatusResult extends CheckResultLike {
	findings: Array<{
		metadata?: {
			summary?: boolean;
			auditId?: string;
			status?: 'queued' | 'running' | 'completed' | 'failed';
			progress?: string;
			completed?: number;
			total?: number;
			targets?: Array<{ target: string; status: 'queued' | 'running' | 'completed' | 'failed'; error?: string | null }>;
		};
	}>;
}
