import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import worker from '../src';
import {
	negotiateProtocolVersion,
	classifyProtocolVersionHeader,
	SUPPORTED_PROTOCOL_VERSIONS,
	LATEST_PROTOCOL_VERSION,
} from '../src/mcp/dispatch';
import { resetAllRateLimits, resetAllRateLimitsKv } from '../src/lib/rate-limiter';
import { resetLegacySseState } from '../src/lib/legacy-sse';
import { resetSessions } from '../src/lib/session';
import { resetQuotaCoordinatorState } from '../src/lib/quota-coordinator';

describe('negotiateProtocolVersion', () => {
	it('exposes the supported versions newest-first with the latest matching the head', () => {
		expect(SUPPORTED_PROTOCOL_VERSIONS).toEqual(['2025-06-18', '2025-03-26']);
		expect(LATEST_PROTOCOL_VERSION).toBe('2025-06-18');
		expect(SUPPORTED_PROTOCOL_VERSIONS[0]).toBe(LATEST_PROTOCOL_VERSION);
	});

	it('echoes a supported requested version', () => {
		expect(negotiateProtocolVersion('2025-06-18')).toBe('2025-06-18');
		expect(negotiateProtocolVersion('2025-03-26')).toBe('2025-03-26');
	});

	it('falls back to the latest version for an unsupported but well-formed version', () => {
		expect(negotiateProtocolVersion('2024-11-05')).toBe('2025-06-18');
	});

	it('falls back to the latest version when the field is omitted', () => {
		expect(negotiateProtocolVersion(undefined)).toBe('2025-06-18');
	});

	it('falls back to the latest version for non-string / garbage input', () => {
		expect(negotiateProtocolVersion(42 as unknown)).toBe('2025-06-18');
		expect(negotiateProtocolVersion(null)).toBe('2025-06-18');
		expect(negotiateProtocolVersion({})).toBe('2025-06-18');
		expect(negotiateProtocolVersion([])).toBe('2025-06-18');
		expect(negotiateProtocolVersion('')).toBe('2025-06-18');
	});
});

describe('classifyProtocolVersionHeader (#363 item 4 — observe-only, never rejects)', () => {
	it('classifies a supported header value', () => {
		expect(classifyProtocolVersionHeader('2025-06-18')).toBe('supported');
		expect(classifyProtocolVersionHeader('2025-03-26')).toBe('supported');
	});

	it('treats a missing / empty / whitespace header as absent (most clients omit it)', () => {
		expect(classifyProtocolVersionHeader(undefined)).toBe('absent');
		expect(classifyProtocolVersionHeader(null)).toBe('absent');
		expect(classifyProtocolVersionHeader('')).toBe('absent');
		expect(classifyProtocolVersionHeader('   ')).toBe('absent');
	});

	it('classifies an unknown / lagging / future version as unsupported (observed, not rejected)', () => {
		expect(classifyProtocolVersionHeader('2024-11-05')).toBe('unsupported');
		expect(classifyProtocolVersionHeader('2099-01-01')).toBe('unsupported');
		expect(classifyProtocolVersionHeader('garbage')).toBe('unsupported');
	});

	it('tolerates surrounding whitespace on an otherwise-supported value', () => {
		expect(classifyProtocolVersionHeader(' 2025-06-18 ')).toBe('supported');
	});
});

describe('initialize protocolVersion negotiation (integration)', () => {
	beforeEach(async () => {
		resetAllRateLimits();
		resetSessions();
		resetLegacySseState();
		await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
		await resetAllRateLimitsKv(env.RATE_LIMIT);
	});

	async function initialize(params: Record<string, unknown>): Promise<string> {
		const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
		const body = (await response.json()) as { result: { protocolVersion: string } };
		return body.result.protocolVersion;
	}

	it('echoes 2025-03-26 when the client requests it', async () => {
		expect(await initialize({ protocolVersion: '2025-03-26' })).toBe('2025-03-26');
	});

	it('echoes 2025-06-18 when the client requests it', async () => {
		expect(await initialize({ protocolVersion: '2025-06-18' })).toBe('2025-06-18');
	});

	it('returns the latest version when the client omits protocolVersion', async () => {
		expect(await initialize({})).toBe('2025-06-18');
	});

	it('returns the latest version when the client requests an unsupported version', async () => {
		expect(await initialize({ protocolVersion: '2024-11-05' })).toBe('2025-06-18');
	});
});

describe('MCP-Protocol-Version request header (#363 item 4 — never rejects)', () => {
	beforeEach(async () => {
		resetAllRateLimits();
		resetSessions();
		resetLegacySseState();
		await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
		await resetAllRateLimitsKv(env.RATE_LIMIT);
	});

	async function initSession(): Promise<string> {
		const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		const sessionId = response.headers.get('mcp-session-id');
		expect(sessionId).toBeTruthy();
		return sessionId!;
	}

	async function toolsList(sessionId: string, protocolHeader?: string): Promise<number> {
		const headers: Record<string, string> = { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId };
		if (protocolHeader !== undefined) headers['MCP-Protocol-Version'] = protocolHeader;
		const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers,
			body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		return response.status;
	}

	it('accepts a post-init request with a supported version header', async () => {
		expect(await toolsList(await initSession(), '2025-06-18')).toBe(200);
	});

	it('accepts a post-init request with NO version header (most clients omit it)', async () => {
		expect(await toolsList(await initSession(), undefined)).toBe(200);
	});

	it('accepts (does NOT reject) a post-init request with an unsupported / future version header', async () => {
		expect(await toolsList(await initSession(), '2099-01-01')).toBe(200);
		expect(await toolsList(await initSession(), 'garbage')).toBe(200);
	});
});
