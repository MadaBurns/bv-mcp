import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import worker from '../src';
import {
	negotiateProtocolVersion,
	classifyProtocolVersionHeader,
	clientSupportsStructuredContent,
	stripRedundantStructuredComment,
	STRUCTURED_COMMENT_LEGACY_CLIENTS,
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

describe('clientSupportsStructuredContent (#363 follow-up — drop redundant comment)', () => {
	it('returns true only for a known protocol version >= 2025-06-18', () => {
		expect(clientSupportsStructuredContent('2025-06-18')).toBe(true);
		expect(clientSupportsStructuredContent(' 2025-06-18 ')).toBe(true);
	});

	it('returns false for the older-but-supported 2025-03-26 (predates structuredContent)', () => {
		expect(clientSupportsStructuredContent('2025-03-26')).toBe(false);
	});

	it('returns false (conservative) for absent / empty / unknown / future headers', () => {
		expect(clientSupportsStructuredContent(undefined)).toBe(false);
		expect(clientSupportsStructuredContent(null)).toBe(false);
		expect(clientSupportsStructuredContent('')).toBe(false);
		expect(clientSupportsStructuredContent('2024-11-05')).toBe(false);
		expect(clientSupportsStructuredContent('2099-01-01')).toBe(false);
		expect(clientSupportsStructuredContent('garbage')).toBe(false);
	});
});

describe('stripRedundantStructuredComment (#363 follow-up — "Both (conservative)" gate)', () => {
	const COMMENT = '<!-- STRUCTURED_RESULT\n{"score":80}\nSTRUCTURED_RESULT -->';
	const make = () => ({
		content: [
			{ type: 'text', text: '## Report\nOverall Score: 80/100 (B)' },
			{ type: 'text', text: COMMENT },
		],
		structuredContent: { score: 80 },
	});

	const hasComment = (r: { content?: Array<{ text: string }> }) => (r.content ?? []).some((c) => c.text.includes('STRUCTURED_RESULT'));

	it('drops the comment for a modern-protocol, non-legacy client (structuredContent stays)', () => {
		const out = stripRedundantStructuredComment(make(), { clientType: 'unknown', protocolVersionHeader: '2025-06-18' });
		expect(hasComment(out)).toBe(false);
		expect(out.content).toHaveLength(1);
		expect(out.content[0].text).toContain('Overall Score');
		expect(out.structuredContent).toEqual({ score: 80 });
	});

	it('KEEPS the comment for the legacy comment-parsing client even on modern protocol', () => {
		const out = stripRedundantStructuredComment(make(), { clientType: 'blackveil_dns_action', protocolVersionHeader: '2025-06-18' });
		expect(hasComment(out)).toBe(true);
		expect(STRUCTURED_COMMENT_LEGACY_CLIENTS.has('blackveil_dns_action')).toBe(true);
	});

	it('KEEPS the comment when the protocol header is absent (most clients omit it)', () => {
		expect(hasComment(stripRedundantStructuredComment(make(), { clientType: 'unknown', protocolVersionHeader: undefined }))).toBe(true);
	});

	it('DROPS the comment for bv_claude_dns_proxy regardless of protocol header (verified-safe positive drop)', () => {
		const out = stripRedundantStructuredComment(make(), { clientType: 'bv_claude_dns_proxy', protocolVersionHeader: undefined });
		expect(hasComment(out)).toBe(false);
		expect(out.structuredContent).toEqual({ score: 80 });
	});

	it('KEEPS the comment when the negotiated protocol predates structuredContent (2025-03-26)', () => {
		expect(hasComment(stripRedundantStructuredComment(make(), { clientType: 'unknown', protocolVersionHeader: '2025-03-26' }))).toBe(true);
	});

	it('does nothing (zero data loss) when there is no structuredContent to fall back to', () => {
		const noSc = { content: [{ type: 'text', text: COMMENT }] };
		const out = stripRedundantStructuredComment(noSc, { clientType: 'unknown', protocolVersionHeader: '2025-06-18' });
		expect(hasComment(out)).toBe(true);
		expect(out).toBe(noSc);
	});

	it('returns the same object reference when nothing is stripped (no needless clone)', () => {
		const r = make();
		expect(stripRedundantStructuredComment(r, { clientType: 'unknown', protocolVersionHeader: undefined })).toBe(r);
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

describe('redundant STRUCTURED_RESULT comment stripping (#363 follow-up, end-to-end)', () => {
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
		return response.headers.get('mcp-session-id')!;
	}

	// explain_finding needs no network and returns structuredContent, so it emits the comment in `full` format.
	async function explainFinding(sessionId: string, opts: { protocolHeader?: string; userAgent?: string }): Promise<{ hasComment: boolean; hasStructured: boolean }> {
		const headers: Record<string, string> = { 'Content-Type': 'application/json', Accept: 'application/json', 'Mcp-Session-Id': sessionId };
		if (opts.protocolHeader !== undefined) headers['MCP-Protocol-Version'] = opts.protocolHeader;
		if (opts.userAgent !== undefined) headers['User-Agent'] = opts.userAgent;
		const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers,
			body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'explain_finding', arguments: { checkType: 'SPF', status: 'high' } } }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
		const body = (await response.json()) as { result: { content: Array<{ text: string }>; structuredContent?: unknown } };
		return {
			hasComment: body.result.content.some((c) => c.text.includes('STRUCTURED_RESULT')),
			hasStructured: body.result.structuredContent !== undefined,
		};
	}

	it('drops the comment for a generic client on protocol 2025-06-18, keeping structuredContent', async () => {
		const out = await explainFinding(await initSession(), { protocolHeader: '2025-06-18' });
		expect(out.hasComment).toBe(false);
		expect(out.hasStructured).toBe(true);
	});

	it('keeps the comment when no MCP-Protocol-Version header is sent', async () => {
		const out = await explainFinding(await initSession(), { protocolHeader: undefined });
		expect(out.hasComment).toBe(true);
		expect(out.hasStructured).toBe(true);
	});

	it('keeps the comment for the blackveil_dns_action client even on protocol 2025-06-18', async () => {
		const out = await explainFinding(await initSession(), { protocolHeader: '2025-06-18', userAgent: 'blackveil-dns-action/1.0' });
		expect(out.hasComment).toBe(true);
	});

	it('drops the comment for the bv_claude_dns_proxy client even with no protocol header (verified-safe)', async () => {
		const out = await explainFinding(await initSession(), { protocolHeader: undefined, userAgent: 'bv-claude-dns-proxy/1.0' });
		expect(out.hasComment).toBe(false);
		expect(out.hasStructured).toBe(true);
	});

	it('keeps the comment for the older 2025-03-26 protocol (predates structuredContent)', async () => {
		const out = await explainFinding(await initSession(), { protocolHeader: '2025-03-26' });
		expect(out.hasComment).toBe(true);
	});
});
