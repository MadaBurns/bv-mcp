import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src';

describe('DNS Security MCP Server', () => {
	describe('GET /health', () => {
		it('returns status ok (unit style)', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/health');
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = await response.json() as { status: string; service: string };
			expect(body.status).toBe('ok');
			expect(body.service).toBe('bv-dns-security-mcp');
		});

		it('returns status ok (integration style)', async () => {
			const response = await SELF.fetch('http://example.com/health');
			expect(response.status).toBe(200);
			const body = await response.json() as { status: string; service: string };
			expect(body.status).toBe('ok');
			expect(body.service).toBe('bv-dns-security-mcp');
		});
	});

	describe('POST /mcp - initialize', () => {
		it('returns server info and capabilities', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = await response.json() as { jsonrpc: string; id: number; result: { serverInfo: { name: string } } };
			expect(body.jsonrpc).toBe('2.0');
			expect(body.id).toBe(1);
			expect(body.result.serverInfo.name).toBe('bv-dns-security-mcp');
		});
	});

	describe('POST /mcp - tools/list', () => {
		it('returns all 10 tools', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = await response.json() as { result: { tools: Array<{ name: string }> } };
			expect(body.result.tools).toHaveLength(10);
			const toolNames = body.result.tools.map((t) => t.name);
			expect(toolNames).toContain('check_spf');
			expect(toolNames).toContain('check_dmarc');
			expect(toolNames).toContain('scan_domain');
			expect(toolNames).toContain('explain_finding');
		});
	});

	describe('POST /mcp - resources/list', () => {
		it('returns resource list', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'resources/list', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = await response.json() as { result: { resources: Array<{ uri: string }> } };
			expect(body.result.resources.length).toBeGreaterThan(0);
		});
	});

	describe('POST /mcp - invalid requests', () => {
		it('rejects invalid JSON', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: 'not json',
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			const body = await response.json() as { error: { code: number } };
			expect(body.error.code).toBe(-32700);
		});

		it('rejects invalid JSON-RPC', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ method: 'test' }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			const body = await response.json() as { error: { code: number } };
			expect(body.error.code).toBe(-32600);
		});

		it('returns method not found for unknown methods', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'unknown/method', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = await response.json() as { error: { code: number } };
			expect(body.error.code).toBe(-32601);
		});
	});

	describe('POST /mcp - tools/call domain validation', () => {
		it('rejects localhost domains', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					jsonrpc: '2.0', id: 5, method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'localhost' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = await response.json() as { result: { content: Array<{ text: string }>; isError: boolean } };
			expect(body.result.isError).toBe(true);
			expect(body.result.content[0].text).toContain('Error');
		});

		it('rejects .local domains', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					jsonrpc: '2.0', id: 6, method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'test.local' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = await response.json() as { result: { content: Array<{ text: string }>; isError: boolean } };
			expect(body.result.isError).toBe(true);
		});
	});

	describe('POST /mcp - explain_finding', () => {
		it('returns explanation for known finding', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					jsonrpc: '2.0', id: 7, method: 'tools/call',
					params: { name: 'explain_finding', arguments: { checkType: 'SPF', status: 'fail' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = await response.json() as { result: { content: Array<{ text: string }> } };
			expect(body.result.content[0].text).toContain('SPF');
			expect(body.result.content[0].text).toContain('Recommendation');
		});
	});

	describe('404 fallback', () => {
		it('returns 404 for unknown routes', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/unknown');
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(404);
		});
	});
});
