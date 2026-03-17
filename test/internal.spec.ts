import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, afterEach, vi } from 'vitest';
import worker from '../src';
import { resetAllRateLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';

afterEach(() => {
	resetAllRateLimits();
	resetSessions();
});

describe('Internal service binding routes', () => {
	describe('guard middleware', () => {
		it('returns 404 when cf-connecting-ip header is present (public internet)', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'cf-connecting-ip': '1.2.3.4',
				},
				body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(404);
		});

		it('allows requests without cf-connecting-ip header (service binding)', async () => {
			const { mockTxtRecords } = await import('./helpers/dns-mock');
			mockTxtRecords(['v=spf1 -all']);

			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
		});
	});

	describe('POST /internal/tools/call', () => {
		it('dispatches check_spf and returns raw result', async () => {
			const { mockTxtRecords } = await import('./helpers/dns-mock');
			mockTxtRecords(['v=spf1 -all']);

			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(200);
			const result = (await response.json()) as { content: { type: string; text: string }[]; isError?: boolean };
			expect(result.content).toHaveLength(1);
			expect(result.content[0].text).toContain('SPF');
			expect(result.isError).toBeUndefined();
		});

		it('returns 400 when name is missing', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ arguments: { domain: 'example.com' } }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(400);
			const result = (await response.json()) as { isError: boolean };
			expect(result.isError).toBe(true);
		});

		it('returns error result for unknown tool', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ name: 'check_nonexistent', arguments: { domain: 'example.com' } }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(200);
			const result = (await response.json()) as { isError: boolean; content: { text: string }[] };
			expect(result.isError).toBe(true);
			expect(result.content[0].text).toContain('Unknown tool');
		});

		it('returns domain validation error for invalid domain', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'not a domain!' } }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(200);
			const result = (await response.json()) as { isError: boolean };
			expect(result.isError).toBe(true);
		});

		it('skips rate limiting for service binding requests', async () => {
			const { mockTxtRecords } = await import('./helpers/dns-mock');
			mockTxtRecords(['v=spf1 -all']);

			// Make 60 requests rapidly — should never get 429
			// Service binding calls bypass all rate limiting since they
			// hit /internal/* instead of /mcp and have no cf-connecting-ip
			for (let i = 0; i < 60; i++) {
				const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
				});
				const ctx = createExecutionContext();
				const response = await worker.fetch(request, env, ctx);
				await waitOnExecutionContext(ctx);
				expect(response.status).not.toBe(429);
			}
		});

		it('returns raw CheckResult when format=structured', async () => {
			const { mockTxtRecords } = await import('./helpers/dns-mock');
			mockTxtRecords(['v=spf1 -all']);

			const request = new Request<unknown, IncomingRequestCfProperties>(
				'http://example.com/internal/tools/call?format=structured',
				{
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
				},
			);
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(200);
			const body = (await response.json()) as { result: { category: string; passed: boolean; score: number; findings: unknown[] }; isError: boolean };
			expect(body.isError).toBe(false);
			expect(body.result).toBeDefined();
			expect(body.result.category).toBe('spf');
			expect(typeof body.result.score).toBe('number');
			expect(typeof body.result.passed).toBe('boolean');
			expect(Array.isArray(body.result.findings)).toBe(true);
		});

		it('returns MCP-framed response when format param is absent', async () => {
			const { mockTxtRecords } = await import('./helpers/dns-mock');
			mockTxtRecords(['v=spf1 -all']);

			const request = new Request<unknown, IncomingRequestCfProperties>(
				'http://example.com/internal/tools/call',
				{
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
				},
			);
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(200);
			const body = (await response.json()) as { content: { type: string; text: string }[]; result?: unknown };
			expect(body.content).toBeDefined();
			expect(body.content[0].type).toBe('text');
			expect(body.result).toBeUndefined();
		});

		it('falls through to MCP-framed response for non-registry tools with format=structured', async () => {
			const { httpResponse, createDohResponse } = await import('./helpers/dns-mock');

			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.startsWith('https://example.com') || url.startsWith('http://example.com')) {
					return Promise.resolve(httpResponse('', 200));
				}
				return Promise.resolve(createDohResponse([{ name: 'example.com', type: 1 }], []));
			});

			const request = new Request<unknown, IncomingRequestCfProperties>(
				'http://example.com/internal/tools/call?format=structured',
				{
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ name: 'scan_domain', arguments: { domain: 'example.com' } }),
				},
			);
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(200);
			const body = (await response.json()) as { content?: unknown; result?: unknown };
			expect(body.content).toBeDefined();
		});
	});
});
