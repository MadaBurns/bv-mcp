import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ScheduledEnv } from '../src/scheduled';

describe('handleScheduled', () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it('does nothing when ALERT_WEBHOOK_URL is not configured', async () => {
		const mockFetch = vi.fn() as typeof fetch;
		globalThis.fetch = mockFetch;
		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({} as ScheduledEnv);
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it('does nothing when CF_ACCOUNT_ID or CF_ANALYTICS_TOKEN is missing', async () => {
		const mockFetch = vi.fn() as typeof fetch;
		globalThis.fetch = mockFetch;
		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({ ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test' } as ScheduledEnv);
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it('sends alert when error rate exceeds threshold', async () => {
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push({ url, body: init?.body as string });

			// Mock Analytics Engine SQL API response
			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				if (query.includes('tool_call')) {
					return new Response(
						JSON.stringify({
							data: [{ total_calls: 100, error_count: 15, error_pct: 15.0, p95_ms: 5000 }],
						}),
					);
				}
				if (query.includes('rate_limit')) {
					return new Response(JSON.stringify({ data: [{ total_hits: 5 }] }));
				}
			}
			// Webhook call
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
			ALERT_ERROR_THRESHOLD: '5',
			ALERT_P95_THRESHOLD: '10000',
			ALERT_RATE_LIMIT_THRESHOLD: '50',
		});

		// Should have called Analytics Engine + webhook
		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		expect(webhookCall!.body).toContain('error');
	});

	it('sends a service-binding degradation alert when present-binding events appear', async () => {
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push({ url, body: init?.body as string });

			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				// Healthy tool_call + rate_limit so only the degradation branch fires.
				if (query.includes("index1 = 'degradation'")) {
					return new Response(JSON.stringify({ data: [{ component: 'recon', degradation_type: 'binding_5xx', event_count: 4 }] }));
				}
				if (query.includes('tool_call')) {
					return new Response(JSON.stringify({ data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }] }));
				}
				if (query.includes('rate_limit')) {
					return new Response(JSON.stringify({ data: [{ total_hits: 2 }] }));
				}
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		});

		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		expect(webhookCall!.body).toContain('binding');
	});

	it('alerts on recognized timeout outcomes only after the configured sample floor', async () => {
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			const body = init?.body as string;
			fetchCalls.push({ url, body });
			if (url.includes('analytics_engine/sql')) {
				if (body.includes('blob16 AS outcome_reason')) {
					return new Response(JSON.stringify({ data: [{ outcome_reason: 'upstream_timeout', total_calls: 3 }] }));
				}
				if (body.includes("index1 = 'tool_call'")) {
					return new Response(JSON.stringify({ data: [{ total_calls: 100, error_count: 0, error_pct: 0, p95_ms: 500 }] }));
				}
				return new Response(JSON.stringify({ data: [] }));
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		});

		const webhookCall = fetchCalls.find((call) => call.url.includes('hooks.slack.com'));
		expect(webhookCall?.body).toContain('Tool timeouts/aborts: 3');
		expect(webhookCall?.body).toContain('upstream_timeout=3');
	});

	it('sends an async-path failure alert when queue_batch failures cross the threshold', async () => {
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push({ url, body: init?.body as string });

			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				if (query.includes("index1 = 'queue_batch'")) {
					// 4 failed messages across an errored brand-audit batch.
					return new Response(
						JSON.stringify({
							data: [{ handler: 'brand-audit-queue', batch_count: 1, error_batch_count: 1, failure_count: 4 }],
						}),
					);
				}
				// Healthy tool_call / rate_limit / degradation so only the queue branch fires.
				if (query.includes("index1 = 'degradation'")) return new Response(JSON.stringify({ data: [] }));
				if (query.includes('tool_call')) {
					return new Response(JSON.stringify({ data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }] }));
				}
				if (query.includes('rate_limit')) return new Response(JSON.stringify({ data: [{ total_hits: 2 }] }));
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		});

		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		expect(webhookCall!.body).toContain('Async-path failures');
		expect(webhookCall!.body).toContain('brand-audit-queue');
	});

	it('sends a cost-ceiling alert when a cost_ceiling_degraded row reaches the cron (R9)', async () => {
		// The whole point of the R9 fix: a cost_ceiling_degraded row (emitted while
		// the QuotaCoordinator breaker is OPEN) must NOT be filtered out and must
		// reach the 15-min cron alert. Here the engine returns such a row.
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push({ url, body: init?.body as string });
			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				if (query.includes("index1 = 'degradation'")) {
					return new Response(
						JSON.stringify({ data: [{ component: 'global_cost_ceiling', degradation_type: 'cost_ceiling_degraded', event_count: 8 }] }),
					);
				}
				if (query.includes('tool_call')) {
					return new Response(JSON.stringify({ data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }] }));
				}
				if (query.includes('rate_limit')) {
					return new Response(JSON.stringify({ data: [{ total_hits: 2 }] }));
				}
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		});

		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		// Title reads as a cost-ceiling degradation (not "Service-binding") and the
		// breakdown carries the cost-ceiling component.
		expect(webhookCall!.body).toContain('cost-ceiling');
		expect(webhookCall!.body).toContain('global_cost_ceiling');
	});

	it('does NOT send an async-path failure alert when no queue_batch failures occur (0 rows)', async () => {
		const fetchCalls: string[] = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push(url);
			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				// The query's HAVING clause filters clean batches, so the engine returns no rows.
				if (query.includes("index1 = 'queue_batch'")) return new Response(JSON.stringify({ data: [] }));
				if (query.includes("index1 = 'degradation'")) return new Response(JSON.stringify({ data: [] }));
				if (query.includes('tool_call'))
					return new Response(JSON.stringify({ data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }] }));
				if (query.includes('rate_limit')) return new Response(JSON.stringify({ data: [{ total_hits: 2 }] }));
				return new Response(JSON.stringify({ data: [] }));
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({ CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't', ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test' });
		expect(fetchCalls.filter((u) => u.includes('hooks.slack.com'))).toHaveLength(0);
	});

	it('does NOT send a degradation alert when only kv_fallback occurs (query excludes it → 0 rows)', async () => {
		const fetchCalls: string[] = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push(url);
			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				// The SQL itself filters kv_fallback, so the engine returns no rows here.
				if (query.includes("index1 = 'degradation'")) return new Response(JSON.stringify({ data: [] }));
				if (query.includes('tool_call'))
					return new Response(JSON.stringify({ data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }] }));
				if (query.includes('rate_limit')) return new Response(JSON.stringify({ data: [{ total_hits: 2 }] }));
				return new Response(JSON.stringify({ data: [] }));
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({ CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't', ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test' });
		expect(fetchCalls.filter((u) => u.includes('hooks.slack.com'))).toHaveLength(0);
	});

	it('does not send alert when metrics are within thresholds', async () => {
		const fetchCalls: string[] = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push(url);

			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				if (query.includes('tool_call')) {
					return new Response(
						JSON.stringify({
							data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }],
						}),
					);
				}
				if (query.includes('rate_limit')) {
					return new Response(JSON.stringify({ data: [{ total_hits: 2 }] }));
				}
				return new Response(JSON.stringify({ data: [] }));
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		});

		// Should NOT have called the webhook
		const webhookCalls = fetchCalls.filter((u) => u.includes('hooks.slack.com'));
		expect(webhookCalls).toHaveLength(0);
	});

	it('sends a watchdog alert through the webhook when the analytics query pipeline fails', async () => {
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push({ url, body: init?.body as string });
			if (url.includes('analytics_engine/sql')) {
				throw new Error('Authentication error: token expired');
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		} as ScheduledEnv);

		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		expect(webhookCall!.body).toContain('Alerting pipeline failure');
		// The watchdog must carry the REASON. Without it the page says only "could not
		// run", and the cause has to be recovered by probing the live API out-of-band —
		// which is exactly what a 7-day-continuous 422 outage cost. The thrown message
		// now carries the AE rejection body (see analytics-engine-error-detail.spec.ts).
		expect(webhookCall!.body).toContain('Authentication error: token expired');
	});
});

describe('checkAccessRollupProvisioned (via handleScheduled)', () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
		vi.restoreAllMocks();
	});

	/** Records every `.bind()` call so a test can assert on the exact args a query received. */
	interface FakeD1Options {
		/** `SELECT 1 FROM mcp_access_rollup LIMIT 1` resolves (no throw) — table exists. `first()` returns null (0 rows), matching an empty-but-provisioned table. */
		rollupTableExists?: boolean;
		/** Message thrown by the rollup probe when the table is absent — override to simulate a DIFFERENT (non "no such table") D1 error. */
		rollupErrorMessage?: string;
		/** Row returned by the `mcp_access_log` correlation query. */
		accessLogRow?: { cnt: number } | null;
		/** Make the correlation query itself throw (best-effort context failure). */
		accessLogThrows?: boolean;
	}

	function makeFakeIntelligenceDb(opts: FakeD1Options) {
		const bindCalls: Array<{ sql: string; args: unknown[] }> = [];
		const db = {
			prepare(sql: string) {
				const stmt = {
					bind(...args: unknown[]) {
						bindCalls.push({ sql, args });
						return stmt;
					},
					async first<T = unknown>(): Promise<T | null> {
						if (sql.includes('FROM mcp_access_rollup')) {
							if (opts.rollupTableExists) return null; // provisioned, empty result set
							throw new Error(opts.rollupErrorMessage ?? 'D1_ERROR: no such table: mcp_access_rollup: SQLITE_ERROR');
						}
						if (sql.includes('FROM mcp_access_log')) {
							if (opts.accessLogThrows) throw new Error('D1_ERROR: transient failure querying mcp_access_log');
							return (opts.accessLogRow ?? null) as T;
						}
						return null;
					},
					async run() {
						// Only the retention DELETE hits this in these tests — no-op success.
						return { success: true } as unknown as D1Result;
					},
				};
				return stmt;
			},
		};
		return { db: db as unknown as D1Database, bindCalls };
	}

	function mockFetchCapturing(): Array<{ url: string; body: string }> {
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push({ url, body: init?.body as string });
			return new Response('ok');
		}) as typeof fetch;
		return fetchCalls;
	}

	it('fires an alert on the missing-table error ("no such table")', async () => {
		const { db } = makeFakeIntelligenceDb({ rollupTableExists: false, accessLogRow: { cnt: 42 } });
		const fetchCalls = mockFetchCapturing();

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			INTELLIGENCE_DB: db,
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		} as unknown as ScheduledEnv);

		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		expect(webhookCall!.body).toContain('mcp_access_rollup table missing');
		expect(webhookCall!.body).toContain('uncounted_internal_requests_24h: 42');
	});

	it('does NOT alert when mcp_access_rollup is provisioned (table present, even if empty)', async () => {
		const { db } = makeFakeIntelligenceDb({ rollupTableExists: true });
		const fetchCalls = mockFetchCapturing();

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			INTELLIGENCE_DB: db,
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		} as unknown as ScheduledEnv);

		expect(fetchCalls.filter((c) => c.url.includes('hooks.slack.com'))).toHaveLength(0);
	});

	it('does NOT alert on an unrelated D1 error (not "no such table") — a different, already-covered failure mode', async () => {
		const { db } = makeFakeIntelligenceDb({ rollupTableExists: false, rollupErrorMessage: 'D1_ERROR: database is locked' });
		const fetchCalls = mockFetchCapturing();

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			INTELLIGENCE_DB: db,
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		} as unknown as ScheduledEnv);

		expect(fetchCalls.filter((c) => c.url.includes('hooks.slack.com'))).toHaveLength(0);
	});

	it('computes the mcp_access_log cutoff in epoch SECONDS, matching created_at\'s convention (the docstring unit trap)', async () => {
		const FIXED_NOW_MS = 1_800_000_000_000; // 2027-01-15T06:40:00.000Z — arbitrary fixed instant
		vi.spyOn(Date, 'now').mockReturnValue(FIXED_NOW_MS);
		const { db, bindCalls } = makeFakeIntelligenceDb({ rollupTableExists: false, accessLogRow: { cnt: 7 } });
		mockFetchCapturing();

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			INTELLIGENCE_DB: db,
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		} as unknown as ScheduledEnv);

		// NOTE: the unrelated retention-prune lane (`DELETE FROM mcp_access_log ...`,
		// a DIFFERENT 90-day-default cutoff) also binds against `mcp_access_log` in
		// the same tick — match the correlation SELECT specifically, not just the table name.
		const accessLogCall = bindCalls.find((c) => c.sql.includes('SELECT COUNT(*)') && c.sql.includes('mcp_access_log'));
		expect(accessLogCall).toBeDefined();
		const cutoff = accessLogCall!.args[0] as number;

		// The exact conversion the docstring warns about: seconds, not the epoch-ms
		// Date.now() itself uses. `brand_audits.created_at` is milliseconds; a cutoff
		// computed on that convention here would be ~1000x this value and land in the
		// far future relative to mcp_access_log's SECONDS created_at column.
		const expectedCutoffSeconds = Math.floor(FIXED_NOW_MS / 1000) - 24 * 3600;
		expect(cutoff).toBe(expectedCutoffSeconds);
		expect(cutoff).toBeLessThan(FIXED_NOW_MS / 1000);
		expect(String(Math.trunc(cutoff)).length).toBeLessThanOrEqual(10); // epoch-SECONDS magnitude, not epoch-ms (13 digits)
	});

	it('reports an explicit 0 (not "unknown") when mcp_access_log has zero matching rows', async () => {
		const { db } = makeFakeIntelligenceDb({ rollupTableExists: false, accessLogRow: { cnt: 0 } });
		const fetchCalls = mockFetchCapturing();

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			INTELLIGENCE_DB: db,
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		} as unknown as ScheduledEnv);

		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		expect(webhookCall!.body).toContain('uncounted_internal_requests_24h: 0');
		expect(webhookCall!.body).not.toContain('unknown (mcp_access_log query also failed)');
	});

	it('reports "unknown" (never a false 0) when the correlation query itself fails', async () => {
		const { db } = makeFakeIntelligenceDb({ rollupTableExists: false, accessLogThrows: true });
		const fetchCalls = mockFetchCapturing();

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			INTELLIGENCE_DB: db,
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		} as unknown as ScheduledEnv);

		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		expect(webhookCall!.body).toContain('uncounted_internal_requests_24h: unknown (mcp_access_log query also failed)');
	});
});

describe('scheduled.ts alert webhook resolution', () => {
	afterEach(() => {
		vi.restoreAllMocks();
		vi.resetModules();
	});

	it('the main alert checker passes the RESOLVED value to sendAlert, not the literal env var', async () => {
		// Force a clean module graph: earlier tests in this file already imported
		// '../src/scheduled' (which statically imports operator-webhook-binding),
		// so without this the doMock below would register too late to affect the
		// cached module instance.
		vi.resetModules();
		vi.doMock('../src/lib/operator-webhook-binding', () => ({
			resolveAlertWebhookUrl: vi.fn(async () => 'https://hooks.example.com/resolved'),
		}));
		const alertingModule = await import('../src/lib/alerting');
		const sendAlertSpy = vi.spyOn(alertingModule, 'sendAlert').mockResolvedValue(true);

		const { handleScheduled } = await import('../src/scheduled');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- minimal env for this targeted test
		const env: any = {
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static-should-not-be-used',
			CF_ACCOUNT_ID: 'acct',
			CF_ANALYTICS_TOKEN: 'token',
		};

		await handleScheduled(env);

		// Every sendAlert call this tick must have received the RESOLVED value,
		// never the literal static env var — this is the precedence-regression
		// guard at the scheduled.ts integration layer (Task 1 already pins the
		// resolver's own precedence in isolation).
		for (const call of sendAlertSpy.mock.calls) {
			expect(call[0]).toBe('https://hooks.example.com/resolved');
			expect(call[0]).not.toBe('https://hooks.example.com/static-should-not-be-used');
		}
	});
});
