import { describe, it, expect, vi, afterEach } from 'vitest';

// Local shape matching ScheduledEnv's relevant fields — avoids importing the
// real ScheduledEnv before Task 2 widens it.
interface TestEnv {
	BV_WEB?: { fetch: (url: string, init?: RequestInit) => Promise<Response> };
	BV_WEB_INTERNAL_KEY?: string;
	SCAN_CACHE?: {
		get: (key: string) => Promise<string | null>;
		put: (key: string, value: string, opts?: { expirationTtl?: number }) => Promise<void>;
	};
	ALERT_WEBHOOK_URL?: string;
}

function mockFetch(status: number, body?: unknown): (url: string, init?: RequestInit) => Promise<Response> {
	return vi.fn(async () => new Response(body !== undefined ? JSON.stringify(body) : undefined, { status }));
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe('resolveAlertWebhookUrl', () => {
	it('dynamic succeeds and wins over static (precedence regression guard)', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const put = vi.fn(async () => {});
		const env: TestEnv = {
			BV_WEB: { fetch: mockFetch(200, { webhookUrl: 'https://hooks.example.com/dynamic' }) },
			BV_WEB_INTERNAL_KEY: 'test-key',
			SCAN_CACHE: { get: vi.fn(async () => null), put },
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static',
		};
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- ScheduledEnv widened in Task 2
		const result = await resolveAlertWebhookUrl(env as any);
		expect(result).toBe('https://hooks.example.com/dynamic');
		expect(put).toHaveBeenCalledWith('operator-webhook:last-known-good', 'https://hooks.example.com/dynamic', {
			expirationTtl: 86_400,
		});
	});

	it('dynamic confirmed-empty falls through to static WITHOUT caching', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const put = vi.fn(async () => {});
		const env: TestEnv = {
			BV_WEB: { fetch: mockFetch(200, { webhookUrl: null }) },
			BV_WEB_INTERNAL_KEY: 'test-key',
			SCAN_CACHE: { get: vi.fn(async () => null), put },
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static',
		};
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- ScheduledEnv widened in Task 2
		const result = await resolveAlertWebhookUrl(env as any);
		expect(result).toBe('https://hooks.example.com/static');
		expect(put).not.toHaveBeenCalled();
	});

	it('dynamic ambiguous failure (5xx) falls to KV last-known-good cache', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const env: TestEnv = {
			BV_WEB: { fetch: mockFetch(503) },
			BV_WEB_INTERNAL_KEY: 'test-key',
			SCAN_CACHE: { get: vi.fn(async () => 'https://hooks.example.com/cached'), put: vi.fn(async () => {}) },
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static',
		};
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- ScheduledEnv widened in Task 2
		const result = await resolveAlertWebhookUrl(env as any);
		expect(result).toBe('https://hooks.example.com/cached');
	});

	it.each([
		['malformed', () => new Response('{not-json', { status: 200 })],
		['oversized', () => new Response(JSON.stringify({ webhookUrl: 'x'.repeat(20 * 1024) }), { status: 200 })],
		[
			'unreadable',
			() =>
				new Response(
					new ReadableStream<Uint8Array>({
						pull() {
							throw new Error('stream read failed');
						},
					}),
					{ status: 200 },
				),
		],
	] as const)('treats an %s 2xx body as ambiguous and uses KV last-known-good', async (_case, responseFactory) => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const get = vi.fn(async () => 'https://hooks.example.com/cached');
		const put = vi.fn(async () => {});
		const env: TestEnv = {
			BV_WEB: { fetch: vi.fn(async () => responseFactory()) },
			BV_WEB_INTERNAL_KEY: 'test-key',
			SCAN_CACHE: { get, put },
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static',
		};

		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- focused partial ScheduledEnv fixture
		await expect(resolveAlertWebhookUrl(env as any)).resolves.toBe('https://hooks.example.com/cached');
		expect(get).toHaveBeenCalledWith('operator-webhook:last-known-good');
		expect(put).not.toHaveBeenCalled();
	});

	it.each(['', '   ', '\t\n'])('rejects a blank dynamic URL and uses KV last-known-good (%j)', async (webhookUrl) => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const get = vi.fn(async () => 'https://hooks.example.com/cached');
		const put = vi.fn(async () => {});
		const env: TestEnv = {
			BV_WEB: { fetch: mockFetch(200, { webhookUrl }) },
			BV_WEB_INTERNAL_KEY: 'test-key',
			SCAN_CACHE: { get, put },
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static',
		};

		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- focused partial ScheduledEnv fixture
		await expect(resolveAlertWebhookUrl(env as any)).resolves.toBe('https://hooks.example.com/cached');
		expect(get).toHaveBeenCalledWith('operator-webhook:last-known-good');
		expect(put).not.toHaveBeenCalled();
	});

	it('ignores a whitespace-only cached URL and uses the static fallback', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const env: TestEnv = {
			BV_WEB: { fetch: mockFetch(503) },
			SCAN_CACHE: { get: vi.fn(async () => '  \t '), put: vi.fn(async () => {}) },
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static',
		};

		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- focused partial ScheduledEnv fixture
		await expect(resolveAlertWebhookUrl(env as any)).resolves.toBe('https://hooks.example.com/static');
	});

	it('returns undefined rather than a whitespace-only static URL', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- focused partial ScheduledEnv fixture
		await expect(resolveAlertWebhookUrl({ ALERT_WEBHOOK_URL: ' \n ' } as any)).resolves.toBeUndefined();
	});

	it('returns a fresh dynamic URL even when its best-effort cache write fails', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const env: TestEnv = {
			BV_WEB: { fetch: mockFetch(200, { webhookUrl: 'https://hooks.example.com/dynamic' }) },
			SCAN_CACHE: {
				get: vi.fn(async () => null),
				put: vi.fn(async () => {
					throw new Error('KV unavailable');
				}),
			},
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static',
		};

		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- focused partial ScheduledEnv fixture
		await expect(resolveAlertWebhookUrl(env as any)).resolves.toBe('https://hooks.example.com/dynamic');
	});

	it('uses the static fallback when the optional LKG cache read fails', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const env: TestEnv = {
			BV_WEB: { fetch: mockFetch(503) },
			SCAN_CACHE: {
				get: vi.fn(async () => {
					throw new Error('KV unavailable');
				}),
				put: vi.fn(async () => {}),
			},
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static',
		};

		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- focused partial ScheduledEnv fixture
		await expect(resolveAlertWebhookUrl(env as any)).resolves.toBe('https://hooks.example.com/static');
	});

	it('dynamic ambiguous failure with EMPTY cache falls to static var', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const env: TestEnv = {
			BV_WEB: { fetch: mockFetch(503) },
			BV_WEB_INTERNAL_KEY: 'test-key',
			SCAN_CACHE: { get: vi.fn(async () => null), put: vi.fn(async () => {}) },
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static',
		};
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- ScheduledEnv widened in Task 2
		const result = await resolveAlertWebhookUrl(env as any);
		expect(result).toBe('https://hooks.example.com/static');
	});

	it('401 (definitive) skips the cache entirely and goes straight to static var', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const get = vi.fn(async () => 'https://hooks.example.com/cached');
		const env: TestEnv = {
			BV_WEB: { fetch: mockFetch(401) },
			BV_WEB_INTERNAL_KEY: 'test-key',
			SCAN_CACHE: { get, put: vi.fn(async () => {}) },
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static',
		};
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- ScheduledEnv widened in Task 2
		const result = await resolveAlertWebhookUrl(env as any);
		expect(result).toBe('https://hooks.example.com/static');
		expect(get).not.toHaveBeenCalled();
	});

	it('BV_WEB binding absent (BSL self-host) skips the dynamic path — byte-identical to today', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const env: TestEnv = { ALERT_WEBHOOK_URL: 'https://hooks.example.com/static' };
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- ScheduledEnv widened in Task 2
		const result = await resolveAlertWebhookUrl(env as any);
		expect(result).toBe('https://hooks.example.com/static');
	});

	it('nothing resolves anywhere returns undefined (today\'s no-op behavior, unchanged)', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const env: TestEnv = {};
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- ScheduledEnv widened in Task 2
		const result = await resolveAlertWebhookUrl(env as any);
		expect(result).toBeUndefined();
	});

	it('network throw (fetch rejects) is treated as ambiguous, falls to KV cache', async () => {
		const { resolveAlertWebhookUrl } = await import('../src/lib/operator-webhook-binding');
		const env: TestEnv = {
			BV_WEB: {
				fetch: vi.fn(async () => {
					throw new Error('network down');
				}),
			},
			BV_WEB_INTERNAL_KEY: 'test-key',
			SCAN_CACHE: { get: vi.fn(async () => 'https://hooks.example.com/cached'), put: vi.fn(async () => {}) },
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/static',
		};
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- ScheduledEnv widened in Task 2
		const result = await resolveAlertWebhookUrl(env as any);
		expect(result).toBe('https://hooks.example.com/cached');
	});
});
