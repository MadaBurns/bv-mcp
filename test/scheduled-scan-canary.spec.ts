// SPDX-License-Identifier: BUSL-1.1

/**
 * SCAN-PATH CANARY — the 15-minute synthetic `scanDomain` of a control domain.
 *
 * The traffic-driven alert lanes abstain below a sample floor, so a scan path broken end to end at low
 * traffic paged nobody. These tests pin the paging contract: one unhealthy run never pages, the
 * second consecutive one pages exactly once (critical), repeats are suppressed, recovery is announced
 * once, the kill switch skips the scan, and a canary fault never blocks the other scheduled lanes.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';

const WEBHOOK = 'https://hooks.slack.com/test';

/** In-memory KV: get/put/delete is all the alert-state helpers use. */
function memoryKv(): KVNamespace & { store: Map<string, string> } {
	const store = new Map<string, string>();
	return {
		store,
		get: async (key: string) => store.get(key) ?? null,
		put: async (key: string, value: string) => {
			store.set(key, value);
		},
		delete: async (key: string) => {
			store.delete(key);
		},
	} as unknown as KVNamespace & { store: Map<string, string> };
}

type ScanMode = 'healthy' | 'throw' | 'ungraded';

function healthyResult() {
	return {
		resolves: undefined,
		score: { overall: 80, grade: 'B', categoryScores: {}, findings: [], summary: '', evidence: { attempted: 19, completed: 19, ratio: 1 } },
	};
}

/** Load scheduled.ts with `scanDomain` replaced by a scripted fake; the rest of scan-domain stays real. */
async function loadWithScan(modes: ScanMode[]) {
	const scan = vi.fn(async () => {
		const mode = modes.shift() ?? 'healthy';
		if (mode === 'throw') throw new Error('resolver transport down');
		if (mode === 'ungraded') {
			return {
				resolves: undefined,
				score: { overall: null, grade: null, evidence: { attempted: 19, completed: 3, ratio: 3 / 19 }, evidenceInsufficient: true },
			};
		}
		return healthyResult();
	});
	vi.doMock('../src/tools/scan-domain', async (importOriginal) => ({ ...(await importOriginal<object>()), scanDomain: scan }));
	const scheduled = await import('../src/scheduled');
	return { scan, ...scheduled };
}

interface Posted {
	url: string;
	body: string;
}

function mockWebhook(): Posted[] {
	const posted: Posted[] = [];
	globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
		if (url.includes('hooks.slack.com')) posted.push({ url, body: (init?.body as string) ?? '' });
		return new Response('ok');
	}) as typeof fetch;
	return posted;
}

/** AE fetch mock that makes the tail-exception lane alert-worthy, so a surviving alert proves that lane ran. */
function mockAnalyticsWithTailAlert(): Posted[] {
	const posted: Posted[] = [];
	globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
		const body = (init?.body as string) ?? '';
		if (url.includes('hooks.slack.com')) {
			posted.push({ url, body });
			return new Response('ok');
		}
		if (url.includes('analytics_engine/sql')) {
			if (body.includes("index1 = 'tail'")) return Response.json({ data: [{ exception_count: 250 }] });
			return Response.json({ data: [] });
		}
		return new Response('ok');
	}) as typeof fetch;
	return posted;
}

afterEach(() => {
	vi.restoreAllMocks();
	vi.doUnmock('../src/tools/scan-domain');
	vi.resetModules();
});

describe('scan canary paging', () => {
	it('one unhealthy run -> no page (acceptance: fail once then succeed sends nothing)', async () => {
		const posted = mockWebhook();
		const kv = memoryKv();
		const { handleScanCanary } = await loadWithScan(['throw', 'healthy']);
		const env = { ALERT_WEBHOOK_URL: WEBHOOK, RATE_LIMIT: kv };

		await handleScanCanary(env);
		expect(posted).toHaveLength(0);
		expect(kv.store.get('scan-canary:consecutive-failures')).toBe('1');

		await handleScanCanary(env); // healthy: blip cleared silently
		expect(posted).toHaveLength(0);
		expect(kv.store.has('scan-canary:consecutive-failures')).toBe(false);
	});

	it('two consecutive unhealthy runs -> exactly one critical page; the third is suppressed', async () => {
		const posted = mockWebhook();
		const kv = memoryKv();
		const { handleScanCanary } = await loadWithScan(['throw', 'throw', 'throw']);
		const env = { ALERT_WEBHOOK_URL: WEBHOOK, RATE_LIMIT: kv };

		await handleScanCanary(env);
		expect(posted).toHaveLength(0);
		await handleScanCanary(env);
		expect(posted).toHaveLength(1);
		expect(posted[0].body).toContain('Critical');
		expect(posted[0].body).toContain('Scan path canary failing');
		expect(posted[0].body).toContain('blackveilsecurity.com');
		expect(posted[0].body).toContain('threw');
		await handleScanCanary(env);
		expect(posted).toHaveLength(1);
	});

	it('a flapping failure reason does not re-page while the outage persists', async () => {
		const posted = mockWebhook();
		const kv = memoryKv();
		const { handleScanCanary } = await loadWithScan(['throw', 'ungraded', 'throw', 'ungraded']);
		const env = { ALERT_WEBHOOK_URL: WEBHOOK, RATE_LIMIT: kv };
		for (let i = 0; i < 4; i++) await handleScanCanary(env);
		expect(posted).toHaveLength(1);
	});

	it('first healthy run after a page -> one recovery notice, counter reset, next failure starts over', async () => {
		const posted = mockWebhook();
		const kv = memoryKv();
		const { handleScanCanary } = await loadWithScan(['throw', 'throw', 'healthy', 'healthy', 'throw']);
		const env = { ALERT_WEBHOOK_URL: WEBHOOK, RATE_LIMIT: kv };

		await handleScanCanary(env);
		await handleScanCanary(env);
		expect(posted).toHaveLength(1);

		await handleScanCanary(env); // healthy
		expect(posted).toHaveLength(2);
		expect(posted[1].body).toContain('Alert recovered: scan_canary');
		expect(kv.store.has('scan-canary:consecutive-failures')).toBe(false);

		await handleScanCanary(env); // healthy again: no second recovery notice
		expect(posted).toHaveLength(2);

		await handleScanCanary(env); // new first failure: counted, not paged
		expect(posted).toHaveLength(2);
		expect(kv.store.get('scan-canary:consecutive-failures')).toBe('1');
	});

	it('an ungraded scan counts as unhealthy', async () => {
		const posted = mockWebhook();
		const { handleScanCanary } = await loadWithScan(['ungraded', 'ungraded']);
		const env = { ALERT_WEBHOOK_URL: WEBHOOK, RATE_LIMIT: memoryKv() };
		await handleScanCanary(env);
		await handleScanCanary(env);
		expect(posted).toHaveLength(1);
		expect(posted[0].body).toContain('ungraded');
	});

	it('an unconfigured alert sink only logs and continues (fail-open)', async () => {
		const posted = mockWebhook();
		const { handleScanCanary } = await loadWithScan(['throw', 'throw']);
		const env = { RATE_LIMIT: memoryKv() };
		await expect(handleScanCanary(env)).resolves.toBeUndefined();
		await expect(handleScanCanary(env)).resolves.toBeUndefined();
		expect(posted).toHaveLength(0);
	});

	it('without the alert-state KV a single unhealthy run can never page', async () => {
		const posted = mockWebhook();
		const { handleScanCanary } = await loadWithScan(['throw', 'throw']);
		await handleScanCanary({ ALERT_WEBHOOK_URL: WEBHOOK });
		await handleScanCanary({ ALERT_WEBHOOK_URL: WEBHOOK });
		expect(posted).toHaveLength(0);
	});

	it('logs the outcome for a healthy run too, so a missing alert is verifiable', async () => {
		mockWebhook();
		const logs: string[] = [];
		vi.spyOn(console, 'log').mockImplementation((line: unknown) => {
			logs.push(String(line));
		});
		const { handleScanCanary } = await loadWithScan(['healthy']);
		await handleScanCanary({ ALERT_WEBHOOK_URL: WEBHOOK, RATE_LIMIT: memoryKv() });
		const line = logs.find((l) => l.includes('"scan_canary"'));
		expect(line).toBeDefined();
		expect(line).toContain('"healthy":true');
	});
});

describe('scan canary kill switch', () => {
	it('SCAN_CANARY_ENABLED=false -> no scan attempted, no alert, other lanes still run', async () => {
		const posted = mockAnalyticsWithTailAlert();
		const kv = memoryKv();
		const { scan, handleScheduled } = await loadWithScan(['throw', 'throw']);
		const env = { ALERT_WEBHOOK_URL: WEBHOOK, RATE_LIMIT: kv, SCAN_CANARY_ENABLED: 'false', CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't' };

		await handleScheduled(env);
		await handleScheduled(env);

		expect(scan).not.toHaveBeenCalled();
		expect(kv.store.has('scan-canary:consecutive-failures')).toBe(false);
		expect(posted.some((p) => p.body.includes('Scan path canary'))).toBe(false);
		// The other lanes still ran: the alert-worthy tail-exception lane fired on both ticks.
		expect(posted.filter((p) => p.body.includes('Fatal Worker exceptions')).length).toBeGreaterThanOrEqual(1);
	});
});

describe('scan canary isolation', () => {
	it('a throwing scan does not break the other scheduled lanes', async () => {
		const posted = mockAnalyticsWithTailAlert();
		const { scan, handleScheduled } = await loadWithScan(['throw']);
		await expect(
			handleScheduled({ CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't', ALERT_WEBHOOK_URL: WEBHOOK, RATE_LIMIT: memoryKv() }),
		).resolves.toBeUndefined();
		expect(scan).toHaveBeenCalledTimes(1);
		expect(posted.map((p) => p.body).join('\n')).toContain('Fatal Worker exceptions');
	});

	it('a faulting alert-state KV does not break the other scheduled lanes', async () => {
		const posted = mockAnalyticsWithTailAlert();
		const broken = {
			get: async () => {
				throw new Error('kv down');
			},
			put: async () => {
				throw new Error('kv down');
			},
			delete: async () => {
				throw new Error('kv down');
			},
		} as unknown as KVNamespace;
		const { handleScheduled } = await loadWithScan(['throw']);
		await expect(
			handleScheduled({ CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't', ALERT_WEBHOOK_URL: WEBHOOK, RATE_LIMIT: broken }),
		).resolves.toBeUndefined();
		expect(posted.map((p) => p.body).join('\n')).toContain('Fatal Worker exceptions');
	});

	it('runs once per fully-configured tick and not on an unconfigured self-host tick', async () => {
		mockAnalyticsWithTailAlert();
		const { scan, handleScheduled } = await loadWithScan(['healthy', 'healthy']);
		await handleScheduled({ CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't', ALERT_WEBHOOK_URL: WEBHOOK, RATE_LIMIT: memoryKv() });
		expect(scan).toHaveBeenCalledTimes(1);
		await handleScheduled({ ALERT_WEBHOOK_URL: WEBHOOK, RATE_LIMIT: memoryKv() });
		expect(scan).toHaveBeenCalledTimes(1);
	});
});
