// SPDX-License-Identifier: BUSL-1.1
//
// registerBrandAuditWatch — input validation vs persistence (US-13 / SQ-373).
// Pins the exact client-visible error strings (they reach clients through the
// error allowlist) and the "invalid input never touches D1" ordering, with a
// stub D1 so no schema is needed. The real-D1 behaviour (cap, insert, concurrent
// admission) lives in brand-audit-watch.integration.test.ts.

import { describe, expect, it, vi } from 'vitest';
import type { BrandAuditWatchDeps } from '../src/tools/brand-audit-watch';

function makeDb(run: () => Promise<{ meta: { changes: number } }>) {
	const binds: unknown[][] = [];
	const prepare = vi.fn((_sql: string) => ({
		bind: (...args: unknown[]) => {
			binds.push(args);
			return { run };
		},
	}));
	return { db: { prepare } as unknown as D1Database, prepare, binds };
}

function deps(db: D1Database): BrandAuditWatchDeps {
	return { db, generateId: () => 'wid-1', now: () => 1_750_000_000_000 };
}

async function register(args: Record<string, unknown>, db: D1Database) {
	const { registerBrandAuditWatch } = await import('../src/tools/brand-audit-watch');
	return registerBrandAuditWatch(args as never, 'owner-1', deps(db));
}

function onlyFinding(result: { findings: Array<{ title: string; severity: string; detail: string; metadata?: Record<string, unknown> }> }) {
	expect(result.findings).toHaveLength(1);
	return result.findings[0];
}

describe('registerBrandAuditWatch — validation (no D1 access)', () => {
	it.each([
		['missing domain', { interval: 'daily' }],
		['empty domain', { domain: '', interval: 'daily' }],
		['non-string domain', { domain: 42, interval: 'daily' }],
	])('%s → "domain is required."', async (_label, args) => {
		const { db, prepare } = makeDb(async () => ({ meta: { changes: 1 } }));
		const f = onlyFinding(await register(args, db));
		expect(f.title).toBe('Brand audit watch: invalidInput');
		expect(f.severity).toBe('high');
		expect(f.detail).toBe('domain is required.');
		expect(f.metadata?.invalidInput).toBe(true);
		expect(prepare).not.toHaveBeenCalled();
	});

	it.each([
		['missing interval', { domain: 'apple.com' }],
		['unknown interval', { domain: 'apple.com', interval: 'hourly' }],
	])('%s → interval message', async (_label, args) => {
		const { db, prepare } = makeDb(async () => ({ meta: { changes: 1 } }));
		const f = onlyFinding(await register(args, db));
		// createFinding strips the pipes from the source string (client-visible text).
		expect(f.detail).toBe('interval must be one of daily weekly monthly.');
		expect(prepare).not.toHaveBeenCalled();
	});

	it('checks the domain before the interval', async () => {
		const { db } = makeDb(async () => ({ meta: { changes: 1 } }));
		const f = onlyFinding(await register({ interval: 'hourly' }, db));
		expect(f.detail).toBe('domain is required.');
	});

	it('a policy-rejected domain → "Invalid domain: …" and no INSERT', async () => {
		const { db, prepare } = makeDb(async () => ({ meta: { changes: 1 } }));
		const f = onlyFinding(await register({ domain: '10.0.0.1', interval: 'daily' }, db));
		expect(f.detail.startsWith('Invalid domain: ')).toBe(true);
		expect(f.metadata?.invalidInput).toBe(true);
		expect(prepare).not.toHaveBeenCalled();
	});

	it('checks the domain policy before the webhook', async () => {
		const { db } = makeDb(async () => ({ meta: { changes: 1 } }));
		const f = onlyFinding(await register({ domain: '10.0.0.1', interval: 'daily', webhook_url: 'http://10.0.0.1/x' }, db));
		expect(f.detail.startsWith('Invalid domain: ')).toBe(true);
	});

	it('a private-IP webhook → "webhook_url failed SSRF validation: …" and no INSERT', async () => {
		const { db, prepare } = makeDb(async () => ({ meta: { changes: 1 } }));
		const f = onlyFinding(await register({ domain: 'apple.com', interval: 'daily', webhook_url: 'http://10.0.0.1/internal' }, db));
		expect(f.detail.startsWith('webhook_url failed SSRF validation: ')).toBe(true);
		expect(f.metadata?.invalidInput).toBe(true);
		expect(prepare).not.toHaveBeenCalled();
	});
});

describe('registerBrandAuditWatch — persistence outcomes', () => {
	it('success: one INSERT with the sanitized domain, summary finding, hasWebhook flag', async () => {
		const { db, prepare, binds } = makeDb(async () => ({ meta: { changes: 1 } }));
		const f = onlyFinding(await register({ domain: 'Apple.COM', interval: 'weekly', webhook_url: 'https://hooks.example.com/abc' }, db));
		expect(prepare).toHaveBeenCalledTimes(1);
		expect(binds[0]).toEqual([
			'wid-1',
			'owner-1',
			'apple.com',
			'weekly',
			'https://hooks.example.com/abc',
			1,
			1_750_000_000_000,
			'owner-1',
			20,
		]);
		expect(f.title).toBe('Brand audit watch registered: apple.com (weekly)');
		expect(f.severity).toBe('info');
		expect(f.detail).toBe('watchId=wid-1 interval=weekly webhook=set');
		expect(f.metadata).toMatchObject({
			summary: true,
			watchId: 'wid-1',
			domain: 'apple.com',
			interval: 'weekly',
			hasWebhook: true,
			createdAt: 1_750_000_000_000,
		});
	});

	it('success without a webhook binds null and reports webhook=none', async () => {
		const { db, binds } = makeDb(async () => ({ meta: { changes: 1 } }));
		const f = onlyFinding(await register({ domain: 'apple.com', interval: 'daily' }, db));
		expect(binds[0][4]).toBeNull();
		expect(f.detail).toBe('watchId=wid-1 interval=daily webhook=none');
		expect(f.metadata?.hasWebhook).toBe(false);
	});

	it('meta.changes=0 → watchLimitExceeded with the cap message and counters', async () => {
		const { db } = makeDb(async () => ({ meta: { changes: 0 } }));
		const f = onlyFinding(await register({ domain: 'apple.com', interval: 'daily' }, db));
		expect(f.title).toBe('Brand audit watch: watchLimitExceeded');
		expect(f.detail).toBe('Per-principal cap of 20 active watches reached. Delete an existing watch before registering another.');
		expect(f.metadata).toMatchObject({ watchLimitExceeded: true, current: 20, limit: 20 });
	});

	it('an Error thrown by D1 → persistenceFailure with its message', async () => {
		const { db } = makeDb(async () => {
			throw new Error('d1_down');
		});
		const f = onlyFinding(await register({ domain: 'apple.com', interval: 'daily' }, db));
		expect(f.title).toBe('Brand audit watch: persistenceFailure');
		expect(f.detail).toBe('Failed to register watch: d1_down');
	});

	it('a non-Error throw is stringified into persistenceFailure', async () => {
		const { db } = makeDb(async () => {
			throw 'plain-string-failure';
		});
		const f = onlyFinding(await register({ domain: 'apple.com', interval: 'daily' }, db));
		expect(f.detail).toBe('Failed to register watch: plain-string-failure');
	});
});
