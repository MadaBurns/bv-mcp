// SPDX-License-Identifier: BUSL-1.1

/**
 * Integration tests for the cron-trigger dispatch in `src/index.ts`.
 *
 * Hits the exported `worker.scheduled` handler directly so we can inject the
 * Tenant bindings (`TENANT_REGISTRY_DB`, `TENANT_DB_*`, `BV_SCANNER_QUEUE`)
 * required by the Phase-3 handlers — `SELF.scheduled` would use
 * `vitest.config.mts` env which doesn't define them.
 *
 * Each cron expression dispatches a different set of handlers; we verify
 * the dispatch by mocking the handler module and asserting which functions
 * were called.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';

// Hoisted spies so vi.mock factories can read them.
const brandAuditWeeklyRescanMock = vi.hoisted(() => vi.fn(async (_e: unknown, _c: unknown) => undefined));
const brandAuditCycleAlertsMock = vi.hoisted(() => vi.fn(async (_e: unknown, _c: unknown) => undefined));
const fuzzingScanMock = vi.hoisted(() => vi.fn(async (_e: unknown) => undefined));
const dailyDigestMock = vi.hoisted(() => vi.fn(async (_e: unknown) => undefined));
const scheduledMock = vi.hoisted(() => vi.fn(async (_e: unknown) => undefined));

vi.mock('../../src/tenants/scheduled-handlers', async () => {
	const actual = await vi.importActual<typeof import('../../src/tenants/scheduled-handlers')>(
		'../../src/tenants/scheduled-handlers',
	);
	return {
		...actual,
		handleTenantWeeklyRescan: brandAuditWeeklyRescanMock,
		handleTenantCycleAlerts: brandAuditCycleAlertsMock,
	};
});

vi.mock('../../src/scheduled', async () => {
	const actual = await vi.importActual<typeof import('../../src/scheduled')>('../../src/scheduled');
	return {
		...actual,
		handleScheduled: scheduledMock,
		handleDailyDigest: dailyDigestMock,
		handleFuzzingScan: fuzzingScanMock,
	};
});

beforeEach(() => {
	brandAuditWeeklyRescanMock.mockClear();
	brandAuditCycleAlertsMock.mockClear();
	fuzzingScanMock.mockClear();
	dailyDigestMock.mockClear();
	scheduledMock.mockClear();
});

async function runCron(cron: string) {
	const worker = (await import('../../src')).default;
	const ctx = createExecutionContext();
	await worker.scheduled!(
		{ scheduledTime: Date.now(), cron, type: 'scheduled' } as ScheduledEvent,
		env as Record<string, unknown>,
		ctx,
	);
	await waitOnExecutionContext(ctx);
}

describe('worker.scheduled cron dispatch', () => {
	it('a. weekly cron 0 2 * * 0 → handleTenantWeeklyRescan runs (and only it)', async () => {
		await runCron('0 2 * * 0');
		expect(brandAuditWeeklyRescanMock).toHaveBeenCalledTimes(1);
		expect(brandAuditCycleAlertsMock).not.toHaveBeenCalled();
		expect(fuzzingScanMock).not.toHaveBeenCalled();
		expect(scheduledMock).not.toHaveBeenCalled();
		expect(dailyDigestMock).not.toHaveBeenCalled();
	});

	it('a2. weekly cron 0 2 * * SUN (named DOW, the DEPLOYED form) → handleTenantWeeklyRescan runs (and only it)', async () => {
		// Regression guard (F1): wrangler.jsonc declares the trigger as the NAMED
		// day-of-week form `0 2 * * SUN`. If Cloudflare passes the cron string
		// verbatim, a string-equality dispatcher against the numeric `0 2 * * 0`
		// silently falls through to the 15-min else-branch and the weekly rescan
		// never runs. The fix normalizes DOW names → numbers on both sides.
		await runCron('0 2 * * SUN');
		expect(brandAuditWeeklyRescanMock).toHaveBeenCalledTimes(1);
		expect(brandAuditCycleAlertsMock).not.toHaveBeenCalled();
		expect(fuzzingScanMock).not.toHaveBeenCalled();
		expect(scheduledMock).not.toHaveBeenCalled();
		expect(dailyDigestMock).not.toHaveBeenCalled();
	});

	it('b. 15-min cron *\\/15 * * * * → handleFuzzingScan AND handleTenantCycleAlerts both run', async () => {
		await runCron('*/15 * * * *');
		expect(fuzzingScanMock).toHaveBeenCalledTimes(1);
		expect(brandAuditCycleAlertsMock).toHaveBeenCalledTimes(1);
		expect(scheduledMock).toHaveBeenCalledTimes(1);
		expect(brandAuditWeeklyRescanMock).not.toHaveBeenCalled();
		expect(dailyDigestMock).not.toHaveBeenCalled();
	});

	it('c. 8am cron 0 8 * * * → handleDailyDigest runs; Tenant handlers do NOT', async () => {
		await runCron('0 8 * * *');
		expect(dailyDigestMock).toHaveBeenCalledTimes(1);
		expect(brandAuditWeeklyRescanMock).not.toHaveBeenCalled();
		expect(brandAuditCycleAlertsMock).not.toHaveBeenCalled();
		expect(fuzzingScanMock).not.toHaveBeenCalled();
		expect(scheduledMock).not.toHaveBeenCalled();
	});

	it('d. rejection in handleTenantCycleAlerts does NOT prevent the other two handlers from being scheduled', async () => {
		// Each handler is dispatched via its own ctx.waitUntil. Even when the
		// Tenant alert sweep rejects, the other two waitUntil chains have
		// already been registered before the rejection surfaces. The scheduled
		// dispatch in `src/index.ts` runs all three statements synchronously,
		// so all three mocks are observably called.
		brandAuditCycleAlertsMock.mockImplementationOnce(async () => {
			throw new Error('tenant alert sweep boom');
		});

		// `waitOnExecutionContext` rethrows aggregated waitUntil rejections,
		// so we tolerate either resolved or rejected outcome — the load-bearing
		// behaviour is "fuzzing + scheduled both saw their call".
		try {
			await runCron('*/15 * * * *');
		} catch {
			// Rejection swallowed — the assertions below verify isolation.
		}

		expect(fuzzingScanMock).toHaveBeenCalledTimes(1);
		expect(scheduledMock).toHaveBeenCalledTimes(1);
		expect(brandAuditCycleAlertsMock).toHaveBeenCalledTimes(1);
	});
});
