// SPDX-License-Identifier: BUSL-1.1

/**
 * Integration tests for handleBrandAuditQueue — deep_scan branch routing and
 * error containment. Sociable: real handleBrandAuditQueue, createD1BrandAuditStepStore,
 * and runDeepScanFromStepStore all execute. Only D1 (DB boundary) and internalCall
 * (external tool/network boundary) are stubbed.
 *
 * Invariants pinned:
 *   1. phase='deep_scan' message is acked; internalCall is not invoked when
 *      csc_complement_fast is absent (runDeepScanFromStepStore exits early).
 *   2. When D1 throws inside runDeepScanFromStepStore, the message is STILL acked
 *      (the new try/catch in handleBrandAuditQueue contains the error).
 *   3. When csc_complement_fast IS present, internalCall is invoked for the anchor
 *      apex and the message is acked.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => vi.restoreAllMocks());

// ---------------------------------------------------------------------------
// Plain D1 stubs — vi.fn() only where we need to assert on call behaviour.
// ---------------------------------------------------------------------------

/** D1 stub where every SELECT returns null (no rows). */
function makeEmptyD1(): D1Database {
	const stmt = {
		bind() { return this; },
		async first() { return null; },
		async run() { return { meta: { changes: 0 } }; },
		async all() { return { results: [] }; },
	};
	return { prepare: () => stmt } as unknown as D1Database;
}

/** D1 stub where .first() always throws (simulates D1 read failure). */
function makeThrowingD1(): D1Database {
	function makeStmt() {
		return {
			bind() { return makeStmt(); },
			async first(): Promise<never> { throw new Error('D1_BUSY: database is locked'); },
			async run() { return { meta: { changes: 0 } }; },
			async all() { return { results: [] }; },
		};
	}
	return { prepare: () => makeStmt() } as unknown as D1Database;
}

/** D1 stub seeded with a csc_complement_fast row for the given auditId/target. */
function makeSeededD1(auditId: string, target: string, fastPayload: unknown): D1Database {
	const payloadJson = JSON.stringify(fastPayload);
	function makeStmt(boundArgs: unknown[] = []): ReturnType<typeof makeStmt> {
		return {
			bind(...args: unknown[]) { return makeStmt(args); },
			async first() {
				// SELECT brand_audit_steps binds [auditId, target, step].
				if (boundArgs[0] === auditId && boundArgs[1] === target && boundArgs[2] === 'csc_complement_fast') {
					return { audit_id: auditId, target, step: 'csc_complement_fast', status: 'completed', payload_json: payloadJson, error: null };
				}
				return null;
			},
			async run() { return { meta: { changes: 1 } }; },
			async all() { return { results: [] }; },
		};
	}
	return { prepare: () => makeStmt() } as unknown as D1Database;
}

/** Build a MessageBatch with one phase='deep_scan' message, returning vi.fn() ack/retry for assertion. */
function makeDeepScanBatch(auditId: string, target: string) {
	const ack = vi.fn();
	const retry = vi.fn();
	const batch = {
		messages: [{ body: { auditId, target, phase: 'deep_scan' }, ack, retry, id: 'msg-1', timestamp: new Date(), attempts: 1 }],
		queue: 'brand-audit-queue',
		retryAll: vi.fn(),
		ackAll: vi.fn(),
	} as unknown as MessageBatch<unknown>;
	return { batch, ack, retry };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('handleBrandAuditQueue — deep_scan branch', () => {
	it('acks message and skips internalCall when csc_complement_fast is absent', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const internalCall = vi.fn();
		const { batch, ack, retry } = makeDeepScanBatch('audit-1', 'ford.com');

		await handleBrandAuditQueue(batch, { db: makeEmptyD1(), internalCall });

		expect(ack).toHaveBeenCalledOnce();
		expect(retry).not.toHaveBeenCalled();
		expect(internalCall).not.toHaveBeenCalled();
	});

	it('acks message even when D1 throws inside runDeepScanFromStepStore (error containment)', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const { batch, ack, retry } = makeDeepScanBatch('audit-2', 'ford.com');

		await expect(handleBrandAuditQueue(batch, { db: makeThrowingD1() })).resolves.toBeUndefined();

		expect(ack).toHaveBeenCalledOnce();
		expect(retry).not.toHaveBeenCalled();
	});

	it('invokes internalCall for anchor apex when csc_complement_fast is seeded', async () => {
		const fastPayload = {
			viewVersion: 1,
			anchor: { apex: 'ford.com', primaryRegistrar: { family: 'csc corporate domains', name: 'CSC', ianaId: null }, managedByCsc: true },
			registrarPortfolio: { totalApexes: 1, byFamily: [{ family: 'csc corporate domains', count: 1, percent: 100, exampleApexes: ['ford.com'] }], offPortfolioCount: 0, offPortfolioApexes: [] },
			shadowItHighlights: [],
			defensiveRegistrations: { count: 0, examples: [], enrichmentStatus: 'ready' },
			postureSnapshot: { stage: 'pending', apexesScanned: 0, apexesTotal: 0, apexes: [], medianGrade: null, distribution: {} },
			deepScan: { stage: 'pending', apexesScanned: 0, apexesTotal: 0, danglingDns: [], danglingDnsTotal: 0, subdomainInventoryByApex: {} },
			generatedAt: '2026-05-22T00:00:00Z',
			reportId: 'csc_rpt_test',
		};

		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		// internalCall is the network/tool boundary — the correct mock point.
		const internalCall = vi.fn().mockResolvedValue({
			content: [],
			structured: { domain: 'ford.com', score: 80, grade: 'B+', categoryScores: {}, findings: [], totalSubdomains: 0, subdomains: [] },
		});
		const { batch, ack, retry } = makeDeepScanBatch('audit-3', 'ford.com');

		await handleBrandAuditQueue(batch, { db: makeSeededD1('audit-3', 'ford.com', fastPayload), internalCall });

		expect(internalCall).toHaveBeenCalled();
		expect((internalCall.mock.calls[0] as [string, { domain: string }])[1].domain).toBe('ford.com');
		expect(ack).toHaveBeenCalledOnce();
		expect(retry).not.toHaveBeenCalled();
	});
});
