// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos D: scanner-queue poison messages, DLQ-write failure, oversized
 * persist errors, and AE emit failure.
 *
 * Targets `src/tenants/queue-consumer.ts` (`processScanMessage`,
 * `deadLetterMessage` → `writeDlqRow`, `MAX_ATTEMPTS`, `ScanQueueMessageSchema`)
 * and the `queue:` export in `src/index.ts` (`emitQueueBatchEvent`).
 *
 * Mock-D1 / MessageBatch patterns are copied in-file from
 * `test/chaos/tenant-queue.chaos.test.ts` and
 * `test/tenants/queue-consumer.integration.test.ts` (not edited).
 *
 * Hypothesis phrasing and the negative control that would have caught a
 * regression for each are posted as SQ-191 ticket comments (testing-methodology
 * principle 8) rather than duplicated here.
 *
 * H1 was originally PARTIALLY FALSIFIED (SQ-191): `ScanQueueMessageSchema.parse`
 * failures never reached `resolveTenant` or `writeDlqRow` — a schema failure
 * always just acked and dropped the message, regardless of how resolvable the
 * raw body looked, and without even a structured log naming the cause.
 *
 * SQ-196 closes that gap via `handlePoisonMessage`: every schema failure now
 * emits one structured `tenant_queue_poison_message` log carrying the zod
 * issue paths (never the raw body). It then attempts a lenient recovery parse
 * of just `{ sub_tenant_id, cycle_id, domain }` (`PoisonRecoverySchema`,
 * `.passthrough()`); when all three recover AND the tenant resolves, it writes
 * the standard `queue_dlq` row via `deadLetterMessage` with reason
 * `schema_invalid:<first issue path>`. A message that fails to recover (or
 * whose tenant doesn't resolve) is logged and dropped, same as before. Neither
 * branch ever retries — a malformed producer payload does not become valid by
 * waiting. See the H1 tests below for the corrected, measured behaviour.
 *
 * H5's "parseTenantScanSnapshot throws" is corrected to `toTenantScanSnapshot`
 * (`src/tenants/scan-snapshot.ts`) — `parseTenantScanSnapshot` only parses a
 * previously-persisted `result_json` column during the fingerprint pre-flight
 * and is written to never throw (it returns `null` for anything unusable, and
 * its only caller wraps it in a best-effort try/catch). `toTenantScanSnapshot`
 * is the function actually invoked on a fresh `handleToolsCall` result via the
 * `scanResultCapture` hook, and it has no such guard — an unexpected result
 * shape throws a plain TypeError, which is what this file exercises.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { env, createExecutionContext } from 'cloudflare:test';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';
import { emitScanCapture } from '../helpers/scan-capture';

const handleToolsCallMock = vi.hoisted(() =>
	vi.fn<(...args: unknown[]) => Promise<{ isError?: boolean; content: unknown[] }>>(),
);

vi.mock('../../src/handlers/tools', () => ({
	handleToolsCall: handleToolsCallMock,
}));

const TEST_TENANT_ID = 'tenant-1';
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';
const REGISTRY_LOOKUP_SQL =
	'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';
// Cheap single-column active-flag probe run by resolveTenant on a cache HIT (3.17.2,
// FINDING #2) — needed only when a test resolves the same tenant more than once.
const ACTIVE_PROBE_SQL = 'SELECT active FROM sub_tenants WHERE id = ? LIMIT 1';
const SCANS_INSERT_SQL =
	'INSERT INTO scans (id, domain, scan_at, score, grade, maturity_stage, finding_count, result_json, cycle_id) ' +
	'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
const FINDINGS_INSERT_SQL =
	'INSERT INTO findings (id, scan_id, domain, category, severity, title, detail, metadata) ' +
	'VALUES (?, ?, ?, ?, ?, ?, ?, ?)';

type RecordedCall = { sql: string; binds: unknown[] };

interface MakeMockD1Options {
	rowsBySql?: Record<string, unknown[]>;
	throwOnSql?: Set<string>;
	/**
	 * Throw a specific error on the FIRST `.run()` for the given SQL, then
	 * succeed on every subsequent call for that same SQL string. Models a
	 * transient/one-shot D1 write failure (e.g. `persistScan`'s own INSERT
	 * failing once while `writeDlqRow`'s later insert of the same SQL still
	 * succeeds) without the blanket always-throw semantics of `throwOnSql`.
	 */
	throwOnRunOnce?: Map<string, Error>;
}

function makeMockD1(opts: MakeMockD1Options = {}) {
	const rowsBySql = opts.rowsBySql ?? {};
	const throwOnSql = opts.throwOnSql ?? new Set<string>();
	const throwOnRunOnce = opts.throwOnRunOnce ?? new Map<string, Error>();
	const calls: RecordedCall[] = [];
	const db: D1Database = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					calls.push({ sql, binds });
					if (throwOnSql.has(sql)) throw new Error('d1_first_failed');
					const rows = rowsBySql[sql] ?? [];
					return (rows[0] as T | undefined) ?? null;
				},
				async all<T = unknown>() {
					calls.push({ sql, binds });
					if (throwOnSql.has(sql)) throw new Error('d1_all_failed');
					const rows = rowsBySql[sql] ?? [];
					return { results: rows as T[], success: true, meta: {} } as unknown as D1Result<T>;
				},
				async run() {
					calls.push({ sql, binds });
					if (throwOnSql.has(sql)) throw new Error('d1_run_failed');
					const onceErr = throwOnRunOnce.get(sql);
					if (onceErr) {
						throwOnRunOnce.delete(sql);
						throw onceErr;
					}
					return {
						success: true,
						meta: { changes: 1, last_row_id: 0, duration: 0, rows_read: 0, rows_written: 1, size_after: 0 },
					} as unknown as D1Response;
				},
				async raw() {
					calls.push({ sql, binds });
					return [] as unknown[];
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
		async batch<T = unknown>(stmts: D1PreparedStatement[]): Promise<D1Result<T>[]> {
			const out: D1Result<T>[] = [];
			for (const s of stmts) {
				const r = (await (s as unknown as { run: () => Promise<unknown> }).run()) as D1Result<T>;
				out.push(r);
			}
			return out;
		},
		async exec() {
			return { count: 0, duration: 0 } as unknown as D1ExecResult;
		},
		dump() {
			throw new Error('not implemented');
		},
		withSession() {
			throw new Error('not implemented');
		},
	} as unknown as D1Database;
	return { db, calls };
}

function buildEnv(overrides: Record<string, unknown> = {}) {
	const registry = makeMockD1({
		rowsBySql: {
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
			[ACTIVE_PROBE_SQL]: [{ active: 1 }],
		},
	});
	const tenant = makeMockD1();
	const customEnv = {
		...env,
		TENANT_REGISTRY_DB: registry.db,
		[TEST_TENANT_BINDING]: tenant.db,
		...overrides,
	};
	return { customEnv, registryCalls: registry.calls, tenantCalls: tenant.calls };
}

function makeCtx() {
	const ctx = createExecutionContext();
	return { waitUntil: (p: Promise<unknown>) => ctx.waitUntil(p) };
}

function makeMessageBatch(bodies: unknown[], attempts?: number[]) {
	const acks: number[] = [];
	const retries: number[] = [];
	const messages = bodies.map((body, i) => ({
		id: `msg-${i}`,
		body,
		attempts: attempts?.[i] ?? 1,
		timestamp: new Date(),
		ack: () => acks.push(i),
		retry: () => retries.push(i),
	}));
	const batch = {
		queue: 'BV_SCANNER_QUEUE',
		messages,
		ackAll: () => {
			for (let i = 0; i < messages.length; i++) acks.push(i);
		},
		retryAll: () => {
			for (let i = 0; i < messages.length; i++) retries.push(i);
		},
	} as unknown as MessageBatch<unknown>;
	return { batch, acks, retries };
}

beforeEach(() => {
	resetTenantResolverCache();
	handleToolsCallMock.mockReset();
});
afterEach(() => {
	resetTenantResolverCache();
	vi.restoreAllMocks();
});

describe('H1: poison messages (schema failures) are always acked; DLQ-recoverable ones write a schema_invalid marker', () => {
	const unrecoverableBodies: Array<{ name: string; body: unknown }> = [
		{ name: 'non-JSON-shaped string body', body: 'not a valid message at all' },
		{ name: 'null body', body: null },
		{
			name: 'wrong field type for domain (fails the lenient recovery too)',
			body: { cycle_id: 'cycle_poison_1', sub_tenant_id: TEST_TENANT_ID, domain: 12345 },
		},
	];

	for (const { name, body } of unrecoverableBodies) {
		it(`acks a ${name} without calling handleToolsCall or touching any D1`, async () => {
			const { processScanMessage } = await import('../../src/tenants/queue-consumer');
			const { customEnv, registryCalls, tenantCalls } = buildEnv();

			const outcome = await processScanMessage(body, 1, customEnv, makeCtx());

			expect(outcome).toBe('ack');
			expect(handleToolsCallMock).not.toHaveBeenCalled();
			// None of the three identifying fields recover cleanly under
			// PoisonRecoverySchema, so no DLQ write is attempted — zero calls on
			// both D1s proves the only durable trace is the poison-message log.
			expect(registryCalls).toHaveLength(0);
			expect(tenantCalls).toHaveLength(0);
		});
	}

	it('writes a queue_dlq row with a schema_invalid reason when the three identifying fields recover and the tenant resolves', async () => {
		// Fails ScanQueueMessageSchema (.strict()) on the unrecognised key, but
		// sub_tenant_id/cycle_id/domain are all individually well-formed — the
		// exact "syntactically valid, resolvable" shape H1 originally falsified.
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv, registryCalls, tenantCalls } = buildEnv();
		const body = { cycle_id: 'cycle_poison_2', sub_tenant_id: TEST_TENANT_ID, domain: 'example.com', unexpected: 'x' };

		const outcome = await processScanMessage(body, 1, customEnv, makeCtx());

		expect(outcome).toBe('ack');
		expect(handleToolsCallMock).not.toHaveBeenCalled();
		expect(registryCalls.length).toBeGreaterThan(0);

		const findingInserts = tenantCalls.filter((c) => c.sql === FINDINGS_INSERT_SQL);
		expect(findingInserts).toHaveLength(1);
		expect(findingInserts[0]!.binds[5]).toBe('queue_dlq');
		const detail = findingInserts[0]!.binds[6] as string;
		expect(detail).toMatch(/^schema_invalid:/);

		// score is null, not 0 — the domain was never actually measured.
		const scanInserts = tenantCalls.filter((c) => c.sql === SCANS_INSERT_SQL);
		expect(scanInserts).toHaveLength(1);
		expect(scanInserts[0]!.binds[3]).toBeNull();
	});

	it('never retries a poison message and never increments/tracks attempts across redelivery', async () => {
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv, tenantCalls } = buildEnv();
		const body = { cycle_id: 'cycle_poison_redelivery', sub_tenant_id: TEST_TENANT_ID, domain: [] };

		// Simulate three redeliveries at increasing attempt counts. If the code
		// tracked/incremented attempts for a poison message anywhere, some call
		// here would diverge from 'ack' or touch D1 to persist that state. The
		// domain (an array) still fails PoisonRecoverySchema, so this stays
		// unrecoverable across all three.
		for (const attempts of [1, 2, 3]) {
			const outcome = await processScanMessage(body, attempts, customEnv, makeCtx());
			expect(outcome).toBe('ack');
		}
		expect(tenantCalls).toHaveLength(0);
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});
});

describe('H2: an oversized, injection-shaped persistScan error is bounded and safely carried into the DLQ finding', () => {
	it('bounds a 5KB error message with quotes/newlines/SQL-fragment content on the last attempt, still valid JSON', async () => {
		const injectionFragment = `'; DROP TABLE scans; --`;
		const rawErrorMessage = `${injectionFragment}\nsecond line with 'quotes' and\ttabs\n` + 'x'.repeat(5000);
		expect(rawErrorMessage.length).toBeGreaterThan(5000);

		class D1OversizedError extends Error {
			constructor(message: string) {
				super(message);
				this.name = 'D1_ERROR';
			}
		}

		handleToolsCallMock.mockImplementation(async (_call, _kv, runtimeOptions) => {
			emitScanCapture(runtimeOptions, 'example.com', { score: 90, grade: 'A', findings: [] });
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const { processScanMessage, MAX_ATTEMPTS } = await import('../../src/tenants/queue-consumer');
		const registry = makeMockD1({
			rowsBySql: {
				[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'x', active: 1 }],
			},
		});
		// Fails only the FIRST SCANS_INSERT_SQL run (persistScan's own insert) —
		// writeDlqRow's later insert of the same SQL must still succeed.
		const tenant = makeMockD1({
			throwOnRunOnce: new Map([[SCANS_INSERT_SQL, new D1OversizedError(rawErrorMessage)]]),
		});
		const customEnv = { ...env, TENANT_REGISTRY_DB: registry.db, [TEST_TENANT_BINDING]: tenant.db };
		const msg = { cycle_id: 'cycle_oversized_error', sub_tenant_id: TEST_TENANT_ID, domain: 'example.com' };

		const outcome = await processScanMessage(msg, MAX_ATTEMPTS, customEnv, makeCtx());
		expect(outcome).toBe('ack');

		const findingInserts = tenant.calls.filter((c) => c.sql === FINDINGS_INSERT_SQL);
		expect(findingInserts).toHaveLength(1);
		const detail = findingInserts[0]!.binds[6] as string;
		const metadataRaw = findingInserts[0]!.binds[7] as string;

		expect(detail).toContain('persist_failed');
		expect(detail).toContain('D1_ERROR');
		// Bounded: MAX_PERSIST_ERROR_MESSAGE_LENGTH (200, local to the source
		// module) plus the short 'persist_failed:D1_ERROR:' prefix — nowhere
		// near the 5KB+ raw message.
		expect(detail.length).toBeLessThan(300);
		expect(detail.length).toBeLessThan(rawErrorMessage.length / 10);
		// Control characters (the injected newlines) are stripped, not carried
		// raw into a log/finding string. Tabs are intentionally preserved by
		// `sanitizeString` (see its `except tab` comment), so only newlines are
		// asserted here.
		expect(detail).not.toMatch(/\n/);
		// No raw SQL of the failing statement leaks into the finding.
		expect(detail).not.toContain('INSERT INTO scans');
		expect(detail).not.toContain(SCANS_INSERT_SQL);

		// metadata is still valid JSON that round-trips, and matches the bounded
		// detail exactly (SQ-179's contract) even though the source error had
		// single quotes and a DROP TABLE fragment in it.
		const metadata = JSON.parse(metadataRaw) as { source: string; reason: string };
		expect(metadata.reason).toBe(detail);
		expect(metadata.source).toBe('queue_dlq');
	});
});

describe('H3: writeDlqRow itself throwing on the last attempt neither crashes the batch nor drops siblings', () => {
	it('retries the message whose own DLQ write fails while still acking healthy siblings in the same batch', async () => {
		handleToolsCallMock.mockImplementation(async (call, _kv, runtimeOptions) => {
			const domain = (call as { arguments: { domain: string } }).arguments.domain;
			if (domain === 'poison-dlq.example.com') {
				return { isError: true, content: [{ type: 'text', text: 'tool_failed' }] };
			}
			// findings: [] deliberately — keeps the healthy siblings' persistFindings
			// call from ever running, so the FINDINGS_INSERT_SQL throw below is
			// isolated to the poison message's own writeDlqRow call.
			emitScanCapture(runtimeOptions, domain, { score: 90, grade: 'A', findings: [] });
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const { handleScanQueue, MAX_ATTEMPTS } = await import('../../src/tenants/queue-consumer');
		const registry = makeMockD1({
			rowsBySql: {
				[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'x', active: 1 }],
				[ACTIVE_PROBE_SQL]: [{ active: 1 }],
			},
		});
		const tenant = makeMockD1({ throwOnSql: new Set([FINDINGS_INSERT_SQL]) });
		const customEnv = { ...env, TENANT_REGISTRY_DB: registry.db, [TEST_TENANT_BINDING]: tenant.db };
		const ctx = createExecutionContext();

		const bodies = [
			{ cycle_id: 'cycle_h3', sub_tenant_id: TEST_TENANT_ID, domain: 'poison-dlq.example.com' },
			{ cycle_id: 'cycle_h3', sub_tenant_id: TEST_TENANT_ID, domain: 'healthy-a.example.com' },
			{ cycle_id: 'cycle_h3', sub_tenant_id: TEST_TENANT_ID, domain: 'healthy-b.example.com' },
		];
		const { batch, acks, retries } = makeMessageBatch(bodies, [MAX_ATTEMPTS, 1, 1]);

		await expect(handleScanQueue(batch, customEnv, ctx)).resolves.toBeUndefined();

		// Observed disposition: `deadLetterMessage`'s own try/catch converts a
		// writeDlqRow throw into 'retry' (never a bare re-throw that could crash
		// the surrounding for-loop in handleScanQueue) — documented here as the
		// code's actual choice, not an invented one.
		expect(retries).toEqual([0]);
		expect(acks).toEqual([1, 2]);
		expect(handleToolsCallMock).toHaveBeenCalledTimes(3);
	});
});

describe('H4: an Analytics Engine emit failure on the queue: batch handler never changes ack/retry disposition', () => {
	it('still resolves and acks the message when MCP_ANALYTICS.writeDataPoint throws in emitQueueBatchEvent', async () => {
		handleToolsCallMock.mockImplementation(async (_call, _kv, runtimeOptions) => {
			emitScanCapture(runtimeOptions, 'example.com', { score: 90, grade: 'A', findings: [] });
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const worker = (await import('../../src/index')).default;
		const registry = makeMockD1({
			rowsBySql: {
				[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'x', active: 1 }],
			},
		});
		const tenant = makeMockD1();
		const throwingDataset = {
			writeDataPoint: vi.fn(() => {
				throw new Error('ae_write_failed');
			}),
		};
		const customEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
			MCP_ANALYTICS: throwingDataset,
		} as unknown as Parameters<typeof worker.queue>[1];
		const ctx = createExecutionContext();
		const { batch, acks, retries } = makeMessageBatch([
			{ cycle_id: 'cycle_h4', sub_tenant_id: TEST_TENANT_ID, domain: 'example.com' },
		]);

		await expect(worker.queue(batch, customEnv, ctx)).resolves.toBeUndefined();

		expect(acks).toEqual([0]);
		expect(retries).toEqual([]);
		// Proves the AE call actually ran (and threw) rather than being skipped —
		// the resolved/acked assertion above is only meaningful with this.
		expect(throwingDataset.writeDataPoint).toHaveBeenCalled();
	});
});

describe('H5: a snapshot-projection failure (toTenantScanSnapshot throws) never silently acks as success', () => {
	// A result missing `.score` entirely — `toTenantScanSnapshot` dereferences
	// `result.score.overall` unconditionally and has no try/catch of its own,
	// so this throws a plain TypeError synchronously from inside the
	// scanResultCapture hook.
	const buildBadResult = () => ({ domain: 'example.com' }) as unknown;

	it('retries on a non-final attempt without ever persisting the rejected result', async () => {
		handleToolsCallMock.mockImplementation(async (_call, _kv, runtimeOptions) => {
			const ro = runtimeOptions as { scanResultCapture?: (r: unknown) => void };
			ro.scanResultCapture?.(buildBadResult());
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv, tenantCalls } = buildEnv();
		const msg = { cycle_id: 'cycle_h5_retry', sub_tenant_id: TEST_TENANT_ID, domain: 'example.com' };

		const outcome = await processScanMessage(msg, 1, customEnv, makeCtx());

		expect(outcome).toBe('retry');
		expect(tenantCalls.filter((c) => c.sql === SCANS_INSERT_SQL)).toHaveLength(0);
	});

	it('dead-letters with a distinguishable DLQ marker on the last attempt, not a bare success ack', async () => {
		handleToolsCallMock.mockImplementation(async (_call, _kv, runtimeOptions) => {
			const ro = runtimeOptions as { scanResultCapture?: (r: unknown) => void };
			ro.scanResultCapture?.(buildBadResult());
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const { processScanMessage, MAX_ATTEMPTS } = await import('../../src/tenants/queue-consumer');
		const registry = makeMockD1({
			rowsBySql: {
				[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'x', active: 1 }],
			},
		});
		const tenant = makeMockD1();
		const customEnv = { ...env, TENANT_REGISTRY_DB: registry.db, [TEST_TENANT_BINDING]: tenant.db };
		const msg = { cycle_id: 'cycle_h5_last', sub_tenant_id: TEST_TENANT_ID, domain: 'example.com' };

		const outcome = await processScanMessage(msg, MAX_ATTEMPTS, customEnv, makeCtx());
		expect(outcome).toBe('ack');

		// It went through the DLQ path (a 'queue_dlq' finding + a null-score scan
		// row) rather than silently completing as if the scan had succeeded.
		const findingInserts = tenant.calls.filter((c) => c.sql === FINDINGS_INSERT_SQL);
		expect(findingInserts).toHaveLength(1);
		expect(findingInserts[0]!.binds[5]).toBe('queue_dlq');
		const scanInserts = tenant.calls.filter((c) => c.sql === SCANS_INSERT_SQL);
		expect(scanInserts).toHaveLength(1);
		expect(scanInserts[0]!.binds[3]).toBeNull();
	});
});

describe('H6: the queue_batch AE row folds scanner-queue poison acks into failureCount (SQ-196)', () => {
	it('reports failureCount = poison-message count, not the whole batch, for a mixed batch that never throws', async () => {
		handleToolsCallMock.mockImplementation(async (call, _kv, runtimeOptions) => {
			const domain = (call as { arguments: { domain: string } }).arguments.domain;
			emitScanCapture(runtimeOptions, domain, { score: 90, grade: 'A', findings: [] });
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const worker = (await import('../../src/index')).default;
		const { customEnv } = buildEnv();
		const writeDataPoint = vi.fn();
		const envWithSpy = { ...customEnv, MCP_ANALYTICS: { writeDataPoint } };
		const ctx = createExecutionContext();
		const { batch, acks, retries } = makeMessageBatch([
			{ cycle_id: 'cycle_h6', sub_tenant_id: TEST_TENANT_ID, domain: 'healthy-a.example.com' },
			'not a valid message at all',
			{ cycle_id: 'cycle_h6', sub_tenant_id: TEST_TENANT_ID, domain: 'healthy-b.example.com' },
		]);

		await expect(worker.queue(batch, envWithSpy as unknown as Parameters<typeof worker.queue>[1], ctx)).resolves.toBeUndefined();

		// All three ack — the two healthy scans, and the poison message, which
		// is always acked (never retried) regardless of DLQ recoverability.
		expect(acks).toEqual([0, 1, 2]);
		expect(retries).toEqual([]);

		const queueBatchCall = writeDataPoint.mock.calls.find(
			(call) => (call[0] as { indexes?: string[] }).indexes?.[0] === 'queue_batch',
		);
		expect(queueBatchCall).toBeDefined();
		const point = queueBatchCall![0] as { doubles: number[] };
		// doubles: [durationMs, failureCount, messageCount] (emitQueueBatchEvent).
		// Exactly the one poison ack counts as a failure — the two successful
		// scans must NOT inflate it, and the whole-batch-throw shortcut (which
		// would report messageCount here) never fires since nothing threw.
		expect(point.doubles[1]).toBe(1);
		expect(point.doubles[2]).toBe(3);
	});
});
