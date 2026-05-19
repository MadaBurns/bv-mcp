// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the brand-audit PDF queue consumer.
 *
 * Each message: { auditId, target, format }. The consumer:
 *   1. Reads brand_audit_targets.result_json from D1
 *   2. Skips (ack) when result_json is missing (race: parent consumer not yet
 *      flushed, or status='failed')
 *   3. Skips (ack) when pdf_r2_key is already set (idempotency / duplicate delivery)
 *   4. Renders PDF via the injected `renderPdf` (pure pdf-lib function by default)
 *   5. Writes to R2 at `audits/{auditId}/{target}.pdf`
 *   6. Updates brand_audit_targets.pdf_r2_key with the object key
 *
 * Post-2026-05-19 redesign: rendering is in-process pdf-lib (no service binding,
 * no external auth). Tests inject a stub `renderPdf` to keep the consumer
 * boundary the same shape across the redesign.
 *
 * Mocked: D1 (recording fake), R2 bucket, renderPdf stub.
 */

import { describe, it, expect, vi } from 'vitest';
import type { BrandAuditPdfConsumerDeps } from '../../src/queue/brand-audit-pdf-consumer';

interface D1Call {
	sql: string;
	binds: unknown[];
}

function makeMockD1(opts: { target?: { result_json: string | null; pdf_r2_key: string | null } | null; throwOnUpdate?: boolean } = {}) {
	const calls: D1Call[] = [];
	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first() {
					calls.push({ sql, binds });
					if (sql.includes('FROM brand_audit_targets')) return opts.target ?? null;
					return null;
				},
				async run() {
					calls.push({ sql, binds });
					if (opts.throwOnUpdate && sql.startsWith('UPDATE')) throw new Error('d1_update_failed');
					return { success: true, meta: {} };
				},
				async all() {
					calls.push({ sql, binds });
					return { results: [], success: true, meta: {} };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return { db, calls };
}

function makeMockR2() {
	const writes: { key: string; bytes: Uint8Array }[] = [];
	const bucket = {
		async put(key: string, value: Uint8Array | ArrayBuffer) {
			const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
			writes.push({ key, bytes });
			return { key, version: 'v1' };
		},
	} as unknown as R2Bucket;
	return { bucket, writes };
}

function fakePdf(): Uint8Array {
	return new TextEncoder().encode('%PDF-1.4\nfake\n%%EOF');
}

function fakeResult() {
	return {
		category: 'brand_discovery',
		score: 100,
		findings: [
			{ category: 'brand_discovery', title: 'apple.net', severity: 'info', detail: '', metadata: { candidate: 'apple.net', bucket: 'consolidated', registrar: 'MarkMonitor', registrarSource: 'rdap', signals: ['ns'], combinedConfidence: 0.95, reasons: [] } },
		],
	};
}

describe('processBrandAuditPdfMessage', () => {
	it('renders, writes to R2 at audits/{auditId}/{target}.pdf, updates pdf_r2_key', async () => {
		const { processBrandAuditPdfMessage } = await import('../../src/queue/brand-audit-pdf-consumer');
		const { db, calls } = makeMockD1({
			target: { result_json: JSON.stringify(fakeResult()), pdf_r2_key: null },
		});
		const { bucket, writes } = makeMockR2();
		const renderPdf = vi.fn().mockResolvedValue(fakePdf());

		const verdict = await processBrandAuditPdfMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'both' },
			{ db, bucket, serverVersion: '2.20.0', now: () => 0, renderPdf } as BrandAuditPdfConsumerDeps,
		);

		expect(verdict).toBe('ack');
		expect(renderPdf).toHaveBeenCalledOnce();
		expect(writes).toHaveLength(1);
		expect(writes[0].key).toBe('audits/aud-1/apple.com.pdf');
		expect(writes[0].bytes.byteLength).toBeGreaterThan(0);

		const update = calls.find((c) => c.sql.includes('UPDATE brand_audit_targets') && c.sql.includes('pdf_r2_key'));
		expect(update).toBeDefined();
		expect(update?.binds).toContain('audits/aud-1/apple.com.pdf');
	});

	it('is idempotent: a duplicate delivery with pdf_r2_key already set ack()s without re-rendering', async () => {
		const { processBrandAuditPdfMessage } = await import('../../src/queue/brand-audit-pdf-consumer');
		const { db } = makeMockD1({
			target: { result_json: JSON.stringify(fakeResult()), pdf_r2_key: 'audits/aud-1/apple.com.pdf' },
		});
		const { bucket, writes } = makeMockR2();
		const renderPdf = vi.fn();

		const verdict = await processBrandAuditPdfMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'both' },
			{ db, bucket, serverVersion: '2.20.0', now: () => 0, renderPdf },
		);

		expect(verdict).toBe('ack');
		expect(renderPdf).not.toHaveBeenCalled();
		expect(writes).toHaveLength(0);
	});

	it('ack()s when target row has no result_json (race or upstream failure)', async () => {
		const { processBrandAuditPdfMessage } = await import('../../src/queue/brand-audit-pdf-consumer');
		const { db } = makeMockD1({
			target: { result_json: null, pdf_r2_key: null },
		});
		const { bucket } = makeMockR2();
		const renderPdf = vi.fn();

		const verdict = await processBrandAuditPdfMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'both' },
			{ db, bucket, serverVersion: '2.20.0', now: () => 0, renderPdf },
		);

		expect(verdict).toBe('ack');
		expect(renderPdf).not.toHaveBeenCalled();
	});

	it('signals retry when renderPdf throws (transient infrastructure failure)', async () => {
		const { processBrandAuditPdfMessage } = await import('../../src/queue/brand-audit-pdf-consumer');
		const { db } = makeMockD1({
			target: { result_json: JSON.stringify(fakeResult()), pdf_r2_key: null },
		});
		const { bucket } = makeMockR2();
		const renderPdf = vi.fn().mockRejectedValue(new Error('boom'));

		const verdict = await processBrandAuditPdfMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'both' },
			{ db, bucket, serverVersion: '2.20.0', now: () => 0, renderPdf },
		);

		expect(verdict).toBe('retry');
	});

	it('drops malformed messages without retrying forever', async () => {
		const { processBrandAuditPdfMessage } = await import('../../src/queue/brand-audit-pdf-consumer');
		const { db } = makeMockD1({});
		const { bucket } = makeMockR2();
		const renderPdf = vi.fn();

		const verdict = await processBrandAuditPdfMessage(
			{ wrong: 'shape' } as unknown,
			{ db, bucket, serverVersion: '2.20.0', now: () => 0, renderPdf },
		);

		expect(verdict).toBe('ack');
		expect(renderPdf).not.toHaveBeenCalled();
	});

	it('falls back to the default pdf-lib renderer when no renderPdf is injected', async () => {
		const { processBrandAuditPdfMessage } = await import('../../src/queue/brand-audit-pdf-consumer');
		const { db } = makeMockD1({
			target: { result_json: JSON.stringify(fakeResult()), pdf_r2_key: null },
		});
		const { bucket, writes } = makeMockR2();

		const verdict = await processBrandAuditPdfMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'both' },
			{ db, bucket, serverVersion: '2.20.0', now: () => 0 },
		);

		expect(verdict).toBe('ack');
		// Default renderer (pdf-lib) emits a real PDF.
		expect(writes).toHaveLength(1);
		expect(writes[0].bytes.byteLength).toBeGreaterThan(500);
		const header = new TextDecoder().decode(writes[0].bytes.slice(0, 5));
		expect(header).toBe('%PDF-');
	});
});
