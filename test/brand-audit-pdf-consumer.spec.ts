// SPDX-License-Identifier: BUSL-1.1
//
// Behaviour of the brand-audit PDF queue consumer (src/queue/brand-audit-pdf-consumer.ts):
// the per-message verdict (ack vs retry) and the batch loop that turns each verdict into
// message.ack() / message.retry(). D1, R2 and the renderer are the only mocked boundaries.

import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => vi.restoreAllMocks());

const VALID = { auditId: 'audit-1', target: 'example.com', format: 'both' as const };
const PDF_BYTES = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

interface Fixture {
	row: { result_json: string | null; pdf_r2_key: string | null } | null;
	selectThrows?: boolean;
	updateThrows?: boolean;
}

function makeDeps(fx: Fixture, overrides: { putThrows?: boolean; renderThrows?: boolean } = {}) {
	const updateRun = vi.fn(async () => {
		if (fx.updateThrows) throw new Error('D1 update failed');
		return { success: true };
	});
	const updateBind = vi.fn(() => ({ run: updateRun }));
	const prepare = vi.fn((sql: string) => {
		if (sql.startsWith('SELECT')) {
			return {
				bind: () => ({
					first: async () => {
						if (fx.selectThrows) throw new Error('D1 select failed');
						return fx.row;
					},
				}),
			};
		}
		return { bind: updateBind };
	});
	const put = vi.fn(async () => {
		if (overrides.putThrows) throw new Error('R2 put failed');
		return {} as R2Object;
	});
	const renderPdf = vi.fn(async () => {
		if (overrides.renderThrows) throw new Error('render failed');
		return PDF_BYTES;
	});
	return {
		deps: {
			db: { prepare } as unknown as D1Database,
			bucket: { put } as unknown as R2Bucket,
			serverVersion: '0.0.0-test',
			now: () => 1234,
			renderPdf,
		},
		put,
		renderPdf,
		updateBind,
	};
}

const READY_ROW = { result_json: JSON.stringify({ category: 'brand_audit', passed: true, score: 90, findings: [] }), pdf_r2_key: null };

describe('processBrandAuditPdfMessage', () => {
	it('acks and persists nothing for a malformed payload (unrecoverable by retry)', async () => {
		const { processBrandAuditPdfMessage } = await import('../src/queue/brand-audit-pdf-consumer');
		const { deps, put, renderPdf } = makeDeps({ row: READY_ROW });
		expect(await processBrandAuditPdfMessage({ auditId: '', target: 'x', format: 'json' }, deps)).toBe('ack');
		expect(await processBrandAuditPdfMessage({ auditId: 'a', target: 'x', format: 'pdf' }, deps)).toBe('ack');
		expect(renderPdf).not.toHaveBeenCalled();
		expect(put).not.toHaveBeenCalled();
	});

	it('retries when the D1 target lookup throws', async () => {
		const { processBrandAuditPdfMessage } = await import('../src/queue/brand-audit-pdf-consumer');
		const { deps, renderPdf } = makeDeps({ row: null, selectThrows: true });
		expect(await processBrandAuditPdfMessage(VALID, deps)).toBe('retry');
		expect(renderPdf).not.toHaveBeenCalled();
	});

	it('acks without rendering when the target row is missing', async () => {
		const { processBrandAuditPdfMessage } = await import('../src/queue/brand-audit-pdf-consumer');
		const { deps, renderPdf } = makeDeps({ row: null });
		expect(await processBrandAuditPdfMessage(VALID, deps)).toBe('ack');
		expect(renderPdf).not.toHaveBeenCalled();
	});

	it('is idempotent: acks without re-rendering or re-writing R2 when pdf_r2_key is already set', async () => {
		const { processBrandAuditPdfMessage } = await import('../src/queue/brand-audit-pdf-consumer');
		const { deps, put, renderPdf } = makeDeps({ row: { ...READY_ROW, pdf_r2_key: 'audits/audit-1/example.com.pdf' } });
		expect(await processBrandAuditPdfMessage(VALID, deps)).toBe('ack');
		expect(renderPdf).not.toHaveBeenCalled();
		expect(put).not.toHaveBeenCalled();
	});

	it('acks without rendering when result_json is not yet populated', async () => {
		const { processBrandAuditPdfMessage } = await import('../src/queue/brand-audit-pdf-consumer');
		const { deps, renderPdf } = makeDeps({ row: { result_json: null, pdf_r2_key: null } });
		expect(await processBrandAuditPdfMessage(VALID, deps)).toBe('ack');
		expect(renderPdf).not.toHaveBeenCalled();
	});

	it('acks without rendering when result_json is not valid JSON', async () => {
		const { processBrandAuditPdfMessage } = await import('../src/queue/brand-audit-pdf-consumer');
		const { deps, renderPdf } = makeDeps({ row: { result_json: '{not json', pdf_r2_key: null } });
		expect(await processBrandAuditPdfMessage(VALID, deps)).toBe('ack');
		expect(renderPdf).not.toHaveBeenCalled();
	});

	it('retries when rendering throws, before touching R2', async () => {
		const { processBrandAuditPdfMessage } = await import('../src/queue/brand-audit-pdf-consumer');
		const { deps, put } = makeDeps({ row: READY_ROW }, { renderThrows: true });
		expect(await processBrandAuditPdfMessage(VALID, deps)).toBe('retry');
		expect(put).not.toHaveBeenCalled();
	});

	it('retries when the R2 put throws, before flagging pdf_r2_key', async () => {
		const { processBrandAuditPdfMessage } = await import('../src/queue/brand-audit-pdf-consumer');
		const { deps, updateBind } = makeDeps({ row: READY_ROW }, { putThrows: true });
		expect(await processBrandAuditPdfMessage(VALID, deps)).toBe('retry');
		expect(updateBind).not.toHaveBeenCalled();
	});

	it('retries when flagging pdf_r2_key fails (the PDF is already in R2; idempotency makes the redelivery a no-op)', async () => {
		const { processBrandAuditPdfMessage } = await import('../src/queue/brand-audit-pdf-consumer');
		const { deps, put } = makeDeps({ row: READY_ROW, updateThrows: true });
		expect(await processBrandAuditPdfMessage(VALID, deps)).toBe('retry');
		expect(put).toHaveBeenCalledTimes(1);
	});

	it('renders, writes audits/{auditId}/{target}.pdf to R2 and records the key, then acks', async () => {
		const { processBrandAuditPdfMessage } = await import('../src/queue/brand-audit-pdf-consumer');
		const { deps, put, renderPdf, updateBind } = makeDeps({ row: READY_ROW });
		expect(await processBrandAuditPdfMessage(VALID, deps)).toBe('ack');
		expect(renderPdf).toHaveBeenCalledWith(expect.objectContaining({ category: 'brand_audit' }), 'example.com', {
			serverVersion: '0.0.0-test',
			now: deps.now,
		});
		expect(put).toHaveBeenCalledWith('audits/audit-1/example.com.pdf', PDF_BYTES);
		expect(updateBind).toHaveBeenCalledWith('audits/audit-1/example.com.pdf', 1234, 'audit-1', 'example.com');
	});
});

describe('handleBrandAuditPdfQueue', () => {
	function message(body: unknown) {
		return { body, ack: vi.fn(), retry: vi.fn() };
	}

	it('acks completed messages and retries failed ones, one verdict per message in order', async () => {
		const { handleBrandAuditPdfQueue } = await import('../src/queue/brand-audit-pdf-consumer');
		const ok = message(VALID);
		const malformed = message({ nope: true });
		const failing = message({ ...VALID, target: 'fails.example' });
		// First lookup succeeds; the last message's lookup throws.
		let call = 0;
		const prepare = vi.fn((sql: string) => {
			if (sql.startsWith('SELECT')) {
				call += 1;
				const thisCall = call;
				return {
					bind: () => ({
						first: async () => {
							if (thisCall === 2) throw new Error('D1 select failed');
							return READY_ROW;
						},
					}),
				};
			}
			return { bind: () => ({ run: async () => ({ success: true }) }) };
		});
		const deps = {
			db: { prepare } as unknown as D1Database,
			bucket: { put: vi.fn(async () => ({}) as R2Object) } as unknown as R2Bucket,
			serverVersion: '0.0.0-test',
			renderPdf: vi.fn(async () => PDF_BYTES),
		};

		await handleBrandAuditPdfQueue({ messages: [ok, malformed, failing] } as unknown as MessageBatch<unknown>, deps);

		expect(ok.ack).toHaveBeenCalledTimes(1);
		expect(ok.retry).not.toHaveBeenCalled();
		expect(malformed.ack).toHaveBeenCalledTimes(1); // malformed -> ack, never retried
		expect(malformed.retry).not.toHaveBeenCalled();
		expect(failing.retry).toHaveBeenCalledTimes(1);
		expect(failing.ack).not.toHaveBeenCalled();
	});

	it('does nothing for an empty batch', async () => {
		const { handleBrandAuditPdfQueue } = await import('../src/queue/brand-audit-pdf-consumer');
		const prepare = vi.fn();
		await handleBrandAuditPdfQueue({ messages: [] } as unknown as MessageBatch<unknown>, {
			db: { prepare } as unknown as D1Database,
			bucket: {} as R2Bucket,
			serverVersion: '0.0.0-test',
		});
		expect(prepare).not.toHaveBeenCalled();
	});
});
