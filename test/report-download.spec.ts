// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the authenticated /reports/ PDF download handler.
 * Mock D1 + R2 — the route's auth (bearer → keyHash) is exercised by the
 * middleware in index.ts; here we cover owner scoping, input validation,
 * and the R2 streaming response shape.
 */

import { describe, it, expect, vi } from 'vitest';

const AUDIT_ID = 'audit-123';
const OWNER = 'abcd1234abcd1234';
const TARGET = 'example.com';
const R2_KEY = `audits/${AUDIT_ID}/${TARGET}.pdf`;

function makeDb(row: { pdf_r2_key: string | null } | null) {
	const first = vi.fn().mockResolvedValue(row);
	const bind = vi.fn().mockReturnValue({ first });
	const prepare = vi.fn().mockReturnValue({ bind });
	return { db: { prepare } as unknown as D1Database, prepare, bind, first };
}

function makeBucket(object: { body: ReadableStream | null; size: number; httpEtag: string } | null) {
	const get = vi.fn().mockResolvedValue(object);
	return { bucket: { get } as unknown as R2Bucket, get };
}

function pdfObject(bytes = new Uint8Array([0x25, 0x50, 0x44, 0x46])) {
	return {
		body: new Response(bytes).body,
		size: bytes.length,
		httpEtag: '"etag-1"',
	};
}

async function run(auditId: string, target: string, ownerId: string, db: D1Database, bucket: R2Bucket) {
	const { handleReportDownload } = await import('../src/handlers/report-download');
	return handleReportDownload(auditId, target, ownerId, { db, bucket });
}

describe('handleReportDownload', () => {
	it('streams the PDF with correct headers for the owner', async () => {
		const { db, bind } = makeDb({ pdf_r2_key: R2_KEY });
		const { bucket, get } = makeBucket(pdfObject());

		const res = await run(AUDIT_ID, `${TARGET}.pdf`, OWNER, db, bucket);

		expect(res.status).toBe(200);
		expect(res.headers.get('Content-Type')).toBe('application/pdf');
		expect(res.headers.get('Content-Disposition')).toBe(`attachment; filename="${TARGET}.pdf"`);
		expect(res.headers.get('Cache-Control')).toBe('private, no-store');
		expect(res.headers.get('Content-Length')).toBe('4');
		expect(res.headers.get('ETag')).toBe('"etag-1"');
		// Owner and normalized target (`.pdf` stripped, lowercased) are bound into the query.
		expect(bind).toHaveBeenCalledWith(AUDIT_ID, TARGET, OWNER);
		expect(get).toHaveBeenCalledWith(R2_KEY);
	});

	it('strips a trailing .pdf and lowercases the target before lookup', async () => {
		const { db, bind } = makeDb({ pdf_r2_key: R2_KEY });
		const { bucket } = makeBucket(pdfObject());

		const res = await run(AUDIT_ID, 'EXAMPLE.COM.PDF', OWNER, db, bucket);

		expect(res.status).toBe(200);
		expect(bind).toHaveBeenCalledWith(AUDIT_ID, TARGET, OWNER);
	});

	it('returns 404 when the owner does not match (query returns no row)', async () => {
		// The SQL owner-scopes via `a.owner_id = ?`, so a wrong owner surfaces as
		// "no row" — indistinguishable from an unknown auditId (ID-enumeration defense).
		const { db } = makeDb(null);
		const { bucket, get } = makeBucket(pdfObject());

		const res = await run(AUDIT_ID, TARGET, 'other-owner-hash', db, bucket);

		expect(res.status).toBe(404);
		expect(get).not.toHaveBeenCalled();
	});

	it('returns 404 when the row exists but has no pdf_r2_key', async () => {
		const { db } = makeDb({ pdf_r2_key: null });
		const { bucket, get } = makeBucket(pdfObject());

		const res = await run(AUDIT_ID, TARGET, OWNER, db, bucket);

		expect(res.status).toBe(404);
		expect(get).not.toHaveBeenCalled();
	});

	it('returns 404 when the R2 object is missing', async () => {
		const { db } = makeDb({ pdf_r2_key: R2_KEY });
		const { bucket } = makeBucket(null);

		const res = await run(AUDIT_ID, TARGET, OWNER, db, bucket);

		expect(res.status).toBe(404);
	});

	it('rejects malformed auditId and target without touching D1', async () => {
		const { db, prepare } = makeDb({ pdf_r2_key: R2_KEY });
		const { bucket } = makeBucket(pdfObject());

		const badAudit = await run('../etc/passwd', TARGET, OWNER, db, bucket);
		const badTarget = await run(AUDIT_ID, 'not a domain!', OWNER, db, bucket);

		expect(badAudit.status).toBe(404);
		expect(badTarget.status).toBe(404);
		expect(prepare).not.toHaveBeenCalled();
	});
});
