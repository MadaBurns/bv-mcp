// SPDX-License-Identifier: BUSL-1.1

/**
 * GET /reports/:auditId/:target(.pdf) — authenticated, owner-scoped download
 * of a rendered brand-audit PDF, streamed from the BRAND_REPORTS R2 bucket.
 *
 * Replaces the never-functional R2 `createSignedUrl` path (PR #128): the
 * Workers R2 binding has no URL-signing API — presigning requires S3
 * credentials — so PDFs are served through the Worker on the same bearer
 * credential the MCP tools use.
 *
 * Owner scoping mirrors `brand_audit_get_report`: a wrong-owner or unknown
 * auditId returns the SAME 404 as a missing row (ID-enumeration defense).
 */

const AUDIT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const TARGET_RE = /^[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?$/;

export interface ReportDownloadDeps {
	db: D1Database;
	bucket: R2Bucket;
}

function notFound(): Response {
	return new Response('Not found', { status: 404 });
}

/**
 * Stream a brand-audit PDF to an authenticated owner.
 *
 * @param auditId - Audit id from the URL path
 * @param targetRaw - Target domain from the URL path; a trailing `.pdf` is stripped
 * @param ownerId - The caller's resolved principal (keyHash) — must match `brand_audits.owner_id`
 */
export async function handleReportDownload(auditId: string, targetRaw: string, ownerId: string, deps: ReportDownloadDeps): Promise<Response> {
	const target = targetRaw.replace(/\.pdf$/i, '').trim().toLowerCase();
	if (!AUDIT_ID_RE.test(auditId) || !TARGET_RE.test(target)) {
		return notFound();
	}

	const row = (await deps.db
		.prepare(
			'SELECT t.pdf_r2_key FROM brand_audit_targets t JOIN brand_audits a ON a.id = t.audit_id WHERE t.audit_id = ? AND t.target = ? AND a.owner_id = ? LIMIT 1',
		)
		.bind(auditId, target, ownerId)
		.first()) as { pdf_r2_key: string | null } | null;

	if (!row?.pdf_r2_key) {
		return notFound();
	}

	const object = await deps.bucket.get(row.pdf_r2_key);
	if (!object) {
		return notFound();
	}

	return new Response(object.body, {
		status: 200,
		headers: {
			'Content-Type': 'application/pdf',
			'Content-Length': String(object.size),
			'Content-Disposition': `attachment; filename="${target}.pdf"`,
			// Owner-scoped content behind a bearer credential — never edge/shared-cacheable.
			'Cache-Control': 'private, no-store',
			ETag: object.httpEtag,
		},
	});
}
