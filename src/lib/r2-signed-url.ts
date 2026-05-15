// SPDX-License-Identifier: BUSL-1.1

/**
 * R2 signed-URL helper for time-limited public-readable links to private bucket
 * objects. Used by `brand_audit_get_report` to surface generated PDFs without
 * proxying the bytes through the worker on every request.
 *
 * Delegates to the R2 binding's `createSignedUrl` method (Workers runtime).
 * The default TTL is 7 days — same as the published Phase-3 plan and roughly
 * the customer's expected polling/retrieval window for an audit batch.
 *
 * Path-traversal defense: we validate the key shape before signing. Although
 * R2 keys are arbitrary opaque strings, signing a `../`-prefixed key could
 * give a misconfigured proxy a route into objects outside the audits namespace.
 */

/** Default URL lifetime — 7 days. */
const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;

/** Max R2 key length we'll sign. Cloudflare's hard cap is 1024. */
const MAX_KEY_LENGTH = 1024;

/** Minimal R2-bucket interface — only the methods we exercise. */
interface CreateSignedUrlable {
	createSignedUrl?: (input: { key: string; expiresInSeconds: number }) => Promise<string>;
}

/**
 * Mint a time-limited signed URL for an R2 object.
 *
 * @throws when `bucket.createSignedUrl` is missing (binding misconfigured), or
 *   when `key` fails the path-shape check (empty, traversal, oversize).
 */
export async function generateR2SignedUrl(
	bucket: CreateSignedUrlable,
	key: string,
	ttlSeconds: number = DEFAULT_TTL_SECONDS,
): Promise<string> {
	if (typeof key !== 'string' || key.length === 0 || key.length > MAX_KEY_LENGTH || key.includes('..') || key.startsWith('/')) {
		throw new Error(`invalid R2 key shape: ${key.length === 0 ? '<empty>' : key.slice(0, 64)}`);
	}
	if (typeof bucket.createSignedUrl !== 'function') {
		throw new Error('R2 bucket binding has no createSignedUrl method — feature not available in this runtime');
	}
	return bucket.createSignedUrl({ key, expiresInSeconds: ttlSeconds });
}
