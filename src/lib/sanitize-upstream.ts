// SPDX-License-Identifier: BUSL-1.1
/**
 * Defensive sanitizer for upstream (bv-recon) JSON before it enters finding
 * metadata / the MCP `structuredContent` channel.
 *
 * F7 (OWASP LLM01 — indirect prompt injection): `createFinding()` sanitizes only
 * the prose `detail`, NOT `metadata`. Any value spread from an upstream bv-recon
 * response into finding metadata therefore reaches the calling LLM verbatim via
 * `structuredContent` (emitted regardless of `format`, read by protocol
 * >=2025-06-18 clients). Bucket names, object keys, and threat-feed entries are
 * attacker-influenceable, so an attacker can inject instructions / control bytes
 * into the model through that channel.
 *
 * The recon bucket-status/findings payloads are opaque (`Record<string, unknown>`)
 * and the start payload is `.passthrough()`, so there is no fixed key set to
 * allowlist — instead recurse over the whole object and run EVERY string through
 * the same output sanitizer the prose channel uses (`sanitizeDnsData`: strips
 * C0/ANSI control bytes, neutralizes markdown/HTML injection incl. code-fence
 * backticks, collapses newlines), THEN apply a length clamp on the cleaned text.
 * Scalars (number/boolean/null) pass through unchanged at any depth (they can't
 * carry injection); recursion is bounded by `MAX_META_DEPTH`.
 *
 * Sanitize the FULL string, THEN clamp — `sanitizeDnsData` collapses whitespace
 * many-to-one, so coarse-slicing first could silently drop content a compressible
 * prefix pushes past the slice. These operator-only (BV_RECON) strings are not
 * multi-MB, so the full sweep is acceptable.
 *
 * Mirrors the F7 fix already shipped for OSINT in `src/tools/osint-investigate.ts`
 * (the local `capString`). Kept as a shared module so the bucket + threat-feed
 * recon tools reuse the identical, tested shaping.
 *
 * Scope note: this bounds per-string length and recursion depth, not array size
 * — a huge upstream `findings[]` still passes through. That is a token-cap concern,
 * not an injection one, and these are operator-only paths; out of scope here.
 */
import { sanitizeDnsData } from './output-sanitize';

/** Defensive cap on any single string field (upstream values can be malformed/huge). */
export const MAX_META_STRING = 8_000;

/** Recursion ceiling for nested sanitization — drop absurdly-deep upstream nesting. */
export const MAX_META_DEPTH = 6;

/**
 * Recursively sanitize an upstream value for safe inclusion in finding metadata.
 * Strings → `sanitizeDnsData` then length-clamped; arrays/objects recursed
 * (depth-bounded); scalars passed through.
 */
export function sanitizeUpstreamValue(v: unknown, depth = 0): unknown {
	if (typeof v === 'string') {
		const sanitized = sanitizeDnsData(v);
		return sanitized.length > MAX_META_STRING ? sanitized.slice(0, MAX_META_STRING) : sanitized;
	}
	if (v === null || typeof v !== 'object') return v; // numbers/booleans/null pass through at any depth
	if (depth >= MAX_META_DEPTH) return undefined; // stop unbounded recursion into nested containers
	if (Array.isArray(v)) return v.map((item) => sanitizeUpstreamValue(item, depth + 1));
	const out: Record<string, unknown> = {};
	for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = sanitizeUpstreamValue(val, depth + 1);
	return out;
}

/**
 * Sanitize a plain upstream object for spreading into finding metadata.
 * Returns a new object whose every (possibly-nested) string value is sanitized.
 */
export function sanitizeUpstreamObject(obj: Record<string, unknown> | null | undefined): Record<string, unknown> {
	if (!obj || typeof obj !== 'object') return {};
	return sanitizeUpstreamValue(obj, 0) as Record<string, unknown>;
}
