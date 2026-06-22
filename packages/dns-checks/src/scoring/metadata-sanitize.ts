// SPDX-License-Identifier: BUSL-1.1
/**
 * Chokepoint sanitizer for finding `metadata` (F7 — OWASP LLM01, indirect prompt
 * injection).
 *
 * Finding `metadata` flows to the calling LLM verbatim via the MCP
 * `structuredContent` channel (emitted regardless of `format`, read by protocol
 * >=2025-06-18 clients). `createFinding()` historically sanitized only the prose
 * `detail`, leaving `metadata` raw — so any tool that spreads attacker-influenceable
 * upstream data (bucket names, object keys, threat-feed entries, OSINT strings)
 * into `metadata` shipped an injection hole. This was fixed opt-in, per tool,
 * THREE times before being generalized here at the `createFinding` chokepoint.
 *
 * This module is the runtime-agnostic equivalent of `src/lib/sanitize-upstream.ts`
 * + `src/lib/output-sanitize.ts`'s `sanitizeDnsData`. It lives INSIDE the vendored
 * `@blackveil/dns-checks` package (which must NOT depend on Worker-only code) so
 * that `createFinding` can call it directly.
 *
 * What it does to STRING values (only):
 *   1. NFKC-normalize fullwidth/confusable forms into their canonical ASCII
 *      equivalents before filtering.
 *   2. Strip ANSI/CSI escape sequences (terminal control injection), including
 *      8-bit C1 CSI (`\x9B`) forms, before generic control-byte stripping.
 *   3. Strip C0/C1/DEL control bytes (preserving nothing — newlines/tabs collapse
 *      to a single space in step 6, matching the `detail` sanitizer).
 *   4. Strip bidi / zero-width Unicode controls that can visually reorder or hide
 *      attacker text.
 *   5. Replace markdown/HTML injection characters — backticks (code fences),
 *      `* # [ ] > | < >` — with a space. This neutralizes ```` ``` ```` code
 *      fences and `<...>`/`[...]` markdown that an LLM could be steered by.
 *   6. Collapse runs of whitespace to a single space and trim.
 *   7. Clamp the cleaned string to `MAX_META_STRING` characters.
 *
 * What it PRESERVES (never altered):
 *   - numbers, booleans, null, undefined, bigint — at ANY depth. Scoring and
 *     formatters rely on numeric/boolean/enum fields (`penaltyOverride`,
 *     `controlPresent`, `missingControl`, `errorKind`, `confidence`, severity/
 *     score fields). Enum string values (e.g. `'deterministic'`, `'verified'`,
 *     `'dns_error'`) survive unchanged because they contain no control bytes,
 *     markdown chars, or internal whitespace.
 *
 * Bounds: recursion is capped at `MAX_META_DEPTH` (nodes deeper than the cap are
 * dropped — `undefined`, which JSON-serializes away); per-string length is capped
 * at `MAX_META_STRING`. Array SIZE is intentionally NOT bounded here — that's a
 * token-cap concern, not an injection one, handled per-tool where it matters.
 *
 * Sanitize the FULL string, THEN clamp: the whitespace collapse is many-to-one,
 * so coarse-slicing first could silently drop content a compressible prefix
 * pushes past the slice.
 */

/** Defensive cap on any single string field (upstream values can be malformed/huge). */
export const MAX_META_STRING = 8_000;

/** Recursion ceiling for nested sanitization — drop absurdly-deep nesting. */
export const MAX_META_DEPTH = 6;

/** ANSI / CSI escape sequences (terminal control injection), including 8-bit C1 CSI. */
const ANSI_ESCAPE = /(?:\x1b\[[0-?]*[ -/]*[@-~]|\x9b[0-?]*[ -/]*[@-~])/g;

/** C0 + C1 control bytes + DEL, excluding none — tab/newline are handled by whitespace collapse. */
const CONTROL_BYTES = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g;

/** Unicode bidi / zero-width formatting controls that can hide or reorder attacker text. */
const UNICODE_STEALTH = /[\u061C\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g;

/**
 * Markdown / HTML injection characters. Mirrors `DNS_DATA_UNSAFE` in
 * `src/lib/output-sanitize.ts` (backtick code fences, headings, list/quote/table
 * markers, link brackets, angle brackets). `_` and `()` are deliberately left
 * intact — they appear in legitimate DNS labels (`_dmarc`) and prose.
 */
const MARKDOWN_UNSAFE = /[`*#[\]>|<]/g;

/**
 * Sanitize a string for safe inclusion in finding detail/metadata structured data.
 * Control/ANSI/Unicode-stealth/markdown neutralized, whitespace-collapsed.
 */
export function sanitizeStructuredString(input: string): string {
	return input
		.normalize('NFKC')
		.replace(ANSI_ESCAPE, '')
		.replace(CONTROL_BYTES, '')
		.replace(UNICODE_STEALTH, '')
		.replace(MARKDOWN_UNSAFE, ' ')
		.replace(/\s+/g, ' ')
		.trim();
}

/**
 * Sanitize a single string for safe inclusion in finding metadata.
 * Control/ANSI/markdown-neutralized, whitespace-collapsed, length-clamped.
 */
export function sanitizeMetadataString(input: string): string {
	const cleaned = sanitizeStructuredString(input);
	return cleaned.length > MAX_META_STRING ? cleaned.slice(0, MAX_META_STRING) : cleaned;
}

/**
 * Recursively sanitize a metadata value. Strings are neutralized + clamped;
 * arrays/objects are recursed (depth-bounded); every other primitive
 * (number/boolean/null/undefined/bigint) passes through unchanged at any depth.
 */
export function sanitizeMetadataValue(v: unknown, depth = 0): unknown {
	if (typeof v === 'string') return sanitizeMetadataString(v);
	if (v === null || typeof v !== 'object') return v; // numbers/booleans/null/undefined/bigint/symbol/function pass through
	if (depth >= MAX_META_DEPTH) return undefined; // stop unbounded recursion into nested containers
	if (Array.isArray(v)) return v.map((item) => sanitizeMetadataValue(item, depth + 1));
	const out: Record<string, unknown> = {};
	for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = sanitizeMetadataValue(val, depth + 1);
	return out;
}

/**
 * Sanitize a finding-metadata object at the `createFinding` chokepoint.
 * Returns a NEW object whose every (possibly-nested) string value is neutralized;
 * non-string scalars are preserved. Non-object input returns `undefined`.
 */
export function sanitizeFindingMetadata(metadata: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
	if (metadata === undefined) return undefined;
	if (metadata === null || typeof metadata !== 'object') return undefined;
	return sanitizeMetadataValue(metadata, 0) as Record<string, unknown>;
}
