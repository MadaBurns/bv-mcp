// SPDX-License-Identifier: BUSL-1.1

import type { CheckCategory, Finding, Severity } from './types';

// Re-export scoring functions from the single source of truth (scoring/model.ts).
// check-utils keeps createFinding + sanitizeDnsData locally because they apply
// DNS-specific sanitization that differs from the generic scoring model version.
export { buildCheckResult, computeCategoryScore, inferFindingConfidence } from './scoring/model';

// ── Output sanitization (inlined from src/lib/output-sanitize.ts) ──────────

/**
 * Characters that can inject HTML or dangerous markdown constructs.
 * Excludes `_` (common in DNS names like `_dmarc`, `_mta-sts`) and
 * `()` (used in natural-language detail text) which are safe in finding details.
 */
const DNS_DATA_UNSAFE = /[`*#[\]>|<]/g;

/**
 * Sanitize DNS-sourced data before it enters finding detail strings.
 * Strips C0 control characters (preserving tab/newline), replaces HTML/markdown
 * injection characters, but does NOT truncate — DNS data in findings can be
 * longer than display output.
 */
export function sanitizeDnsData(input: string): string {
	return input
		.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
		.replace(DNS_DATA_UNSAFE, ' ')
		.replace(/\s+/g, ' ')
		.trim();
}

/**
 * Create a finding object with the given parameters.
 */
export function createFinding(
	category: CheckCategory,
	title: string,
	severity: Severity,
	detail: string,
	metadata?: Record<string, unknown>,
): Finding {
	return { category, title, severity, detail: sanitizeDnsData(detail), ...(metadata ? { metadata } : {}) };
}

/**
 * Check whether a discovered domain is the same as or a subdomain of a seed domain.
 * Used to filter out same-organization assets from shadow-IT discovery.
 * Both inputs are normalized (lowercased, trailing dots stripped).
 */
export function isSubdomainOf(discovered: string, seed: string): boolean {
	const d = discovered.toLowerCase().replace(/\.$/, '');
	const s = seed.toLowerCase().replace(/\.$/, '');
	return d === s || d.endsWith(`.${s}`);
}
