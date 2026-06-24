// SPDX-License-Identifier: BUSL-1.1

import type { CheckCategory, Finding, Severity } from './types';
import { sanitizeFindingMetadata, sanitizeStructuredString } from './scoring/metadata-sanitize';

// Re-export scoring functions from the single source of truth (scoring/model.ts).
export { buildCheckResult, computeCategoryScore, inferFindingConfidence } from './scoring/model';

// ── Output sanitization (inlined from src/lib/output-sanitize.ts) ──────────

/**
 * Sanitize DNS-sourced data before it enters finding detail strings.
 * Uses the shared metadata/detail structured-string sanitizer so both finding
 * channels stay in lockstep. Does NOT truncate — DNS data in findings can be
 * longer than display output.
 */
export function sanitizeDnsData(input: string): string {
	return sanitizeStructuredString(input);
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
	// F7 (OWASP LLM01) parity with scoring/model.ts createFinding: metadata reaches
	// the LLM verbatim via the MCP `structuredContent` channel, so sanitize
	// attacker-influenceable string values at this chokepoint too. Both exported
	// createFinding implementations must sanitize metadata identically
	// (createfinding-metadata-parity.audit.test.ts).
	const sanitizedMetadata = sanitizeFindingMetadata(metadata);
	return { category, title, severity, detail: sanitizeDnsData(detail), ...(sanitizedMetadata ? { metadata: sanitizedMetadata } : {}) };
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
