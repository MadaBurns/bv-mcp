// SPDX-License-Identifier: BUSL-1.1

import type { CheckResult } from '../lib/scoring';
import type { OutputFormat } from './tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';
import { isCompletedCheck, UNGRADED_DISPLAY } from '../lib/ungraded-display';
import { resolveImpactNarrative } from '../tools/explain-finding';

export interface McpContent {
	type: 'text';
	text: string;
}

export function mcpError(message: string): McpContent {
	return { type: 'text', text: `Error: ${message}` };
}

export function mcpText(text: string): McpContent {
	return { type: 'text', text };
}

/**
 * Build MCP content array with human-readable text and, for non-interactive clients (format=full),
 * an appended structured JSON block for machine-readable consumption.
 *
 * Emission is format-driven here; whether a given client still *needs* this backward-compat comment
 * is decided downstream at the dispatch boundary — `stripRedundantStructuredComment` in `mcp/dispatch.ts`
 * removes it for clients that read the MCP-standard `structuredContent` field (protocol >= 2025-06-18,
 * excluding known comment-parsers like `blackveil_dns_action`).
 */
export function buildToolContent(text: string, structuredData: unknown, format: OutputFormat): McpContent[] {
	const content: McpContent[] = [mcpText(text)];
	if (format === 'full') {
		content.push(mcpText(`<!-- STRUCTURED_RESULT\n${JSON.stringify(structuredData)}\nSTRUCTURED_RESULT -->`));
	}
	return content;
}

/**
 * Coerce arbitrary structured tool data into the MCP-standard `structuredContent`
 * shape — which MUST be a JSON object (not an array or scalar) per MCP 2025-06-18.
 *
 * - `null`/`undefined` → `undefined` (field is omitted from the result).
 * - array → `{ results: <array> }` (objects-only constraint).
 * - plain object → returned as-is.
 * - scalar (string/number/boolean) → `{ value: <scalar> }`.
 */
export function toStructuredContent(data: unknown): Record<string, unknown> | undefined {
	if (data === null || data === undefined) return undefined;
	if (Array.isArray(data)) return { results: data };
	if (typeof data === 'object') return data as Record<string, unknown>;
	return { value: data };
}

/**
 * Build a full MCP tool-call result: the human-readable `content` array (with the
 * backward-compat `STRUCTURED_RESULT` comment in `full` format) plus the
 * MCP-standard `structuredContent` machine-readable channel.
 *
 * `structuredContent` is set regardless of `format` — it is a separate channel
 * from `content`, and clients that don't support it simply ignore it.
 */
export function buildToolResult(
	text: string,
	structuredData: unknown,
	format: OutputFormat,
): { content: McpContent[]; structuredContent?: Record<string, unknown> } {
	const content = buildToolContent(text, structuredData, format);
	const sc = toStructuredContent(structuredData);
	return sc === undefined ? { content } : { content, structuredContent: sc };
}

/**
 * Public per-domain security scorecard base — the citation link-back target that
 * feeds the GSI SEO / AI-search funnel (mirrors the `source` link a caller sees
 * from comparable hosted scanners).
 */
const PUBLIC_REPORT_BASE_URL = 'https://www.blackveilsecurity.com/security-report';

/**
 * Public scorecard URL for a domain. `domain` has already passed
 * `extractAndValidateDomain` (validateDomain + sanitizeDomain) upstream;
 * `encodeURIComponent` is defence-in-depth against any stray character.
 */
export function buildReportUrl(domain: string): string {
	return `${PUBLIC_REPORT_BASE_URL}/${encodeURIComponent(domain)}`;
}

/**
 * Attach a citation link back to the public per-domain scorecard. Emitted ONLY
 * for a domain-bearing, non-error result — non-domain tools (`domain` undefined)
 * and error results are a no-op. Additive: the `source`/`report_url` keys ride
 * through the `.loose()` CheckResult outputSchema, so strict MCP clients that
 * validate against the schema still pass.
 */
export function withReportCitation<T extends { structuredContent?: Record<string, unknown>; isError?: boolean }>(
	result: T,
	domain: string | undefined,
): T {
	if (!domain || result.isError) return result;
	const reportUrl = buildReportUrl(domain);
	return {
		...result,
		structuredContent: {
			...(result.structuredContent ?? {}),
			source: reportUrl,
			report_url: reportUrl,
		},
	};
}

export function formatCheckResult(result: CheckResult, format: OutputFormat = 'full'): string {
	const lines: string[] = [];
	lines.push(`## ${result.category.toUpperCase()} Check`);
	// A check that did not COMPLETE has no verdict to report. `buildCheckResult` derives
	// `passed`/`score` from finding severities, so a lane that was never measured -- whose only
	// finding is an `info` "unavailable" note -- renders as "✅ Passed / 100/100": an affirmative
	// clean bill of health for something nobody observed (#695). Abstaining mirrors
	// `displayGradeFor`'s rule for an ungraded scan, which returns null rather than letting
	// `nistScoreToGrade(0)` fabricate an `F`. Same principle, same vocabulary
	// (`UNGRADED_DISPLAY`), one layer down.
	//
	// The predicate MUST come from `isCompletedCheck`; re-deriving it here is banned by
	// `test/audits/completed-evidence-predicate-ssot.audit.test.ts`.
	if (isCompletedCheck(result)) {
		lines.push(`**Status:** ${result.passed ? '✅ Passed' : '❌ Failed'}`);
		lines.push(`**Score:** ${result.score}/100`);
	} else {
		lines.push(`**Status:** ${UNGRADED_DISPLAY}`);
	}
	lines.push('');

	if (result.findings.length > 0) {
		lines.push('### Findings');
		for (const finding of result.findings) {
			if (format === 'compact') {
				const isHighPriority = finding.severity === 'critical' || finding.severity === 'high';
				const detailLimit = isHighPriority ? 4000 : 300;
				lines.push(`- [${finding.severity.toUpperCase()}] ${sanitizeOutputText(finding.title, 120)} — ${sanitizeOutputText(finding.detail, detailLimit)}`);
				continue;
			}

			const icon =
				finding.severity === 'info'
					? 'ℹ️'
					: finding.severity === 'low'
						? '⚠️'
						: finding.severity === 'medium'
							? '🔶'
							: finding.severity === 'high'
								? '🔴'
								: '🚨';
					lines.push(`- ${icon} **[${finding.severity.toUpperCase()}]** ${sanitizeOutputText(finding.title, 120)}`);
					lines.push(`  ${sanitizeOutputText(finding.detail)}`);

			const verificationStatus =
				finding.category === 'subdomain_takeover' && finding.metadata?.verificationStatus
					? String(finding.metadata.verificationStatus)
					: undefined;
			if (verificationStatus) {
				lines.push(`  Takeover Verification: ${sanitizeOutputText(verificationStatus, 80)}`);
			}

			const proofRequired =
				finding.category === 'subdomain_takeover' && finding.metadata?.proofRequired
					? String(finding.metadata.proofRequired)
					: undefined;
			if (proofRequired) {
				lines.push(`  Proof Required: ${sanitizeOutputText(proofRequired, 120)}`);
			}

			const confidence = finding.metadata?.confidence ? String(finding.metadata.confidence) : undefined;
			if (confidence) {
				lines.push(`  Confidence: ${sanitizeOutputText(confidence, 80)}`);
			}

			if (finding.severity !== 'info') {
				const narrative = resolveImpactNarrative({
					category: finding.category,
					severity: finding.severity,
					title: finding.title,
					detail: finding.detail,
				});
				if (narrative.impact) {
					lines.push(`  Potential Impact: ${narrative.impact}`);
				}
				if (narrative.adverseConsequences) {
					lines.push(`  Adverse Consequences: ${narrative.adverseConsequences}`);
				}
			}
		}
	}

	appendCertificateSection(lines, result);

	return lines.join('\n');
}

/**
 * Narrate `CheckResult.metadata.certificate` into the human-readable channel.
 *
 * WHY. `check_ssl`'s description promises the issuer and expiry date. The
 * enrichment attaches them to `metadata`, which reaches the caller on the
 * MCP-standard `structuredContent` field — but a client that reads only the
 * `content` text saw nothing, and in `compact` format there is no appended
 * STRUCTURED_RESULT blob to fall back on either. The promise was kept on one
 * channel and silently broken on the other.
 *
 * NON-SCORING, and it must stay that way: this renders metadata, never a
 * `Finding`, so nothing here can move a domain's score or grade.
 *
 * An unmeasured field prints `unknown` rather than being omitted — a missing row
 * reads as "we did not look", which is a different claim from "there is no
 * expiry date". Absence of the whole block adds nothing at all: no CT record is
 * not a finding about the certificate.
 */
function appendCertificateSection(lines: string[], result: CheckResult): void {
	const cert = (result as { metadata?: { certificate?: unknown } }).metadata?.certificate;
	if (!cert || typeof cert !== 'object') return;
	const c = cert as Record<string, unknown>;

	const str = (v: unknown): string =>
		typeof v === 'string' && v.trim() !== '' ? sanitizeOutputText(v, 200) : 'unknown';
	const expires =
		typeof c.notAfter === 'string' && c.notAfter.trim() !== ''
			? // Date-only: the time component is noise for an expiry, and CT precision
				// does not warrant implying it.
				sanitizeOutputText(c.notAfter.slice(0, 10), 20)
			: 'unknown';
	const remaining =
		typeof c.daysRemaining === 'number' && Number.isFinite(c.daysRemaining)
			? `${c.daysRemaining} days`
			: 'unknown';

	lines.push('');
	lines.push('### Certificate');
	lines.push(`- Issuer: ${str(c.issuer)}`);
	lines.push(`- Expires: ${expires} (${remaining} remaining, band: ${str(c.expiryBand)})`);
	if (typeof c.sanCount === 'number' && Number.isFinite(c.sanCount)) {
		// Count only — publishing the SAN list would hand out an enumerated
		// subdomain inventory.
		lines.push(`- Subject alternative names: ${c.sanCount}`);
	}
	// Never drop this line: without it a reader takes "logged" to mean "served"
	// and draws a wrong conclusion from a correct answer.
	lines.push(
		'- Source: Certificate Transparency logs — describes the most recently logged certificate, which may differ from the certificate currently served.'
	);
}
