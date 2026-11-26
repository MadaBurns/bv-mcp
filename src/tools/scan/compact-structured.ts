// SPDX-License-Identifier: BUSL-1.1

/**
 * `format: "compact"` for the `scan_domain` structured payload.
 *
 * Compact already shortens the text, but hosts that hand the model `structuredContent`
 * instead of the text got the full-size payload anyway. This is a PRESENTATION transform
 * applied at the dispatch boundary to the complete result of `buildStructuredScanResult`:
 * scores, grade, counts, statuses and every non-info finding are untouched, and
 * `format: "full"` never reaches this module.
 *
 * What it drops, and what it never drops:
 *  - `webPosture` becomes a per-category summary (category, passed, score, and the title and
 *    severity of each non-info finding, plus checkStatus/partial when the check did not
 *    complete); no detail, no metadata.
 *  - info findings keep category/title/severity and lose `detail`. They are NEVER removed:
 *    the text report omits info findings in every format, so this payload is their only carrier.
 */

import type { StructuredScanResult } from './format-report';

/** Said once on the trimmed payload so a reader knows detail was omitted and where to get it. */
export const COMPACT_DETAIL_OMITTED_NOTE = 'Per-finding detail is omitted in compact format; call with format "full" to include it.';

type CompactFinding = Omit<StructuredScanResult['findings'][number], 'detail'> & { detail?: string };

export type CompactStructuredScanResult = Omit<StructuredScanResult, 'findings' | 'webPosture'> & {
	findings: CompactFinding[];
	webPosture?: {
		nonScoring: true;
		results: Array<{
			category: string;
			passed: boolean;
			score: number;
			/** Present only when the check did not complete: a 0 here is "not measured", not a failure. */
			checkStatus?: string;
			partial?: boolean;
			findings: Array<{ title: string; severity: string }>;
		}>;
	};
	compactDetailOmitted: string;
};

export function compactStructuredScanResult(structured: StructuredScanResult): CompactStructuredScanResult {
	const { webPosture, findings, ...rest } = structured;
	return {
		...rest,
		findings: findings.map((f) => (f.severity === 'info' ? { category: f.category, title: f.title, severity: f.severity } : f)),
		...(webPosture !== undefined && {
			webPosture: {
				nonScoring: webPosture.nonScoring,
				results: webPosture.results.map((r) => ({
					category: r.category,
					passed: r.passed,
					score: r.score,
					// Unmeasured checks score 0 with only an info finding; without these two a reader sees a bare failure.
					...(r.checkStatus !== undefined && { checkStatus: r.checkStatus }),
					...(r.partial !== undefined && { partial: r.partial }),
					findings: r.findings.filter((f) => f.severity !== 'info').map((f) => ({ title: f.title, severity: f.severity })),
				})),
			},
		}),
		compactDetailOmitted: COMPACT_DETAIL_OMITTED_NOTE,
	};
}
