// SPDX-License-Identifier: BUSL-1.1

/**
 * Shapes delivered to `ToolRuntimeOptions.resultCapture` (see `handlers/tools.ts`).
 *
 * These live in their own module rather than in `handlers/tools.ts` on purpose: the
 * tenant and internal call sites need the type guard, and several suites `vi.mock()`
 * `handlers/tools` down to just `handleToolsCall`. Importing the guard from there
 * would leave it `undefined` under those mocks and throw at runtime inside the very
 * persistence path this guard protects.
 */

import type { CheckResult, Finding } from './scoring';
import type { StructuredScanResult } from '../tools/scan/format-report';

/**
 * `scan_domain`'s `resultCapture` payload: the same `StructuredScanResult` that is
 * surfaced as `structuredContent`, plus the per-category findings flattened out of
 * the raw `ScanDomainResult` (which `StructuredScanResult` summarises only as
 * `findingCounts`). Consumers that persist a scan — the tenant scan paths — need
 * both the aggregate score/grade AND the individual findings.
 */
export interface CapturedScanResult extends StructuredScanResult {
	/** Findings flattened across every scan category, in category order. */
	findings: Finding[];
}

/**
 * Payload delivered to `ToolRuntimeOptions.resultCapture`. Per-category registry
 * tools emit a `CheckResult`; `scan_domain` emits a `CapturedScanResult`.
 *
 * Declaring the union is deliberate. The previous `(result: CheckResult) => void`
 * signature was a type lie: it let the tenant call sites read `score` as a plain
 * `number` and hid `grade` behind an `as unknown as { grade?: string }` cast, so
 * `tsc` could not flag nullability at the sites that persist those columns.
 */
export type CapturedToolResult = CheckResult | CapturedScanResult;

/**
 * Narrow a captured payload to `scan_domain`'s aggregate shape.
 *
 * Discriminates on `categoryScores`, which only the scan aggregate carries — a
 * `CheckResult` has a single `category` string and no per-category score map.
 */
export function isCapturedScanResult(result: CapturedToolResult): result is CapturedScanResult {
	const candidate = (result as CapturedScanResult).categoryScores;
	return typeof candidate === 'object' && candidate !== null;
}
