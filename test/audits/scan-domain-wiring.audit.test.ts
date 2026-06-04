// SPDX-License-Identifier: BUSL-1.1

/**
 * scan_domain dispatch-wiring drift guard.
 *
 * Pins the scan_domain RUNTIME category set (`SCAN_CATEGORIES`, the keys of the
 * hand-maintained dispatch table in `src/tools/scan-domain.ts`) to the
 * `scanIncluded` SSOT in `TOOL_DEFS` (`src/schemas/tool-definitions.ts`).
 *
 * Why this exists: the `EXPECTED_SCAN_DOMAIN_TOOLS` tripwire in
 * `test/tool-schemas.spec.ts` only checks that TOOL_DEFS' `scanIncluded` set
 * matches a hardcoded expectation — it does NOT verify that scan-domain.ts
 * actually RUNS those categories. So a scanned tool could exist in the SSOT
 * with no runner (silently never executed, sitting in the scoring denominator
 * at 0), or scan-domain.ts could carry a stale runner for a tool no longer
 * scanned. This assertion closes that gap by comparing the two independently
 * derived sets directly.
 *
 * The two sides are NOT tautological: `SCAN_CATEGORIES` is the runtime dispatch
 * table's keys, while the derived set is computed from `TOOLS`.
 */

import { describe, it, expect } from 'vitest';
import { TOOLS } from '../../src/schemas/tool-definitions';
import { SCAN_CATEGORIES } from '../../src/tools/scan-domain';

describe('scan_domain dispatch wiring (audit)', () => {
	it('SCAN_CATEGORIES exactly matches the scanIncluded SSOT (+ internal subdomain_takeover)', () => {
		// scanIncluded check_* tools map to their category by stripping the check_ prefix;
		// subdomain_takeover runs inside scan_domain but is scanIncluded:false (internal), so add it.
		const derived = [...TOOLS.filter((t) => t.scanIncluded).map((t) => t.name.replace(/^check_/, '')), 'subdomain_takeover'].sort();

		expect([...SCAN_CATEGORIES].sort()).toEqual(derived);
		// ^ A mismatch means scan-domain.ts's dispatch table drifted from the
		//   scanIncluded SSOT: either a scanned tool has no runner here (extra in
		//   `derived`), or a stale/orphan runner remains (extra in SCAN_CATEGORIES).
	});
});
