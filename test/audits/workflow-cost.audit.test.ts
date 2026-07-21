/** @vitest-environment node */
// SPDX-License-Identifier: BUSL-1.1
//
// $0 CI/CD cost guard audit: fails if any ACTIVE workflow (.yml/.yaml, not
// .disabled) declares a self-hosted runner or a known paid marketplace
// action. Runs in the node pool (needs real `node:fs` directory + file
// reads against .github/workflows — the default Workers pool has neither;
// see license-headers.audit.test.ts for the same rationale).
import { describe, it, expect } from 'vitest';
import { findCostViolations, scanWorkflowDir } from '../../scripts/ci/check-workflow-cost.mjs';

const WF_DIR = '.github/workflows';

describe('workflow cost guard', () => {
	it('flags self-hosted runners and paid actions', () => {
		const bad = 'jobs:\n  x:\n    runs-on: self-hosted\n    steps:\n      - uses: MadaBurns/blackveil-dns-action@v1';
		const v = findCostViolations('bad.yml', bad);
		expect(v.map((x) => x.kind).sort()).toEqual(['paid-action', 'self-hosted-runner']);
	});

	it('the live workflows directory is $0 (no self-hosted, no paid actions)', () => {
		// .disabled files are intentionally excluded (only active .yml/.yaml scanned).
		expect(scanWorkflowDir(WF_DIR)).toEqual([]);
	});
});
