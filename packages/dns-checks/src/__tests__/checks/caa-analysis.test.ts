// SPDX-License-Identifier: BUSL-1.1

/**
 * CAA tag-completeness analysis.
 *
 * Ported from the Worker-side `test/caa-analysis.spec.ts`, which exercised a
 * duplicate copy at `src/tools/caa-analysis.ts` that nothing in the production
 * path imported — `src/tools/check-caa.ts` delegates to this package. The tests
 * passed while validating dead code, so the live implementation was untested.
 * The duplicate is removed; this file is the coverage, pointed at what runs.
 */

import { describe, expect, it } from 'vitest';

import { getCaaConfiguredFinding, getCaaValidationFindings, summarizeCaaTags } from '../../checks/caa-analysis';

describe('caa-analysis', () => {
	it('summarizes presence of key CAA tags', () => {
		expect(
			summarizeCaaTags([
				{ flags: 0, tag: 'issue', value: 'letsencrypt.org' },
				{ flags: 0, tag: 'iodef', value: 'mailto:admin@example.com' },
			]),
		).toEqual({ hasIssue: true, hasIssuewild: false, hasIodef: true });
	});

	it('emits findings for missing tags', () => {
		const findings = getCaaValidationFindings({ hasIssue: false, hasIssuewild: false, hasIodef: true });
		expect(findings.map((finding) => finding.title)).toEqual(['No CAA issue tag', 'No CAA issuewild tag']);
	});

	it('produces the configured finding when all tags are present', () => {
		expect(getCaaValidationFindings({ hasIssue: true, hasIssuewild: true, hasIodef: true })).toHaveLength(0);
		expect(getCaaConfiguredFinding().severity).toBe('info');
	});
});
