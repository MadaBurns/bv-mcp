import { describe, expect, it } from 'vitest';

import { getCaaConfiguredFinding, getCaaValidationFindings, summarizeCaaTags } from '../src/tools/caa-analysis';

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