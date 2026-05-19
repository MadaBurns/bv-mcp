// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import script from '../../scripts/generate-report.sh?raw';

describe('generate-report script safety', () => {
	it('passes TARGET_DOMAIN through the environment without mutating the Vitest spec', () => {
		expect(script).toContain('export TARGET_DOMAIN=$1');
		expect(script).toContain('test/generate-discovery-report.spec.ts');
		expect(script).not.toContain('sed -i');
		expect(script).not.toContain('SPEC_FILE.bak');
		expect(script).not.toContain('mv "$SPEC_FILE.bak"');
	});

	it('defaults report generation to deep discovery while preserving domain validation', () => {
		expect(script).toContain('BV_REPORT_DEPTH=${BV_REPORT_DEPTH:-deep}');
		expect(script).toContain('export BV_REPORT_DEPTH');
		expect(script).toMatch(/standard\|deep/);
		expect(script).toContain('export TARGET_DOMAIN=$1');
		expect(script).toContain('is not a valid domain');
	});

	it('writes to temporary report artifacts before promoting a QA-passing pair', () => {
		expect(script).toContain('BV_REPORT_JSON_PATH');
		expect(script).toContain('BV_REPORT_PDF_PATH');
		expect(script).toContain('scripts/audits/brand-report-qa.mjs');
		expect(script).not.toContain('rm -f "reports/$TARGET_DOMAIN-discovery-report.pdf" "reports/$TARGET_DOMAIN-discovery-report.json"');
	});
});
