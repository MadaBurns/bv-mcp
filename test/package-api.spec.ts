import { describe, expect, it } from 'vitest';

describe('package public API', () => {
	async function getModule() {
		return import('../src/package');
	}

	it('exports the scanner entrypoints from the package root', async () => {
		const mod = await getModule();

		expect(mod.scanDomain).toBeTypeOf('function');
		expect(mod.formatScanReport).toBeTypeOf('function');
		expect(mod.checkSpf).toBeTypeOf('function');
		expect(mod.checkDmarc).toBeTypeOf('function');
		expect(mod.checkDkim).toBeTypeOf('function');
		expect(mod.checkDnssec).toBeTypeOf('function');
		expect(mod.explainFinding).toBeTypeOf('function');
		expect(mod.validateDomain).toBeTypeOf('function');
		expect(mod.queryDns).toBeTypeOf('function');
		expect(mod.computeScanScore).toBeTypeOf('function');
		expect(mod.computeProfileAwareScanScore).toBeTypeOf('function');
	});

	it('supports helper-only usage without MCP transport wiring', async () => {
		const { createFinding, buildCheckResult, explainFinding, formatExplanation } = await getModule();

		const result = buildCheckResult('spf', [
			createFinding('spf', 'No SPF record found', 'critical', 'No SPF record found for example.com'),
		]);
		const explanation = explainFinding('SPF', 'fail', result.findings[0].detail);

		expect(result.category).toBe('spf');
		expect(explanation.title).toBeTruthy();
		expect(formatExplanation(explanation)).toContain('Recommendation');
	});

	// SQ-66: package.ts used to export only the internal 9-band `scoreToGrade` (which
	// takes a plain `number` and has no way to represent "ungraded"), so a direct npm
	// consumer had no way to render the same customer-facing scale, or to distinguish
	// "never measured" from a real letter, without re-implementing displayGradeFor
	// themselves.
	it('exports the customer-facing display-grade chokepoint, not just the internal 9-band scale', async () => {
		const mod = await getModule();

		expect(mod.displayGradeFor).toBeTypeOf('function');
		expect(mod.nistScoreToGrade).toBeTypeOf('function');
		expect(mod.scoreToGrade).toBeTypeOf('function');
		expect(mod.formatScoreGrade).toBeTypeOf('function');
		expect(mod.UNGRADED_DISPLAY).toBeTypeOf('string');
	});

	it('a null/ungraded score does NOT yield a fabricated grade through the package surface', async () => {
		const { displayGradeFor } = await getModule();

		// An ungraded scan (`overall`/`grade` both null) must stay `null` through the
		// exported chokepoint — never collapse to `scoreToGrade`'s 'F' fallback.
		expect(displayGradeFor({ overall: null, grade: null })).toBeNull();
	});

	it('renders a real letter for a measured scan through the package surface (control)', async () => {
		const { displayGradeFor, scoreToGrade } = await getModule();

		const graded = displayGradeFor({ overall: 78, grade: scoreToGrade(78) });
		expect(graded).not.toBeNull();
		expect(graded).toBe('C');
	});
});
