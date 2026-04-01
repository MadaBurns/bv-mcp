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
});