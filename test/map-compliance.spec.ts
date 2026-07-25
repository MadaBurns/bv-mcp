import { describe, it, expect } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import { evaluateCompliance, formatCompliance } from '../src/tools/map-compliance';
import type { ComplianceReport } from '../src/tools/map-compliance';

/** Helper to build a minimal CheckResult for compliance mapping tests. */
function makeCheckResult(
	category: string,
	passed: boolean,
	findings: Array<{ title: string; severity: string }> = [],
): CheckResult {
	return {
		category,
		passed,
		score: passed ? 100 : 0,
		findings: findings.map((f) => ({
			category,
			title: f.title,
			severity: f.severity,
			detail: '',
		})),
	} as CheckResult;
}

/** Build a full set of check results where every category passes. */
function makeAllPassing(): CheckResult[] {
	return [
		makeCheckResult('spf', true),
		makeCheckResult('dkim', true),
		makeCheckResult('dmarc', true),
		makeCheckResult('mta_sts', true),
		makeCheckResult('dane', true),
		makeCheckResult('tlsrpt', true),
		makeCheckResult('dnssec', true),
		makeCheckResult('caa', true),
		makeCheckResult('ssl', true),
		makeCheckResult('http_security', true),
		makeCheckResult('ns', true),
		makeCheckResult('mx', true),
		makeCheckResult('authoritative_dns_infra', true),
	];
}

describe('evaluateCompliance', () => {
	it('should mark all controls as pass when all checks pass', () => {
		const results = makeAllPassing();
		const report = evaluateCompliance(results, 'example.com', 95, 'A+');

		expect(report.domain).toBe('example.com');
		expect(report.score).toBe(95);
		expect(report.grade).toBe('A+');

		// Every framework should have 0 failing and 0 partial
		for (const fw of ['nist_800_177', 'pci_dss_4', 'soc2', 'cis_controls'] as const) {
			const summary = report.frameworks[fw];
			expect(summary.failing).toBe(0);
			expect(summary.partial).toBe(0);
			expect(summary.passing).toBe(summary.totalControls);
			expect(summary.percentage).toBe(100);
		}
	});

	it('should fail NIST email controls when SPF/DKIM/DMARC fail', () => {
		const results = makeAllPassing().map((r) => {
			if (r.category === 'spf' || r.category === 'dkim' || r.category === 'dmarc') {
				return makeCheckResult(r.category, false, [{ title: `${r.category.toUpperCase()} not configured`, severity: 'high' }]);
			}
			return r;
		});

		const report = evaluateCompliance(results, 'example.com', 40, 'F');
		const nist = report.frameworks.nist_800_177;

		// §4.3.1 (SPF), §4.3.2 (DKIM), §4.3.3 (DMARC) should all fail
		const spfControl = nist.mappings.find((m) => m.controlId === '§4.3.1');
		const dkimControl = nist.mappings.find((m) => m.controlId === '§4.3.2');
		const dmarcControl = nist.mappings.find((m) => m.controlId === '§4.3.3');

		expect(spfControl!.status).toBe('fail');
		expect(dkimControl!.status).toBe('fail');
		expect(dmarcControl!.status).toBe('fail');

		expect(spfControl!.relatedFindings).toContain('SPF not configured');
		expect(dkimControl!.relatedFindings).toContain('DKIM not configured');
		expect(dmarcControl!.relatedFindings).toContain('DMARC not configured');
	});

	it('should fail NIST §5.1 and mark SOC2 CC6.1 as partial when DNSSEC fails', () => {
		const results = makeAllPassing().map((r) => {
			if (r.category === 'dnssec') {
				return makeCheckResult('dnssec', false, [{ title: 'DNSSEC not enabled', severity: 'medium' }]);
			}
			return r;
		});

		const report = evaluateCompliance(results, 'example.com', 71, 'C+');

		// NIST §5.1 DNSSEC Validation — requirePass: true, single category → fail
		const dnssecControl = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§5.1');
		expect(dnssecControl!.status).toBe('fail');
		expect(dnssecControl!.relatedFindings).toContain('DNSSEC not enabled');

		// SOC2 CC6.1 — requirePass: false, categories: [spf, dkim, dmarc, dnssec]
		// 3 passing, 1 failing → partial
		const cc61 = report.frameworks.soc2.mappings.find((m) => m.controlId === 'CC6.1');
		expect(cc61!.status).toBe('partial');
	});

	it('maps authoritative DNS infra failures into DNS infrastructure controls', () => {
		const results = [
			...makeAllPassing(),
			makeCheckResult('authoritative_dns_infra', false, [
				{ title: 'Route leak or hijack signal observed', severity: 'critical' },
			]),
		];

		const report = evaluateCompliance(results, 'a.root-servers.net', 40, 'F');

		const cisDnsInfra = report.frameworks.cis_controls.mappings.find((m) => m.controlId === '12.1');
		expect(cisDnsInfra!.status).toBe('partial');
		expect(cisDnsInfra!.relatedFindings).toContain('Route leak or hijack signal observed');

		const socBoundary = report.frameworks.soc2.mappings.find((m) => m.controlId === 'CC6.6');
		expect(socBoundary!.status).toBe('partial');
		expect(socBoundary!.relatedFindings).toContain('Route leak or hijack signal observed');
	});

	it('should compute partial status for multi-category controls with mixed results', () => {
		const results = [
			makeCheckResult('spf', true),
			makeCheckResult('dkim', false, [{ title: 'DKIM missing', severity: 'high' }]),
			makeCheckResult('dmarc', true),
			makeCheckResult('mta_sts', false, [{ title: 'No MTA-STS record', severity: 'medium' }]),
			makeCheckResult('dane', false, [{ title: 'No DANE records', severity: 'low' }]),
			makeCheckResult('tlsrpt', true),
			makeCheckResult('dnssec', true),
			makeCheckResult('caa', true),
			makeCheckResult('ssl', true),
			makeCheckResult('http_security', true),
			makeCheckResult('ns', true),
		];

		const report = evaluateCompliance(results, 'mixed.com', 65, 'C');

		// PCI DSS 8.3.1 — [spf, dkim, dmarc], requirePass: false
		// 2 passing, 1 failing → partial
		const pci831 = report.frameworks.pci_dss_4.mappings.find((m) => m.controlId === '8.3.1');
		expect(pci831!.status).toBe('partial');
		expect(pci831!.relatedFindings).toContain('DKIM missing');

		// CIS 9.3 — [spf, dkim, dmarc, mta_sts], requirePass: false
		// 2 passing, 2 failing → partial
		const cis93 = report.frameworks.cis_controls.mappings.find((m) => m.controlId === '9.3');
		expect(cis93!.status).toBe('partial');

		// SOC2 CC6.7 — [ssl, mta_sts, dane], requirePass: false
		// 1 passing (ssl), 2 failing → partial
		const cc67 = report.frameworks.soc2.mappings.find((m) => m.controlId === 'CC6.7');
		expect(cc67!.status).toBe('partial');
	});

	it('should compute percentage correctly', () => {
		// NIST 800-177 has 8 controls. Make 5 pass, 3 fail.
		const results = [
			makeCheckResult('spf', true),
			makeCheckResult('dkim', true),
			makeCheckResult('dmarc', true),
			makeCheckResult('mta_sts', false, [{ title: 'Missing MTA-STS', severity: 'medium' }]),
			makeCheckResult('dane', false, [{ title: 'Missing DANE', severity: 'low' }]),
			makeCheckResult('tlsrpt', true),
			makeCheckResult('dnssec', true),
			makeCheckResult('caa', false, [{ title: 'Missing CAA', severity: 'medium' }]),
			makeCheckResult('ssl', true),
			makeCheckResult('http_security', true),
			makeCheckResult('ns', true),
		];

		const report = evaluateCompliance(results, 'pct.com', 70, 'C+');
		const nist = report.frameworks.nist_800_177;

		// 5 pass (spf, dkim, dmarc, tlsrpt, dnssec), 3 fail (mta_sts, dane, caa)
		expect(nist.passing).toBe(5);
		expect(nist.failing).toBe(3);
		expect(nist.partial).toBe(0);
		expect(nist.totalControls).toBe(8);
		expect(nist.percentage).toBe(63); // Math.round(5/8 * 100) = 63
	});

	it('should populate relatedFindings only from non-info severity findings', () => {
		const results = [
			makeCheckResult('spf', false, [
				{ title: 'SPF misconfigured', severity: 'high' },
				{ title: 'SPF note', severity: 'info' },
			]),
			makeCheckResult('dkim', true),
			makeCheckResult('dmarc', true),
			makeCheckResult('dnssec', true),
			makeCheckResult('ssl', true),
			makeCheckResult('http_security', true),
			makeCheckResult('ns', true),
			makeCheckResult('caa', true),
			makeCheckResult('mta_sts', true),
			makeCheckResult('dane', true),
			makeCheckResult('tlsrpt', true),
		];

		const report = evaluateCompliance(results, 'findings.com', 80, 'B');

		// NIST §4.3.1 SPF — should have the high finding but not info
		const spfControl = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.3.1');
		expect(spfControl!.relatedFindings).toContain('SPF misconfigured');
		expect(spfControl!.relatedFindings).not.toContain('SPF note');
	});

	it('should include all 4 frameworks in output', () => {
		const results = makeAllPassing();
		const report = evaluateCompliance(results, 'example.com', 95, 'A+');

		expect(Object.keys(report.frameworks)).toHaveLength(4);
		expect(report.frameworks.nist_800_177).toBeDefined();
		expect(report.frameworks.pci_dss_4).toBeDefined();
		expect(report.frameworks.soc2).toBeDefined();
		expect(report.frameworks.cis_controls).toBeDefined();
	});

	it('should report a control with NO check evidence as not_assessed, never as fail', () => {
		// Only provide SPF — all controls referencing other categories should reflect accordingly
		const results = [makeCheckResult('spf', true)];
		const report = evaluateCompliance(results, 'sparse.com', 20, 'F');

		// NIST §4.3.1 SPF — passes (single category, present and passing)
		const spfControl = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.3.1');
		expect(spfControl!.status).toBe('pass');

		// NIST §4.3.2 DKIM — no dkim check ran, so there is no evidence either way.
		// Reporting that as `fail` asserts a requirement was found unmet; it wasn't looked at.
		const dkimControl = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.3.2');
		expect(dkimControl!.status).toBe('not_assessed');

		// PCI 8.3.1 — [spf, dkim, dmarc], requirePass: false — only spf present and passes → partial.
		// A control with SOME evidence is still graded; only ZERO evidence abstains.
		const pci831 = report.frameworks.pci_dss_4.mappings.find((m) => m.controlId === '8.3.1');
		expect(pci831!.status).toBe('partial');

		// The framework summary drops the unassessable control from its denominator
		// rather than counting it as a failure.
		const nist = report.frameworks.nist_800_177;
		expect(nist.totalControls).toBe(8);
		expect(nist.notAssessed).toBe(7);
		expect(nist.assessedControls).toBe(1);
		expect(nist.passing + nist.failing + nist.partial).toBe(nist.assessedControls);
		// The one assessable control passed. Computing this over `totalControls`
		// instead would report 13% — a compliance number driven by how much was
		// never looked at. This assertion is what separates the two denominators.
		expect(nist.percentage).toBe(100);
	});
});

/**
 * The banked defect. `map_compliance` returns `buildToolResult(text, result, format)`,
 * so the raw `ComplianceReport` becomes BOTH the MCP `structuredContent` and the
 * `STRUCTURED_RESULT` comment. Task 3 corrected the PROSE (a "not measured" score
 * line plus a caveat) but left the payload emitting, per control:
 *
 *     {"passing":0,"failing":5,"percentage":0,"status":"fail"}
 *
 * — a fabricated 0% compliance verdict, with no caveat field at all, for a domain
 * that was never assessed. `percentage: 0` is a number something will chart.
 * A domain that does not exist has not failed SOC 2.
 *
 * These assertions run against the SERIALIZED wire payload deliberately: a
 * prose-only fix is exactly the defect being closed, so asserting on rendered
 * text could not have caught it.
 */
describe('map_compliance structured payload — a domain that was never measured', () => {
	const FRAMEWORKS = ['nist_800_177', 'pci_dss_4', 'soc2', 'cis_controls'] as const;

	async function unmeasuredReport() {
		const { evaluateCompliance: evaluate } = await import('../src/tools/map-compliance');
		return evaluate([], 'never-measured.example', null, null);
	}

	it('marks every control not_assessed — absence of evidence is not a failed requirement', async () => {
		const report = await unmeasuredReport();
		const mappings = FRAMEWORKS.flatMap((fw) => report.frameworks[fw].mappings);

		// Fixture-reachability guard: with an empty mappings list every assertion
		// below would hold vacuously and this test would protect nothing.
		expect(mappings.length).toBeGreaterThan(20);
		expect(mappings.filter((m) => m.status === 'fail')).toEqual([]);
		expect(mappings.every((m) => m.status === 'not_assessed')).toBe(true);
	});

	it('omits the compliance percentage instead of reporting 0%', async () => {
		const report = await unmeasuredReport();
		for (const fw of FRAMEWORKS) {
			const summary = report.frameworks[fw];
			expect(summary.totalControls).toBeGreaterThan(0);
			expect(summary.percentage).toBeNull();
			expect(summary.assessedControls).toBe(0);
			expect(summary.notAssessed).toBe(summary.totalControls);
			expect(summary.failing).toBe(0);
			expect(summary.passing).toBe(0);
		}
	});

	it('carries the caveat as DATA, not only as prose', async () => {
		const report = await unmeasuredReport();
		expect(report.assessed).toBe(false);
		expect(report.caveat).toMatch(/not assessable/i);
	});

	it('emits no fabricated verdict on either machine channel (structuredContent AND the STRUCTURED_RESULT comment)', async () => {
		const { formatCompliance: format } = await import('../src/tools/map-compliance');
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		const report = await unmeasuredReport();
		const result = buildToolResult(format(report, 'full'), report, 'full');

		// Channel 1 — the MCP-standard structuredContent field.
		expect(result.structuredContent).toBeDefined();
		const wire = JSON.stringify(result.structuredContent);
		expect(wire).not.toContain('"status":"fail"');
		expect(wire).not.toContain('"percentage":0');
		expect(wire).toContain('"status":"not_assessed"');
		expect(wire).toContain('"assessed":false');

		// Channel 2 — the legacy STRUCTURED_RESULT comment some clients still parse.
		const comment = result.content.map((c) => c.text).find((t) => t.includes('STRUCTURED_RESULT'));
		expect(comment).toBeDefined();
		expect(comment).not.toContain('"status":"fail"');
		expect(comment).not.toContain('"percentage":0');
		expect(comment).toContain('"assessed":false');
	});

	it('still emits a real fail verdict and a numeric percentage for a MEASURED domain (control)', async () => {
		const { evaluateCompliance: evaluate, formatCompliance: format } = await import('../src/tools/map-compliance');
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		// 5 of the 8 NIST controls pass; mta_sts/dane/caa genuinely fail.
		const measured = evaluate(
			[
				makeCheckResult('spf', true),
				makeCheckResult('dkim', true),
				makeCheckResult('dmarc', true),
				makeCheckResult('mta_sts', false, [{ title: 'Missing MTA-STS', severity: 'medium' }]),
				makeCheckResult('dane', false, [{ title: 'Missing DANE', severity: 'low' }]),
				makeCheckResult('tlsrpt', true),
				makeCheckResult('dnssec', true),
				makeCheckResult('caa', false, [{ title: 'Missing CAA', severity: 'medium' }]),
				makeCheckResult('ssl', true),
				makeCheckResult('http_security', true),
				makeCheckResult('ns', true),
			],
			'measured.example',
			73,
			'C+',
		);
		const wire = JSON.stringify(buildToolResult(format(measured, 'full'), measured, 'full').structuredContent);

		// Without these the assertions above would all hold under an implementation
		// that reported EVERY control as not_assessed and every percentage as null.
		expect(measured.assessed).toBe(true);
		expect(measured.caveat).toBeNull();
		expect(wire).toContain('"status":"fail"');
		expect(measured.frameworks.nist_800_177.percentage).toBe(63);
		expect(measured.frameworks.nist_800_177.notAssessed).toBe(0);
		expect(measured.frameworks.nist_800_177.assessedControls).toBe(8);
	});
});

describe('formatCompliance', () => {
	function makeReport(): ComplianceReport {
		const results = [
			makeCheckResult('spf', true),
			makeCheckResult('dkim', true),
			makeCheckResult('dmarc', true),
			makeCheckResult('mta_sts', false, [{ title: 'No MTA-STS record', severity: 'medium' }]),
			makeCheckResult('dane', false, [{ title: 'No DANE records', severity: 'low' }]),
			makeCheckResult('tlsrpt', true),
			makeCheckResult('dnssec', false, [{ title: 'DNSSEC not enabled', severity: 'medium' }]),
			makeCheckResult('caa', true),
			makeCheckResult('ssl', true),
			makeCheckResult('http_security', true),
			makeCheckResult('ns', true),
		];
		return evaluateCompliance(results, 'fmt.com', 71, 'C+');
	}

	it('should produce compact format with status icons', () => {
		const report = makeReport();
		const output = formatCompliance(report, 'compact');

		expect(output).toContain('Compliance: fmt.com');
		expect(output).toContain('71/100 (C+)');
		expect(output).toContain('NIST 800-177:');
		expect(output).toContain('PCI DSS 4.0:');
		expect(output).toContain('SOC 2:');
		expect(output).toContain('CIS Controls:');
		// Check mark for passing control
		expect(output).toContain('\u2713 §4.3.1');
		// X mark for failing control
		expect(output).toContain('\u2717 §5.1');
	});

	it('should produce full format with markdown headers and details', () => {
		const report = makeReport();
		const output = formatCompliance(report, 'full');

		expect(output).toContain('# Compliance Report: fmt.com');
		expect(output).toContain('**Score:** 71/100 (C+)');
		expect(output).toContain('## NIST 800-177');
		expect(output).toContain('## PCI DSS 4.0');
		expect(output).toContain('## SOC 2');
		expect(output).toContain('## CIS Controls');
		// Should show related findings as sub-items
		expect(output).toContain('DNSSEC not enabled');
		expect(output).toContain('No MTA-STS record');
	});

	it.each(['compact', 'full'] as const)('renders "not measured" instead of null/100 (null) for an ungraded scan [%s]', async (format) => {
		const { evaluateCompliance: evaluate, formatCompliance: fmt } = await import('../src/tools/map-compliance');
		const report = evaluate([], 'never-measured.example', null, null);
		const text = fmt(report, format);

		expect(text).toContain('not measured');
		expect(text).not.toContain('null');
		expect(text).not.toContain('/100');
		// The per-control column must not read as a failure verdict either.
		expect(text).not.toMatch(/\bFAIL\b/);
		expect(text.toLowerCase()).toContain('not assessed');
	});

	it('should not show related findings for passing controls in compact format', () => {
		const results = makeAllPassing();
		const report = evaluateCompliance(results, 'pass.com', 95, 'A+');
		const output = formatCompliance(report, 'compact');

		// Passing controls should not have finding text appended
		const spfLine = output.split('\n').find((l) => l.includes('§4.3.1'));
		expect(spfLine).toBeDefined();
		expect(spfLine).not.toContain(' — ');
	});
});
