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

	it('should handle missing check categories gracefully as fail', () => {
		// Only provide SPF — all controls referencing other categories should reflect accordingly
		const results = [makeCheckResult('spf', true)];
		const report = evaluateCompliance(results, 'sparse.com', 20, 'F');

		// NIST §4.3.1 SPF — passes (single category, present and passing)
		const spfControl = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.3.1');
		expect(spfControl!.status).toBe('pass');

		// NIST §4.3.2 DKIM — fail (no dkim data)
		const dkimControl = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.3.2');
		expect(dkimControl!.status).toBe('fail');

		// PCI 8.3.1 — [spf, dkim, dmarc], requirePass: false — only spf present and passes → partial
		const pci831 = report.frameworks.pci_dss_4.mappings.find((m) => m.controlId === '8.3.1');
		expect(pci831!.status).toBe('partial');
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
