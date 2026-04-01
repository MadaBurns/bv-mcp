// SPDX-License-Identifier: BUSL-1.1

/**
 * Compliance mapping tool.
 * Maps scan findings to compliance framework controls (NIST 800-177, PCI DSS 4.0, SOC 2, CIS Controls v8).
 * Designed for MSSPs that need client compliance reporting.
 */

import type { CheckResult } from '../lib/scoring';
import { scanDomain } from './scan-domain';
import type { ScanRuntimeOptions } from './scan/post-processing';
import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';

export type ComplianceFramework = 'nist_800_177' | 'pci_dss_4' | 'soc2' | 'cis_controls';

export interface ComplianceMapping {
	framework: ComplianceFramework;
	controlId: string;
	controlName: string;
	status: 'pass' | 'fail' | 'partial';
	relatedFindings: string[];
}

export interface ComplianceFrameworkSummary {
	totalControls: number;
	passing: number;
	failing: number;
	partial: number;
	percentage: number;
	mappings: ComplianceMapping[];
}

export interface ComplianceReport {
	domain: string;
	score: number;
	grade: string;
	frameworks: Record<ComplianceFramework, ComplianceFrameworkSummary>;
}

interface ComplianceControlDef {
	framework: ComplianceFramework;
	controlId: string;
	controlName: string;
	categories: string[];
	requirePass: boolean;
}

const COMPLIANCE_CONTROLS: ComplianceControlDef[] = [
	// NIST 800-177: Trustworthy Email
	{ framework: 'nist_800_177', controlId: '§4.3.1', controlName: 'SPF Authentication', categories: ['spf'], requirePass: true },
	{ framework: 'nist_800_177', controlId: '§4.3.2', controlName: 'DKIM Signing', categories: ['dkim'], requirePass: true },
	{ framework: 'nist_800_177', controlId: '§4.3.3', controlName: 'DMARC Policy', categories: ['dmarc'], requirePass: true },
	{ framework: 'nist_800_177', controlId: '§4.4', controlName: 'MTA-STS Transport Security', categories: ['mta_sts'], requirePass: true },
	{ framework: 'nist_800_177', controlId: '§4.5', controlName: 'DANE for SMTP', categories: ['dane'], requirePass: true },
	{ framework: 'nist_800_177', controlId: '§4.6', controlName: 'TLS Reporting', categories: ['tlsrpt'], requirePass: true },
	{ framework: 'nist_800_177', controlId: '§5.1', controlName: 'DNSSEC Validation', categories: ['dnssec'], requirePass: true },
	{ framework: 'nist_800_177', controlId: '§5.2', controlName: 'Certificate Authority Authorization', categories: ['caa'], requirePass: true },

	// PCI DSS 4.0
	{ framework: 'pci_dss_4', controlId: '4.2.1', controlName: 'Strong Cryptography for Transmission', categories: ['ssl', 'mta_sts'], requirePass: false },
	{ framework: 'pci_dss_4', controlId: '6.4.1', controlName: 'Public-Facing Web Application Security', categories: ['http_security', 'ssl'], requirePass: false },
	{ framework: 'pci_dss_4', controlId: '6.4.2', controlName: 'Web Application Firewall / CSP', categories: ['http_security'], requirePass: true },
	{ framework: 'pci_dss_4', controlId: '8.3.1', controlName: 'Authentication Controls', categories: ['spf', 'dkim', 'dmarc'], requirePass: false },
	{ framework: 'pci_dss_4', controlId: '11.3.1', controlName: 'Vulnerability Management', categories: ['ssl', 'dnssec'], requirePass: false },

	// SOC 2 (Trust Services Criteria)
	{ framework: 'soc2', controlId: 'CC6.1', controlName: 'Logical Access Security', categories: ['spf', 'dkim', 'dmarc', 'dnssec'], requirePass: false },
	{ framework: 'soc2', controlId: 'CC6.6', controlName: 'System Boundary Protection', categories: ['http_security', 'ssl', 'caa'], requirePass: false },
	{ framework: 'soc2', controlId: 'CC6.7', controlName: 'Data-in-Transit Encryption', categories: ['ssl', 'mta_sts', 'dane'], requirePass: false },
	{ framework: 'soc2', controlId: 'CC7.1', controlName: 'Monitoring and Detection', categories: ['tlsrpt', 'dmarc'], requirePass: false },
	{ framework: 'soc2', controlId: 'CC8.1', controlName: 'Change Management', categories: ['dnssec', 'ns'], requirePass: false },

	// CIS Controls v8
	{ framework: 'cis_controls', controlId: '9.2', controlName: 'DNS Filtering and Monitoring', categories: ['dnssec', 'ns'], requirePass: false },
	{ framework: 'cis_controls', controlId: '9.3', controlName: 'Email Security', categories: ['spf', 'dkim', 'dmarc', 'mta_sts'], requirePass: false },
	{ framework: 'cis_controls', controlId: '3.10', controlName: 'Encrypt Data in Transit', categories: ['ssl', 'mta_sts', 'dane'], requirePass: false },
	{ framework: 'cis_controls', controlId: '12.1', controlName: 'DNS Infrastructure', categories: ['dnssec', 'ns', 'caa'], requirePass: false },
];

/** All framework keys in stable display order. */
const FRAMEWORK_ORDER: ComplianceFramework[] = ['nist_800_177', 'pci_dss_4', 'soc2', 'cis_controls'];

/** Human-readable framework names. */
const FRAMEWORK_LABELS: Record<ComplianceFramework, string> = {
	nist_800_177: 'NIST 800-177',
	pci_dss_4: 'PCI DSS 4.0',
	soc2: 'SOC 2',
	cis_controls: 'CIS Controls',
};

/**
 * Evaluate compliance control status from check results (pure function).
 * Exported for direct unit testing without needing to mock scanDomain.
 */
export function evaluateCompliance(checkResults: CheckResult[], domain: string, score: number, grade: string): ComplianceReport {
	const resultsByCategory = new Map<string, CheckResult>();
	for (const r of checkResults) {
		resultsByCategory.set(r.category, r);
	}

	const frameworkMappings = new Map<ComplianceFramework, ComplianceMapping[]>();
	for (const fw of FRAMEWORK_ORDER) {
		frameworkMappings.set(fw, []);
	}

	for (const control of COMPLIANCE_CONTROLS) {
		const matchedResults = control.categories
			.map((cat) => resultsByCategory.get(cat))
			.filter((r): r is CheckResult => r !== undefined);

		let status: 'pass' | 'fail' | 'partial';
		const relatedFindings: string[] = [];

		if (matchedResults.length === 0) {
			// No check data for any mapped category — treat as fail
			status = 'fail';
		} else {
			const passingCount = matchedResults.filter((r) => r.passed).length;
			const failingResults = matchedResults.filter((r) => !r.passed);

			// Collect finding titles from failing categories
			for (const r of failingResults) {
				for (const f of r.findings) {
					if (f.severity !== 'info') {
						relatedFindings.push(f.title);
					}
				}
			}

			const totalCategories = control.categories.length;

			if (control.requirePass) {
				// All mapped categories must pass (and be present)
				status = passingCount === totalCategories ? 'pass' : 'fail';
			} else {
				// Partial pass allowed — missing categories count as not passing
				if (passingCount === totalCategories) {
					status = 'pass';
				} else if (passingCount > 0) {
					status = 'partial';
				} else {
					status = 'fail';
				}
			}
		}

		const mapping: ComplianceMapping = {
			framework: control.framework,
			controlId: control.controlId,
			controlName: control.controlName,
			status,
			relatedFindings,
		};

		frameworkMappings.get(control.framework)!.push(mapping);
	}

	const frameworks = {} as Record<ComplianceFramework, ComplianceFrameworkSummary>;
	for (const fw of FRAMEWORK_ORDER) {
		const mappings = frameworkMappings.get(fw)!;
		const passing = mappings.filter((m) => m.status === 'pass').length;
		const failing = mappings.filter((m) => m.status === 'fail').length;
		const partial = mappings.filter((m) => m.status === 'partial').length;
		const total = mappings.length;

		frameworks[fw] = {
			totalControls: total,
			passing,
			failing,
			partial,
			percentage: total > 0 ? Math.round((passing / total) * 100) : 0,
			mappings,
		};
	}

	return { domain, score, grade, frameworks };
}

/**
 * Map scan findings to compliance framework controls.
 * Runs a full scan (or uses cached results), then evaluates each control.
 */
export async function mapCompliance(domain: string, kv?: KVNamespace, runtimeOptions?: ScanRuntimeOptions): Promise<ComplianceReport> {
	const scanResult = await scanDomain(domain, kv, runtimeOptions);

	return evaluateCompliance(scanResult.checks, domain, scanResult.score.overall, scanResult.score.grade);
}

/**
 * Format a compliance report for display.
 */
export function formatCompliance(report: ComplianceReport, format: OutputFormat = 'full'): string {
	const lines: string[] = [];

	if (format === 'compact') {
		lines.push(`Compliance: ${sanitizeOutputText(report.domain, 253)} — ${report.score}/100 (${report.grade})`);
		lines.push('');

		for (const fw of FRAMEWORK_ORDER) {
			const summary = report.frameworks[fw];
			const label = FRAMEWORK_LABELS[fw];
			lines.push(`${label}: ${summary.passing}/${summary.totalControls} controls passing (${summary.percentage}%)`);

			for (const m of summary.mappings) {
				const icon = m.status === 'pass' ? ' \u2713' : m.status === 'partial' ? ' ~' : ' \u2717';
				const findingSuffix =
					m.relatedFindings.length > 0 ? ` — ${sanitizeOutputText(m.relatedFindings[0], 80)}` : '';
				lines.push(`${icon} ${m.controlId} ${sanitizeOutputText(m.controlName, 60)}${m.status !== 'pass' ? findingSuffix : ''}`);
			}
			lines.push('');
		}
	} else {
		lines.push(`# Compliance Report: ${sanitizeOutputText(report.domain, 253)}`);
		lines.push(`**Score:** ${report.score}/100 (${report.grade})`);
		lines.push('');

		for (const fw of FRAMEWORK_ORDER) {
			const summary = report.frameworks[fw];
			const label = FRAMEWORK_LABELS[fw];
			lines.push(`## ${label}`);
			lines.push(
				`**${summary.passing}/${summary.totalControls}** controls passing (${summary.percentage}%) | ` +
					`${summary.failing} failing | ${summary.partial} partial`,
			);
			lines.push('');

			for (const m of summary.mappings) {
				const icon = m.status === 'pass' ? '\u2705' : m.status === 'partial' ? '\u26A0\uFE0F' : '\u274C';
				lines.push(`${icon} **${m.controlId} ${sanitizeOutputText(m.controlName, 60)}** — ${m.status.toUpperCase()}`);

				if (m.relatedFindings.length > 0) {
					for (const f of m.relatedFindings) {
						lines.push(`  - ${sanitizeOutputText(f, 120)}`);
					}
				}
			}
			lines.push('');
		}
	}

	return lines.join('\n').trimEnd();
}
