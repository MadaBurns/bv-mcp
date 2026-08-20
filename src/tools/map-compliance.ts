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
import { displayGradeFor, formatScoreGrade, hasCompletedEvidence, isCompletedCheck, UNGRADED_DISPLAY } from '../lib/ungraded-display';
// `isSatisfiedControl` and the applicability derivation are SHARED with
// `compare_baseline` (#706), which had the identical defect on the enforcement
// surface. Both live in `lib/control-presence.ts` so the reporting tool and the
// policy gate cannot drift on what "satisfied" and "applicable" mean.
import { isSatisfiedControl, notApplicableCategoriesFor } from '../lib/control-presence';

export type ComplianceFramework = 'nist_800_177' | 'pci_dss_4' | 'soc2' | 'cis_controls';

/**
 * A control's verdict.
 *
 * `not_assessed` is NOT a soft failure — it is the absence of a verdict. A control is
 * `not_assessed` when its mapped categories produced NO check data at all, OR when they
 * produced check data that never COMPLETED (`checkStatus: 'timeout'`/`'error'` — a
 * transient DNS/network failure, not a measurement). Either way the control was never
 * actually looked at, and reporting that as `fail` asserts a requirement was found
 * unmet. A domain that does not exist has not failed SOC 2 — and neither has one whose
 * resolver was slow.
 */
export type ComplianceStatus = 'pass' | 'fail' | 'partial' | 'not_assessed';

export interface ComplianceMapping {
	framework: ComplianceFramework;
	controlId: string;
	controlName: string;
	status: ComplianceStatus;
	relatedFindings: string[];
}

export interface ComplianceFrameworkSummary {
	totalControls: number;
	passing: number;
	failing: number;
	partial: number;
	/**
	 * Controls with no COMPLETED check evidence — either no check data at all, or every
	 * matched check timed out/errored before finishing. Excluded from `percentage`,
	 * never counted as failures.
	 */
	notAssessed: number;
	/** `totalControls - notAssessed` — the denominator `percentage` is computed over. */
	assessedControls: number;
	/**
	 * Percent of ASSESSED controls passing, or `null` when nothing could be
	 * assessed. Deliberately nullable rather than 0: a `0` here is a number a
	 * dashboard will chart as total non-compliance for a domain nobody measured.
	 */
	percentage: number | null;
	mappings: ComplianceMapping[];
}

export interface ComplianceReport {
	domain: string;
	/** `null` when the scan produced no gradeable measurement. Never a coerced 0. */
	score: number | null;
	/** `null` when the scan produced no gradeable measurement. Never a fabricated letter. */
	grade: string | null;
	/**
	 * Did ANY check evidence exist for this domain? `false` means the control
	 * results carry no verdict at all. Machine consumers (bv-web-prod, dashboards,
	 * LLM clients reading `structuredContent`) must gate on this before charting
	 * anything — it is the structured twin of the prose caveat below.
	 */
	assessed: boolean;
	/** Populated only when `assessed` is false; `null` otherwise. */
	caveat: string | null;
	frameworks: Record<ComplianceFramework, ComplianceFrameworkSummary>;
}

/**
 * The single wording of the "nothing was assessed" qualifier, carried on BOTH
 * surfaces — the prose a customer reads and the `caveat` field a machine consumes.
 * Task 3 corrected only the prose; the payload kept shipping a fabricated 0%.
 */
export const UNASSESSED_COMPLIANCE_CAVEAT =
	'No checks ran for this domain, so the controls below are NOT assessable — each is reported as NOT ASSESSED (absence of evidence), never as a requirement found unmet.';

/**
 * F3: a SEPARATE wording from {@link UNASSESSED_COMPLIANCE_CAVEAT} for a different
 * failure mode. `UNASSESSED_COMPLIANCE_CAVEAT` describes "no checks ran" (NXDOMAIN,
 * broken zone — `checks: []`). This describes "checks ran, none of them finished" — a
 * total DoH/network outage where every attempted check carries a transient
 * `checkStatus: 'timeout'`/`'error'` (the `buildDnsErrorResult`/`safeCheck` shape).
 * Saying "no checks ran" there would be false — N checks DID run — and would mislead a
 * customer/operator into thinking the domain has no measurable DNS presence at all,
 * rather than that a retry (once the transient condition clears) would work.
 */
export function buildAllTransientCaveat(attempted: number): string {
	return (
		`${attempted} check${attempted === 1 ? '' : 's'} ${attempted === 1 ? 'was' : 'were'} attempted for this domain, ` +
		`but none of them completed (transient DNS/network failure) — the controls below are NOT assessable from this scan. ` +
		`This is different from no checks running at all: retry once the transient condition clears.`
	);
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
	{
		framework: 'nist_800_177',
		controlId: '§5.2',
		controlName: 'Certificate Authority Authorization',
		categories: ['caa'],
		requirePass: true,
	},

	// PCI DSS 4.0
	{
		framework: 'pci_dss_4',
		controlId: '4.2.1',
		controlName: 'Strong Cryptography for Transmission',
		categories: ['ssl', 'mta_sts'],
		requirePass: false,
	},
	{
		framework: 'pci_dss_4',
		controlId: '6.4.1',
		controlName: 'Public-Facing Web Application Security',
		categories: ['http_security', 'ssl'],
		requirePass: false,
	},
	{
		framework: 'pci_dss_4',
		controlId: '6.4.2',
		controlName: 'Web Application Firewall / CSP',
		categories: ['http_security'],
		requirePass: true,
	},
	{
		framework: 'pci_dss_4',
		controlId: '8.3.1',
		controlName: 'Authentication Controls',
		categories: ['spf', 'dkim', 'dmarc'],
		requirePass: false,
	},
	{
		framework: 'pci_dss_4',
		controlId: '11.3.1',
		controlName: 'Vulnerability Management',
		categories: ['ssl', 'dnssec'],
		requirePass: false,
	},

	// SOC 2 (Trust Services Criteria)
	{
		framework: 'soc2',
		controlId: 'CC6.1',
		controlName: 'Logical Access Security',
		categories: ['spf', 'dkim', 'dmarc', 'dnssec'],
		requirePass: false,
	},
	{
		framework: 'soc2',
		controlId: 'CC6.6',
		controlName: 'System Boundary Protection',
		categories: ['http_security', 'ssl', 'caa', 'authoritative_dns_infra'],
		requirePass: false,
	},
	{
		framework: 'soc2',
		controlId: 'CC6.7',
		controlName: 'Data-in-Transit Encryption',
		categories: ['ssl', 'mta_sts', 'dane'],
		requirePass: false,
	},
	{ framework: 'soc2', controlId: 'CC7.1', controlName: 'Monitoring and Detection', categories: ['tlsrpt', 'dmarc'], requirePass: false },
	{ framework: 'soc2', controlId: 'CC8.1', controlName: 'Change Management', categories: ['dnssec', 'ns'], requirePass: false },

	// CIS Controls v8
	{
		framework: 'cis_controls',
		controlId: '9.2',
		controlName: 'DNS Filtering and Monitoring',
		categories: ['dnssec', 'ns'],
		requirePass: false,
	},
	{
		framework: 'cis_controls',
		controlId: '9.3',
		controlName: 'Email Security',
		categories: ['spf', 'dkim', 'dmarc', 'mta_sts'],
		requirePass: false,
	},
	{
		framework: 'cis_controls',
		controlId: '3.10',
		controlName: 'Encrypt Data in Transit',
		categories: ['ssl', 'mta_sts', 'dane'],
		requirePass: false,
	},
	{
		framework: 'cis_controls',
		controlId: '12.1',
		controlName: 'DNS Infrastructure',
		categories: ['dnssec', 'ns', 'caa', 'authoritative_dns_infra'],
		requirePass: false,
	},
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
 *
 * `notApplicableCategories` comes from the scan's own applicability pass — see
 * `isCategoryNonApplicable` in `scan/format-report.ts`, the single source that
 * `categoryScores` and `notApplicableCategories` both derive from. Callers that omit it
 * get the previous behaviour for every category.
 */
export function evaluateCompliance(
	checkResults: CheckResult[],
	domain: string,
	score: number | null,
	grade: string | null,
	notApplicableCategories: readonly string[] = [],
): ComplianceReport {
	const resultsByCategory = new Map<string, CheckResult>();
	for (const r of checkResults) {
		resultsByCategory.set(r.category, r);
	}

	const notApplicable = new Set(notApplicableCategories);

	const frameworkMappings = new Map<ComplianceFramework, ComplianceMapping[]>();
	for (const fw of FRAMEWORK_ORDER) {
		frameworkMappings.set(fw, []);
	}

	for (const control of COMPLIANCE_CONTROLS) {
		const matchedResults = control.categories.map((cat) => resultsByCategory.get(cat)).filter((r): r is CheckResult => r !== undefined);

		let status: ComplianceStatus;
		const relatedFindings: string[] = [];

		// A category the SCAN itself declared not-applicable carries no verdict for this
		// control. Dropping it here (rather than letting it fall through to the presence
		// rule below) is what stops a `web_only` domain — which legitimately publishes no
		// MTA-STS record — from newly reading "NIST §4.4 — FAIL". The applicability
		// decision is NOT re-derived here: `isCategoryNonApplicable` in
		// `scan/format-report.ts` is the single source `categoryScores` and
		// `notApplicableCategories` both come from, and its verdict is passed in.
		const applicableResults = matchedResults.filter((r) => !notApplicable.has(r.category));
		const notApplicableCount = matchedResults.length - applicableResults.length;

		if (applicableResults.length === 0) {
			// No check data for ANY mapped category — there is no evidence either way,
			// so this control has no verdict. It used to be reported as `fail`, which
			// made an unmeasured domain (NXDOMAIN / broken zone — `checks: []`) render
			// as a complete framework-by-framework compliance failure. The same reasoning
			// covers a control whose every mapped category was declared inapplicable.
			status = 'not_assessed';
		} else {
			// A matched result whose check never COMPLETED (checkStatus 'timeout'/'error')
			// is not evidence either way — `buildDnsErrorResult`/`safeCheck` return those
			// as `passed: false`, indistinguishable from a genuine failure unless we
			// partition on `checkStatus` here. `isCompletedCheck` is the single SSOT
			// spelling of "absent or 'completed' means the check ran normally" — see
			// `test/audits/*evidence*` for the ban on re-deriving this locally.
			const completed = applicableResults.filter(isCompletedCheck);

			if (completed.length === 0) {
				// Every matched category was measured-AT but never measured — one slow
				// resolver must not turn into "DMARC Policy — FAIL" on a healthy domain.
				status = 'not_assessed';
			} else {
				const passingCount = completed.filter(isSatisfiedControl).length;
				const failingResults = completed.filter((r) => !isSatisfiedControl(r));

				// Collect finding titles from failing categories — completed ones only, so a
				// transient check's "check error"/"timed out" title never reads as a graded
				// compliance finding.
				for (const r of failingResults) {
					for (const f of r.findings) {
						if (f.severity !== 'info') {
							relatedFindings.push(f.title);
						}
					}
				}

				// F1: a category that only produced TRANSIENT evidence must not occupy a
				// non-passing slot in the denominator either — that's the same bug as
				// grading on it, just one level up. `control.categories.length` still
				// counts a category with NO data at all as "not passing" (pre-existing,
				// intentional — see the sparse-evidence test), so only the categories that
				// matched AND were excluded as transient are subtracted here. Since we're
				// past the `completed.length === 0` guard above, `completed.length >= 1`,
				// and `totalCategories >= completed.length` always holds — the all-transient
				// case (denominator hitting 0) already short-circuited to `not_assessed`
				// before this line, so no separate zero-check is needed here.
				const transientCount = applicableResults.length - completed.length;
				const totalCategories = control.categories.length - transientCount - notApplicableCount;

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
		const notAssessed = mappings.filter((m) => m.status === 'not_assessed').length;
		const total = mappings.length;
		const assessedControls = total - notAssessed;

		frameworks[fw] = {
			totalControls: total,
			passing,
			failing,
			partial,
			notAssessed,
			assessedControls,
			// OMIT rather than zero. A control nobody could assess is out of the
			// denominator; with none assessable there is no percentage to report.
			// When every control has evidence (the normal case) this is identical to
			// the previous `passing / totalControls`.
			percentage: assessedControls > 0 ? Math.round((passing / assessedControls) * 100) : null,
			mappings,
		};
	}

	// F3: `assessed` must be false whenever there is no COMPLETED evidence — either no
	// checks ran at all (`checkResults.length === 0`, the slice-2/Task-3 case) OR every
	// attempted check failed to complete (a total DoH/network outage, all `checkStatus`
	// transient). `isMeasured` (checks.length > 0) alone can't tell these apart from a
	// genuinely measured scan — it was true for BOTH "19 healthy checks" and "19 checks
	// that all timed out", which is exactly the dishonesty this closes. The two failure
	// modes get DISTINCT caveat wording (different remediation: nothing to retry vs.
	// retry once the transient condition clears), even though both report `assessed: false`.
	const assessed = hasCompletedEvidence(checkResults);
	const caveat = assessed ? null : checkResults.length === 0 ? UNASSESSED_COMPLIANCE_CAVEAT : buildAllTransientCaveat(checkResults.length);
	return { domain, score, grade, assessed, caveat, frameworks };
}

/**
 * Map scan findings to compliance framework controls.
 * Runs a full scan (or uses cached results), then evaluates each control.
 */
export async function mapCompliance(domain: string, kv?: KVNamespace, runtimeOptions?: ScanRuntimeOptions): Promise<ComplianceReport> {
	const scanResult = await scanDomain(domain, kv, runtimeOptions);

	// Mirror the scan's own applicability pass so a category it nulled cannot be graded
	// here. Same predicate, same profile default as `formatScanReport` — not a second
	// opinion on applicability, and now literally the same function `compare_baseline`
	// calls.
	const notApplicableCategories = notApplicableCategoriesFor(scanResult);

	// `ScanScore.grade` is the engine's canonical NINE-band letter. Every DISPLAY surface
	// renders the six-band scale via `displayGradeFor`, so passing the raw grade through
	// made this tool disagree with `scan_domain` on the same score (82 → "B+" here, "B"
	// there). One band scale, one helper.
	return evaluateCompliance(scanResult.checks, domain, scanResult.score.overall, displayGradeFor(scanResult.score), notApplicableCategories);
}

/**
 * Per-status display vocabulary. `not_assessed` gets its OWN glyph and label —
 * reusing the failure glyph would put an unassessable control back in the same
 * visual column as a real failure, which is the defect in a different costume.
 */
const STATUS_ICON_COMPACT: Record<ComplianceStatus, string> = {
	pass: ' ✓',
	partial: ' ~',
	fail: ' ✗',
	not_assessed: ' ?',
};

const STATUS_ICON_FULL: Record<ComplianceStatus, string> = {
	pass: '✅',
	partial: '⚠️',
	fail: '❌',
	not_assessed: '❓',
};

const STATUS_LABEL: Record<ComplianceStatus, string> = {
	pass: 'PASS',
	partial: 'PARTIAL',
	fail: 'FAIL',
	not_assessed: 'NOT ASSESSED',
};

/**
 * Format a compliance report for display.
 */
export function formatCompliance(report: ComplianceReport, format: OutputFormat = 'full'): string {
	const lines: string[] = [];

	// Driven by whether anything was MEASURED, not by whether the scan scored: a
	// domain whose checks ran but whose scoring bundle failed has a null score
	// alongside genuinely evaluable control results, and telling that customer
	// "no checks ran" would itself be false.
	const unassessed = !report.assessed;
	// `caveat` is REQUIRED on `ComplianceReport`, so the real producer
	// (`evaluateCompliance`) always states which reason applies whenever
	// `!assessed`. Falling back to `UNASSESSED_COMPLIANCE_CAVEAT` specifically
	// is the same silent-wrong-prose shape closed elsewhere this fix round
	// (map_csc_products, generate_fix_plan): a fabricated/hand-built report
	// with a somehow-unset `caveat` would render the never-ran-specific text
	// even for an all-transient state. The only genuinely safe fallback here
	// makes no specific claim.
	const caveat = report.caveat ?? 'This domain could not be assessed.';

	if (format === 'compact') {
		lines.push(`Compliance: ${sanitizeOutputText(report.domain, 253)} — ${formatScoreGrade(report.score, report.grade)}`);
		if (unassessed) lines.push(caveat);
		lines.push('');

		for (const fw of FRAMEWORK_ORDER) {
			const summary = report.frameworks[fw];
			const label = FRAMEWORK_LABELS[fw];
			lines.push(
				summary.assessedControls === 0
					? `${label}: ${UNGRADED_DISPLAY} \u2014 0 of ${summary.totalControls} controls assessable`
					: `${label}: ${summary.passing}/${summary.assessedControls} controls passing (${summary.percentage}%)` +
							(summary.notAssessed > 0 ? ` | ${summary.notAssessed} not assessed` : ''),
			);

			for (const m of summary.mappings) {
				const icon = STATUS_ICON_COMPACT[m.status];
				const findingSuffix = m.relatedFindings.length > 0 ? ` — ${sanitizeOutputText(m.relatedFindings[0], 80)}` : '';
				lines.push(`${icon} ${m.controlId} ${sanitizeOutputText(m.controlName, 60)}${m.status !== 'pass' ? findingSuffix : ''}`);
			}
			lines.push('');
		}
	} else {
		lines.push(`# Compliance Report: ${sanitizeOutputText(report.domain, 253)}`);
		lines.push(`**Score:** ${formatScoreGrade(report.score, report.grade)}`);
		if (unassessed) lines.push(`> **${caveat}**`);
		lines.push('');

		for (const fw of FRAMEWORK_ORDER) {
			const summary = report.frameworks[fw];
			const label = FRAMEWORK_LABELS[fw];
			lines.push(`## ${label}`);
			lines.push(
				summary.assessedControls === 0
					? `**No control could be assessed** — 0 of ${summary.totalControls} had any check evidence (${UNGRADED_DISPLAY}).`
					: `**${summary.passing}/${summary.assessedControls}** controls passing (${summary.percentage}%) | ` +
							`${summary.failing} failing | ${summary.partial} partial` +
							(summary.notAssessed > 0 ? ` | ${summary.notAssessed} not assessed` : ''),
			);
			lines.push('');

			for (const m of summary.mappings) {
				const icon = STATUS_ICON_FULL[m.status];
				lines.push(`${icon} **${m.controlId} ${sanitizeOutputText(m.controlName, 60)}** — ${STATUS_LABEL[m.status]}`);

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
