// SPDX-License-Identifier: BUSL-1.1

/**
 * Attack Path Simulation tool.
 * Analyzes current DNS security posture and describes specific attack paths
 * an adversary could exploit. Combines signals from multiple check categories
 * into concrete attack narratives with severity, feasibility, and mitigations.
 */

import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { Finding } from '../lib/scoring-model';
import { checkSpf } from './check-spf';
import { checkDmarc } from './check-dmarc';
import { checkDkim } from './check-dkim';
import { checkDnssec } from './check-dnssec';
import { checkSsl } from './check-ssl';
import { checkMtaSts } from './check-mta-sts';
import { checkCaa } from './check-caa';
import { checkHttpSecurity } from './check-http-security';
import { checkDane } from './check-dane';
import { checkSubdomainTakeover } from './check-subdomain-takeover';

/** A single attack path that an adversary could exploit. */
export interface AttackPath {
	id: string;
	name: string;
	severity: 'critical' | 'high' | 'medium' | 'low';
	feasibility: 'trivial' | 'moderate' | 'difficult';
	prerequisites: string[];
	steps: string[];
	impact: string;
	mitigations: string[];
}

/** Full attack simulation result. */
export interface AttackSimulationResult {
	domain: string;
	totalPaths: number;
	criticalPaths: number;
	highPaths: number;
	attackPaths: AttackPath[];
	overallRisk: 'critical' | 'high' | 'medium' | 'low';
}

/** Severity sort order: critical first. */
const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

/** Feasibility sort order: trivial first. */
const FEASIBILITY_ORDER: Record<string, number> = { trivial: 0, moderate: 1, difficult: 2 };

/** Severity display icons for full format. */
const SEVERITY_ICON: Record<string, string> = {
	critical: '\uD83D\uDEA8',
	high: '\uD83D\uDD34',
	medium: '\u26A0',
	low: '\uD83D\uDFE1',
};

// ---------------------------------------------------------------------------
// Finding condition helpers
// ---------------------------------------------------------------------------

/** Check if any finding in a set matches a predicate. */
function hasFindings(findings: Finding[], predicate: (f: Finding) => boolean): boolean {
	return findings.some(predicate);
}

/** Check if SPF is missing or permissive. */
function isSpfWeakOrMissing(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'spf') return false;
		if (f.severity === 'info') return false;
		const t = f.title.toLowerCase();
		const d = f.detail.toLowerCase();
		return (
			t.includes('no spf') ||
			t.includes('missing') ||
			t.includes('permissive') ||
			d.includes('+all') ||
			d.includes('?all')
		);
	});
}

/** Check if DMARC is missing or has p=none. */
function isDmarcWeakOrMissing(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'dmarc') return false;
		if (f.severity === 'info') return false;
		const t = f.title.toLowerCase();
		const d = f.detail.toLowerCase();
		return t.includes('no dmarc') || t.includes('missing') || d.includes('p=none');
	});
}

/** Check if DMARC has no subdomain policy (sp=) or sp=none. */
function isDmarcSubdomainWeak(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'dmarc') return false;
		const d = f.detail.toLowerCase();
		const t = f.title.toLowerCase();
		// Missing DMARC entirely means no subdomain policy either
		if (t.includes('no dmarc') || t.includes('missing')) return true;
		// Explicit sp=none
		if (d.includes('sp=none')) return true;
		// No sp= tag and p=none
		if (!d.includes('sp=') && d.includes('p=none')) return true;
		return false;
	});
}

/** Check if subdomain takeover findings exist with severity >= medium. */
function hasSubdomainTakeoverRisk(findings: Finding[]): boolean {
	return hasFindings(
		findings,
		(f) => f.category === 'subdomain_takeover' && (f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium'),
	);
}

/** Check if DNSSEC is not enabled. */
function isDnssecMissing(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'dnssec') return false;
		if (f.severity === 'info') return false;
		const t = f.title.toLowerCase();
		return t.includes('not enabled') || t.includes('not configured') || t.includes('missing') || t.includes('no dnssec');
	});
}

/** Check if MTA-STS is missing. */
function isMtaStsMissing(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'mta_sts') return false;
		if (f.severity === 'info') return false;
		const t = f.title.toLowerCase();
		return t.includes('no mta-sts') || t.includes('missing') || t.includes('not configured');
	});
}

/** Check if DANE is missing. */
function isDaneMissing(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'dane') return false;
		if (f.severity === 'info') return false;
		const t = f.title.toLowerCase();
		return t.includes('no dane') || t.includes('no tlsa') || t.includes('missing') || t.includes('not configured');
	});
}

/** Check if CAA records are missing. */
function isCaaMissing(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'caa') return false;
		if (f.severity === 'info') return false;
		const t = f.title.toLowerCase();
		return t.includes('no caa') || t.includes('missing') || t.includes('not configured');
	});
}

/** Check if CSP is missing or has unsafe-inline. */
function isCspWeakOrMissing(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'http_security') return false;
		if (f.severity === 'info') return false;
		const t = f.title.toLowerCase();
		const d = f.detail.toLowerCase();
		return t.includes('no content-security-policy') || t.includes('missing csp') || d.includes('unsafe-inline');
	});
}

/** Check if X-Frame-Options is missing and CSP frame-ancestors is missing. */
function isClickjackingVulnerable(findings: Finding[]): boolean {
	const httpFindings = findings.filter((f) => f.category === 'http_security' && f.severity !== 'info');
	if (httpFindings.length === 0) return false;

	const hasFrameOptionsMissing = httpFindings.some((f) => {
		const t = f.title.toLowerCase();
		return t.includes('x-frame-options') || t.includes('frame-options');
	});

	// Also check if CSP is missing entirely (no frame-ancestors possible without CSP)
	const hasCspMissing = httpFindings.some((f) => {
		const t = f.title.toLowerCase();
		return t.includes('no content-security-policy') || t.includes('missing csp');
	});

	return hasFrameOptionsMissing || hasCspMissing;
}

/** Check if DKIM key is weak (< 2048 bits). */
function isDkimKeyWeak(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'dkim') return false;
		if (f.severity === 'info') return false;
		const t = f.title.toLowerCase();
		const d = f.detail.toLowerCase();
		return t.includes('weak') || t.includes('short') || d.includes('1024') || d.includes('512');
	});
}

// ---------------------------------------------------------------------------
// Attack path definitions
// ---------------------------------------------------------------------------

interface AttackPathDefinition {
	id: string;
	name: string;
	severity: 'critical' | 'high' | 'medium' | 'low';
	feasibility: 'trivial' | 'moderate' | 'difficult';
	condition: (findings: Finding[]) => boolean;
	prerequisites: string[];
	steps: string[];
	impact: string;
	mitigations: string[];
}

const ATTACK_PATH_DEFINITIONS: AttackPathDefinition[] = [
	{
		id: 'email_spoof_direct',
		name: 'Direct Email Spoofing',
		severity: 'critical',
		feasibility: 'trivial',
		condition: (findings) => isSpfWeakOrMissing(findings) || isDmarcWeakOrMissing(findings),
		prerequisites: ['SPF missing or permissive', 'DMARC missing or set to p=none'],
		steps: [
			'Send email as ceo@domain using any SMTP server',
			'No SPF check or DMARC enforcement blocks it',
			'Recipient mail server accepts and delivers the forged email',
		],
		impact: 'Phishing emails appear to come from your domain. BEC fraud, credential theft.',
		mitigations: ['Deploy SPF with -all', 'Set DMARC to p=reject'],
	},
	{
		id: 'email_spoof_subdomain',
		name: 'Subdomain Email Spoofing',
		severity: 'high',
		feasibility: 'moderate',
		condition: (findings) => isDmarcSubdomainWeak(findings),
		prerequisites: ['DMARC has no sp= policy or sp=none'],
		steps: [
			'Send email from any subdomain (e.g. hr@sub.example.com)',
			'No subdomain DMARC policy blocks it',
			'Recipients trust the parent domain brand',
		],
		impact: 'Subdomain spoofing bypasses main domain protections. Enables targeted phishing from trusted subdomains.',
		mitigations: ['Add sp=reject to DMARC record', 'Publish DMARC records on active subdomains'],
	},
	{
		id: 'subdomain_takeover',
		name: 'Subdomain Takeover via Dangling CNAME',
		severity: 'critical',
		feasibility: 'moderate',
		condition: (findings) => hasSubdomainTakeoverRisk(findings),
		prerequisites: ['Dangling CNAME pointing to unclaimed resource'],
		steps: [
			'Identify dangling CNAME record pointing to deprovisioned cloud resource',
			'Register the unclaimed resource on the cloud provider',
			'Serve malicious content on trusted subdomain',
		],
		impact: 'Attacker controls content on your subdomain. Cookie theft, phishing, malware distribution.',
		mitigations: ['Remove stale CNAME records', 'Monitor DNS records for orphaned entries'],
	},
	{
		id: 'dns_hijack',
		name: 'DNS Response Manipulation',
		severity: 'high',
		feasibility: 'difficult',
		condition: (findings) => isDnssecMissing(findings),
		prerequisites: ['DNSSEC not enabled on the domain'],
		steps: [
			'Perform DNS cache poisoning or BGP hijack',
			'Redirect traffic to attacker-controlled server',
			'Intercept email, web traffic, or serve fake content',
		],
		impact: 'All DNS-dependent security (SPF, DKIM, DMARC, MTA-STS) can be bypassed via forged DNS responses.',
		mitigations: ['Enable DNSSEC'],
	},
	{
		id: 'tls_downgrade_email',
		name: 'Email TLS Stripping',
		severity: 'medium',
		feasibility: 'moderate',
		condition: (findings) => isMtaStsMissing(findings) && isDaneMissing(findings),
		prerequisites: ['MTA-STS not configured', 'DANE (TLSA) not configured'],
		steps: [
			'Perform network-level MITM on SMTP connection',
			'Strip STARTTLS from SMTP negotiation',
			'Read email in plaintext',
		],
		impact: 'Emails delivered in cleartext, exposing sensitive content to network-level attackers.',
		mitigations: ['Deploy MTA-STS with mode enforce', 'Configure DANE TLSA records'],
	},
	{
		id: 'cert_misissuance',
		name: 'Unauthorized Certificate Issuance',
		severity: 'medium',
		feasibility: 'difficult',
		condition: (findings) => isCaaMissing(findings),
		prerequisites: ['No CAA records restrict certificate issuance'],
		steps: [
			'Request a certificate from any CA for your domain',
			'No CAA restriction prevents issuance',
			'Use certificate for MITM or phishing site',
		],
		impact: 'Unauthorized TLS certificates enable impersonation and traffic interception.',
		mitigations: ['Add CAA records restricting issuance to authorized CAs'],
	},
	{
		id: 'xss_injection',
		name: 'Cross-Site Scripting',
		severity: 'high',
		feasibility: 'moderate',
		condition: (findings) => isCspWeakOrMissing(findings),
		prerequisites: ['Content-Security-Policy header missing or allows unsafe-inline'],
		steps: [
			'Inject script via user input or reflected parameter',
			'No CSP blocks execution of injected script',
			'Steal session tokens, credentials, or perform actions as the user',
		],
		impact: 'Arbitrary JavaScript execution in user browsers. Session hijacking, data theft, defacement.',
		mitigations: ['Deploy Content-Security-Policy with strict source restrictions', 'Remove unsafe-inline from CSP'],
	},
	{
		id: 'clickjacking',
		name: 'UI Redressing (Clickjacking)',
		severity: 'medium',
		feasibility: 'moderate',
		condition: (findings) => isClickjackingVulnerable(findings),
		prerequisites: ['X-Frame-Options header missing', 'No CSP frame-ancestors directive'],
		steps: [
			'Embed target page in hidden iframe on attacker site',
			'Overlay transparent page over decoy UI',
			'Trick user into clicking hidden buttons or links',
		],
		impact: 'Users unknowingly perform actions on your site (transfers, settings changes, account modifications).',
		mitigations: ['Set X-Frame-Options to DENY or SAMEORIGIN', 'Add frame-ancestors directive to CSP'],
	},
	{
		id: 'dkim_key_compromise',
		name: 'DKIM Key Weakness',
		severity: 'medium',
		feasibility: 'difficult',
		condition: (findings) => isDkimKeyWeak(findings),
		prerequisites: ['DKIM key shorter than 2048 bits'],
		steps: [
			'Factor weak RSA key using available compute resources',
			'Sign forged emails that pass DKIM verification',
			'Bypass email authentication checks',
		],
		impact: 'Forged emails pass DKIM verification, undermining email authentication chain.',
		mitigations: ['Rotate to 2048-bit or longer DKIM key'],
	},
];

// ---------------------------------------------------------------------------
// Core simulation function
// ---------------------------------------------------------------------------

/**
 * Simulate attack paths against a domain's current DNS security posture.
 * Runs multiple security checks in parallel and evaluates which attack paths
 * are feasible based on the combined findings.
 */
export async function simulateAttackPaths(
	domain: string,
	dnsOptions?: QueryDnsOptions,
): Promise<AttackSimulationResult> {
	// Run all checks in parallel
	const results = await Promise.allSettled([
		checkSpf(domain, dnsOptions),
		checkDmarc(domain, dnsOptions),
		checkDkim(domain, undefined, dnsOptions),
		checkDnssec(domain, dnsOptions),
		checkSsl(domain),
		checkMtaSts(domain, dnsOptions),
		checkCaa(domain, dnsOptions),
		checkHttpSecurity(domain),
		checkDane(domain, dnsOptions),
		checkSubdomainTakeover(domain, dnsOptions),
	]);

	// Collect all findings from fulfilled checks
	const allFindings: Finding[] = [];
	for (const result of results) {
		if (result.status === 'fulfilled') {
			allFindings.push(...result.value.findings);
		}
	}

	// Evaluate each attack path definition against collected findings
	const feasiblePaths: AttackPath[] = [];
	for (const def of ATTACK_PATH_DEFINITIONS) {
		if (def.condition(allFindings)) {
			feasiblePaths.push({
				id: def.id,
				name: def.name,
				severity: def.severity,
				feasibility: def.feasibility,
				prerequisites: def.prerequisites,
				steps: def.steps,
				impact: def.impact,
				mitigations: def.mitigations,
			});
		}
	}

	// Sort by severity (critical first), then feasibility (trivial first)
	feasiblePaths.sort((a, b) => {
		const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
		if (sevDiff !== 0) return sevDiff;
		return FEASIBILITY_ORDER[a.feasibility] - FEASIBILITY_ORDER[b.feasibility];
	});

	const criticalPaths = feasiblePaths.filter((p) => p.severity === 'critical').length;
	const highPaths = feasiblePaths.filter((p) => p.severity === 'high').length;

	// Overall risk = most severe feasible path, or low if none
	let overallRisk: 'critical' | 'high' | 'medium' | 'low' = 'low';
	if (feasiblePaths.length > 0) {
		overallRisk = feasiblePaths[0].severity;
	}

	return {
		domain,
		totalPaths: feasiblePaths.length,
		criticalPaths,
		highPaths,
		attackPaths: feasiblePaths,
		overallRisk,
	};
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

/** Format severity label for display. */
function severityLabel(severity: string): string {
	return severity.toUpperCase();
}

/**
 * Format attack simulation results for display.
 * Compact mode shows summary + one-line per path.
 * Full mode includes steps, prerequisites, and detailed impact.
 */
export function formatAttackPaths(result: AttackSimulationResult, format: OutputFormat): string {
	if (result.totalPaths === 0) {
		const header = `Attack Paths: ${sanitizeOutputText(result.domain, 100)} - No feasible attack paths detected`;
		return format === 'compact'
			? `${header}\nOverall Risk: LOW\n\nNo exploitable attack paths identified based on current DNS security posture.`
			: `${header}\nOverall Risk: LOW\n\nNo exploitable attack paths were identified.\nAll evaluated attack vectors are blocked by the current security configuration.`;
	}

	const severityCounts: string[] = [];
	if (result.criticalPaths > 0) severityCounts.push(`${result.criticalPaths} critical`);
	if (result.highPaths > 0) severityCounts.push(`${result.highPaths} high`);
	const mediumPaths = result.attackPaths.filter((p) => p.severity === 'medium').length;
	if (mediumPaths > 0) severityCounts.push(`${mediumPaths} medium`);
	const lowPaths = result.attackPaths.filter((p) => p.severity === 'low').length;
	if (lowPaths > 0) severityCounts.push(`${lowPaths} low`);

	const header = `Attack Paths: ${sanitizeOutputText(result.domain, 100)} - ${result.totalPaths} feasible attack${result.totalPaths === 1 ? '' : 's'} (${severityCounts.join(', ')})`;
	const lines: string[] = [header, `Overall Risk: ${severityLabel(result.overallRisk)}`, ''];

	for (const path of result.attackPaths) {
		if (format === 'compact') {
			const icon = SEVERITY_ICON[path.severity] ?? '';
			lines.push(`${icon} [${severityLabel(path.severity)}] ${sanitizeOutputText(path.name, 60)} - ${path.feasibility}`);
			// One-line summary: first prerequisite + first mitigation
			const summaryDetail = path.prerequisites[0] ?? path.impact;
			lines.push(`   ${sanitizeOutputText(summaryDetail, 120)}`);
			if (path.mitigations.length > 0) {
				lines.push(`   Mitigate: ${sanitizeOutputText(path.mitigations[0], 120)}`);
			}
			lines.push('');
		} else {
			// Full format: all details
			const icon = SEVERITY_ICON[path.severity] ?? '';
			lines.push(`${icon} [${severityLabel(path.severity)}] ${path.name} (${path.feasibility} feasibility)`);
			lines.push('');

			if (path.prerequisites.length > 0) {
				lines.push('   Prerequisites:');
				for (const prereq of path.prerequisites) {
					lines.push(`   - ${sanitizeOutputText(prereq, 200)}`);
				}
				lines.push('');
			}

			lines.push('   Attack Steps:');
			for (let i = 0; i < path.steps.length; i++) {
				lines.push(`   ${i + 1}. ${sanitizeOutputText(path.steps[i], 200)}`);
			}
			lines.push('');

			lines.push(`   Impact: ${sanitizeOutputText(path.impact, 200)}`);
			lines.push('');

			if (path.mitigations.length > 0) {
				lines.push('   Mitigations:');
				for (const mit of path.mitigations) {
					lines.push(`   - ${sanitizeOutputText(mit, 200)}`);
				}
			}
			lines.push('');
		}
	}

	return lines.join('\n').trimEnd();
}
