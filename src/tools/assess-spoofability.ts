// SPDX-License-Identifier: BUSL-1.1

/**
 * Composite email spoofability score (0–100).
 *
 * Combines SPF trust surface, DMARC enforcement, and DKIM coverage
 * with interaction multipliers to produce a single spoofability metric.
 *
 * Higher score = more spoofable (worse).
 * 0 = fully protected, 100 = completely exposed.
 */

import type { CheckResult, Finding } from '../lib/scoring-model';
import type { QueryDnsOptions } from '../lib/dns-types';
import { checkSpf } from './check-spf';
import { checkDmarc } from './check-dmarc';
import { checkDkim } from './check-dkim';

/** Spoofability assessment result. */
export interface SpoofabilityResult {
	domain: string;
	spoofabilityScore: number;
	riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'minimal';
	spfProtection: number;
	dmarcProtection: number;
	dkimProtection: number;
	interactionEffects: string[];
	summary: string;
}

/** Compute SPF protection score (0–100, higher = more protected). */
function computeSpfProtection(result: CheckResult): number {
	if (!result.passed && result.score === 0) return 0;

	const findings = result.findings;
	const hasRecord = !findings.some((f: Finding) =>
		f.title.toLowerCase().includes('no spf') || f.title.toLowerCase().includes('missing'),
	);

	if (!hasRecord) return 0;

	const hasHardFail = findings.some((f: Finding) =>
		f.detail.includes('-all'),
	) || result.score >= 80;

	const hasSoftFail = findings.some((f: Finding) =>
		f.detail.includes('~all'),
	);

	const hasTrustSurface = findings.some((f: Finding) =>
		f.title.toLowerCase().includes('trust surface') ||
		f.title.toLowerCase().includes('shared platform') ||
		f.title.toLowerCase().includes('multi-tenant'),
	);

	if (hasHardFail && !hasTrustSurface) return 100;
	if (hasHardFail && hasTrustSurface) return 75;
	if (hasSoftFail) return 50;
	return 25;
}

/** Compute DMARC protection score (0–100, higher = more protected). */
function computeDmarcProtection(result: CheckResult): number {
	if (!result.passed && result.score === 0) return 0;

	const findings = result.findings;
	const hasRecord = !findings.some((f: Finding) =>
		f.title.toLowerCase().includes('no dmarc') || f.title.toLowerCase().includes('missing'),
	);

	if (!hasRecord) return 0;

	const detail = findings.map((f: Finding) => f.detail.toLowerCase()).join(' ');
	const title = findings.map((f: Finding) => f.title.toLowerCase()).join(' ');

	const hasReject = detail.includes('p=reject') || title.includes('p=reject');
	const hasQuarantine = detail.includes('p=quarantine') || title.includes('p=quarantine');
	const hasNone = detail.includes('p=none') || title.includes('p=none');
	const hasRua = detail.includes('rua=') || detail.includes('aggregate');
	const hasStrictAlign = detail.includes('aspf=s') && detail.includes('adkim=s');

	if (hasReject && hasStrictAlign) return 100;
	if (hasReject) return 85;
	if (hasQuarantine) return 60;
	if (hasNone && hasRua) return 30;
	if (hasNone) return 15;
	return result.score;
}

/** Compute DKIM protection score (0–100, higher = more protected). */
function computeDkimProtection(result: CheckResult): number {
	if (!result.passed && result.score === 0) return 0;

	const findings = result.findings;
	const hasKey = !findings.some((f: Finding) =>
		f.title.toLowerCase().includes('no dkim') || f.title.toLowerCase().includes('not found'),
	);

	if (!hasKey) return 0;

	const hasWeakKey = findings.some((f: Finding) =>
		f.title.toLowerCase().includes('weak') || f.title.toLowerCase().includes('1024'),
	);

	if (hasWeakKey) return 40;
	return result.score >= 80 ? 100 : 80;
}

/** Map spoofability score to risk level. */
function scoreToRiskLevel(score: number): 'critical' | 'high' | 'medium' | 'low' | 'minimal' {
	if (score >= 80) return 'critical';
	if (score >= 60) return 'high';
	if (score >= 40) return 'medium';
	if (score >= 20) return 'low';
	return 'minimal';
}

/** Generate a human-readable summary. */
function generateSummary(score: number): string {
	if (score <= 10) return 'Domain has strong email authentication. Spoofing risk is minimal.';
	if (score <= 30) return 'Domain has good email authentication with minor gaps.';
	if (score <= 50) return 'Domain has moderate email authentication gaps that could be exploited.';
	if (score <= 70) return 'Domain has significant email authentication weaknesses. Spoofing is feasible.';
	if (score <= 90) return 'Domain is highly vulnerable to email spoofing. Critical protections are missing.';
	return 'Domain has no effective email spoofing protection. Any server can send as this domain.';
}

/**
 * Assess email spoofability for a domain.
 *
 * @param domain - Validated, sanitized domain
 * @param dnsOptions - Optional DNS query options
 * @returns Composite spoofability assessment
 */
export async function assessSpoofability(
	domain: string,
	dnsOptions?: QueryDnsOptions,
): Promise<SpoofabilityResult> {
	// Run the three email auth checks in parallel
	const [spfResult, dmarcResult, dkimResult] = await Promise.all([
		checkSpf(domain, dnsOptions),
		checkDmarc(domain, dnsOptions),
		checkDkim(domain, undefined, dnsOptions),
	]);

	const spfProtection = computeSpfProtection(spfResult);
	const dmarcProtection = computeDmarcProtection(dmarcResult);
	const dkimProtection = computeDkimProtection(dkimResult);

	// Composite score: weighted combination
	let spoofability = 100 - (spfProtection * 0.30 + dmarcProtection * 0.45 + dkimProtection * 0.25);

	// Apply interaction multipliers
	const interactionEffects: string[] = [];

	// Weak DMARC + SPF trust surface = amplified risk
	if (dmarcProtection <= 30 && spfProtection <= 75 && spfProtection > 0) {
		spoofability = Math.min(100, spoofability * 1.3);
		interactionEffects.push('Weak DMARC enforcement combined with SPF trust surface exposure amplifies spoofing risk.');
	}

	// No DMARC + No SPF = complete exposure
	if (dmarcProtection === 0 && spfProtection === 0) {
		spoofability = Math.min(100, spoofability * 1.2);
		interactionEffects.push('Complete absence of both SPF and DMARC means any server can send as this domain.');
	}

	// Strong DMARC + Strong SPF = defense-in-depth bonus
	if (dmarcProtection >= 85 && spfProtection >= 75) {
		spoofability = Math.max(0, spoofability * 0.7);
		interactionEffects.push('Strong DMARC enforcement with SPF provides defense-in-depth against spoofing.');
	}

	// No DKIM weakens DMARC alignment
	if (dkimProtection === 0 && dmarcProtection > 0) {
		spoofability = Math.min(100, spoofability + 5);
		interactionEffects.push('Missing DKIM weakens DMARC alignment — messages rely solely on SPF alignment.');
	}

	// Clamp to 0–100
	spoofability = Math.round(Math.max(0, Math.min(100, spoofability)));

	return {
		domain,
		spoofabilityScore: spoofability,
		riskLevel: scoreToRiskLevel(spoofability),
		spfProtection,
		dmarcProtection,
		dkimProtection,
		interactionEffects,
		summary: generateSummary(spoofability),
	};
}

/** Format spoofability result as human-readable text. */
export function formatSpoofability(result: SpoofabilityResult): string {
	const lines: string[] = [];

	lines.push(`# Email Spoofability Assessment: ${result.domain}`);
	lines.push(`Spoofability Score: ${result.spoofabilityScore}/100 (${result.riskLevel.toUpperCase()} risk)`);
	lines.push('');
	lines.push(result.summary);
	lines.push('');

	lines.push('## Protection Breakdown');
	lines.push(`  SPF Protection:   ${result.spfProtection}/100`);
	lines.push(`  DMARC Protection: ${result.dmarcProtection}/100`);
	lines.push(`  DKIM Protection:  ${result.dkimProtection}/100`);

	if (result.interactionEffects.length > 0) {
		lines.push('');
		lines.push('## Interaction Effects');
		for (const effect of result.interactionEffects) {
			lines.push(`  - ${effect}`);
		}
	}

	return lines.join('\n');
}
