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
import type { Finding } from '@blackveil/dns-checks/scoring';
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

/** Check if DMARC is missing or set to a non-enforcing policy (p=none). */
function isDmarcWeakOrMissing(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'dmarc') return false;
		if (f.severity === 'info') return false;
		const t = f.title.toLowerCase();
		const d = f.detail.toLowerCase();
		// Missing record, missing p= tag, or multiple-records-no-valid-policy.
		if (t.includes('no dmarc') || t.includes('missing') || t.includes('no valid policy')) return true;
		// Non-enforcing organizational policy (p=none). Match the policy-none title, and
		// only a boundary-anchored "p=none" in the detail. Issue #564: the SUBDOMAIN
		// (sp=none) and non-existent-subdomain (np=none) findings both carry the substring
		// "p=none", which previously false-tripped this direct-spoof gate on well-protected
		// domains (SPF -all + DMARC p=quarantine). Those are subdomain risks, handled by the
		// separate email_spoof_subdomain path — they must NOT imply direct org-domain spoofing.
		if (t.includes('policy set to none')) return true;
		if (/(?:^|[^a-z])p=none/.test(d)) return true;
		return false;
	});
}

/**
 * Check if DMARC leaves subdomains unprotected.
 *
 * ⚠️ #788 — the mirror image of #782. That bug matched prose meaning the
 * opposite; this one FAILED to match for the same reason. The old third clause
 * was `!d.includes('sp=') && d.includes('p=none')`, and check_dmarc's detail for
 * a MISSING subdomain policy reads:
 *
 *   "No subdomain policy (sp=) specified. Subdomains inherit the "none" policy,
 *    which provides no protection against spoofing."
 *
 * `sp=` appears as a substring precisely BECAUSE the tag is absent, so
 * `!d.includes('sp=')` was always false and the clause could never fire. The
 * literal `p=none` is not in the detail either — the policy is named as
 * `"none"`. Measured 2026-08-26: `email_spoof_subdomain` fired for 0 of 16
 * domains, including moonshot.ai, whose own finding says subdomains have "no
 * protection against spoofing".
 *
 * THE DISCRIMINATOR IS THE INHERITED POLICY, not whether an `sp=` tag exists.
 * Inheriting `reject` is fine; inheriting `none` is not. Both cases emit the
 * same "No subdomain policy (sp=)" prose, so keying on the tag cannot separate
 * them — only the named policy can.
 *
 * Deliberately conservative: a domain with `p=none` but NO subdomain finding at
 * all (huggingface.co on the same sweep) does not fire here. That evidence state
 * is indistinguishable from `p=none` + an explicit strong `sp=`, and inventing a
 * finding from an absence is the failure mode this family of fixes exists to
 * stop. If that gap matters it belongs in check_dmarc, which owns the evidence.
 */
const SUBDOMAIN_POLICY_IS_NONE: RegExp[] = [
	// Explicit tags. Word-anchored so `aspf=`/`adkim=` cannot match.
	/\bsp=none\b/,
	/\bnp=none\b/,
	// `p=quarantine|reject` + `sp=none` (existing subdomains).
	/subdomain polic\w*\s+is set to "none"/,
	// `p=none` + no `sp=` — subdomains inherit the org policy, which is none.
	/subdomains inherit p=none/,
	/subdomains inherit the "none"/,
];

function isDmarcSubdomainWeak(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'dmarc') return false;
		const haystack = `${f.title} ${f.detail}`.toLowerCase();
		// Missing DMARC entirely means no subdomain policy either.
		if (f.title.toLowerCase().includes('no dmarc') || f.title.toLowerCase().includes('missing')) {
			return true;
		}
		// Otherwise the path fires only where the policy that APPLIES TO SUBDOMAINS
		// is literally `none`. `sp=quarantine` under `p=reject` is weaker than the
		// parent but still enforcing, so it is deliberately NOT a match here.
		return SUBDOMAIN_POLICY_IS_NONE.some((re) => re.test(haystack));
	});
}

/**
 * The `subdomain_takeover` findings that actually support a takeover path.
 *
 * ⚠️ #787 — everything below exists because this set is NOT homogeneous.
 * `check_subdomain_takeover` emits two quite different things under one
 * category, and the path used to treat them identically:
 *
 *   [high]   Subdomain possible takeover signal <provider>   ← claimable service
 *   [medium] Dangling CNAME operational drift : a → b        ← just doesn't resolve
 *
 * Measured on openai.com (2026-08-26): `blog.openai.com` CNAMEs to
 * `d2b532lzynlqb7.cloudfront.net`, which returns NOERROR/NODATA on two
 * independent public resolvers (Cloudflare and Google) — a deleted
 * distribution, genuinely dangling. But a CloudFront distribution ID is
 * assigned by AWS and cannot be chosen by an attacker, so that name is NOT
 * re-registrable. The scanner encodes exactly that distinction in the severity
 * it assigns; the simulator threw it away.
 */
function subdomainTakeoverEvidence(findings: Finding[]): Finding[] {
	return findings.filter(
		(f) =>
			f.category === 'subdomain_takeover' &&
			(f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium'),
	);
}

/** Check if subdomain takeover findings exist with severity >= medium. */
function hasSubdomainTakeoverRisk(findings: Finding[]): boolean {
	return subdomainTakeoverEvidence(findings).length > 0;
}

/**
 * Severity of the takeover path = severity of its STRONGEST supporting finding.
 *
 * ⚠️ #787 — this was hardcoded `critical`. Because `overallRisk` is simply the
 * most severe feasible path, a single MEDIUM operational-drift finding rendered
 * the entire domain **critical**. On the 16-domain AI-provider sweep that
 * produced the only `critical` verdict in the whole run, on a dangling CNAME
 * nobody can claim. A severity a reader can check and disagree with discredits
 * the paths that are correct.
 */
function subdomainTakeoverSeverity(findings: Finding[]): 'critical' | 'high' | 'medium' {
	const evidence = subdomainTakeoverEvidence(findings);
	if (evidence.some((f) => f.severity === 'critical')) return 'critical';
	if (evidence.some((f) => f.severity === 'high')) return 'high';
	return 'medium';
}

/**
 * Prerequisites naming what was OBSERVED, never what would be convenient.
 *
 * ⚠️ #787 — the static list said "Dangling CNAME pointing to unclaimed
 * resource". "Unclaimed" is an assertion of attacker-registrability, and a
 * drift finding establishes only that the target stopped resolving. Those are
 * different claims with different remediation urgency, and only one of them is
 * supported by a NODATA answer.
 */
function subdomainTakeoverPrerequisites(findings: Finding[]): string[] {
	const evidence = subdomainTakeoverEvidence(findings);
	const out: string[] = [];
	if (evidence.some((f) => f.title.toLowerCase().includes('takeover'))) {
		out.push('Subdomain CNAME resolves to a service with a known takeover signature');
	}
	if (evidence.some((f) => /dangling|drift/.test(f.title.toLowerCase()))) {
		out.push('Dangling CNAME to a resource that no longer resolves (attacker registrability not established)');
	}
	// Never emit a path that can name nothing it rests on — an unreviewable
	// finding is the failure mode this whole family of fixes exists to stop.
	if (out.length === 0 && evidence.length > 0) {
		out.push('Subdomain takeover signal reported by check_subdomain_takeover');
	}
	return out;
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

/**
 * Findings that exist ONLY on a zone which already publishes CAA.
 *
 * `issuewild` and `iodef` are OPTIONAL sub-tags of an EXISTING CAA RRset — a
 * zone with three `issue` tags and no `iodef` is a zone WITH CAA, and the
 * finding says exactly that. Their titles ("No CAA iodef tag") nonetheless
 * contain the substring "no caa", which is what the old predicate matched.
 */
const CAA_SUBTAG_FINDING = /\b(issuewild|iodef|issuemail)\b/;

/**
 * Does the zone publish NO CAA records at all?
 *
 * ⚠️ #782 — this used to substring-match `"no caa"` against any non-info `caa`
 * finding, so *"No CAA issuewild tag"* and *"No CAA iodef tag"* both matched.
 * Measured on openclaw.org: the zone publishes THREE `issue` tags
 * (sectigo.com, letsencrypt.org, pki.goog), `check_caa` scored it 90 and
 * reported only the two optional sub-tags as absent — while the simulator, in
 * the SAME run, emitted a `cert_misissuance` path whose stated prerequisite was
 * "No CAA records restrict certificate issuance".
 *
 * That is a report contradicting itself: a CAA section listing three issuers,
 * and an attack-path section asserting there are none. A path whose
 * prerequisite is checkably false is worse than no path — a competent reader
 * checks it, and then distrusts everything else in the document.
 *
 * A title naming a sub-tag is therefore EXCLUDING evidence: it proves the RRset
 * exists rather than that it is absent.
 */
function isCaaMissing(findings: Finding[]): boolean {
	const caaFindings = findings.filter((f) => f.category === 'caa' && f.severity !== 'info');
	if (caaFindings.some((f) => CAA_SUBTAG_FINDING.test(f.title.toLowerCase()))) return false;
	return caaFindings.some((f) => {
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
/**
 * Which framing control is actually absent.
 *
 * ⚠️ #782 — the condition is an OR (`XFO missing` OR `CSP missing`) but the
 * path's `prerequisites` asserted BOTH unconditionally. Measured on
 * openclaw.org: `www` sends `X-Frame-Options: SAMEORIGIN` and publishes no CSP,
 * so only the CSP arm matched — and the emitted path still stated
 * "X-Frame-Options header missing", which `check_http_security` in the same run
 * correctly did not report, because the header is present.
 *
 * Returning WHICH arm fired lets the path state only what it observed. A path
 * that names a control the reader can see is present is a checkable falsehood,
 * and it discredits the paths that are correct.
 */
function clickjackingGaps(findings: Finding[]): { frameOptions: boolean; csp: boolean } {
	const httpFindings = findings.filter((f) => f.category === 'http_security' && f.severity !== 'info');
	if (httpFindings.length === 0) return { frameOptions: false, csp: false };

	const frameOptions = httpFindings.some((f) => {
		const t = f.title.toLowerCase();
		return t.includes('x-frame-options') || t.includes('frame-options');
	});

	// CSP missing entirely — no frame-ancestors is possible without a CSP.
	const csp = httpFindings.some((f) => {
		const t = f.title.toLowerCase();
		return t.includes('no content-security-policy') || t.includes('missing csp');
	});

	return { frameOptions, csp };
}

function isClickjackingVulnerable(findings: Finding[]): boolean {
	const gaps = clickjackingGaps(findings);
	return gaps.frameOptions || gaps.csp;
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

/** Check if authoritative DNS infrastructure has route-leak or hijack evidence. */
function hasAuthoritativeRouteHijackRisk(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'authoritative_dns_infra') return false;
		if (f.severity !== 'critical' && f.severity !== 'high') return false;
		const t = f.title.toLowerCase();
		const d = f.detail.toLowerCase();
		return t.includes('route leak') || t.includes('hijack') || d.includes('route monitoring');
	});
}

/** Check if authoritative servers expose recursion or omit authoritative response behavior. */
function hasAuthoritativeServiceExposure(findings: Finding[]): boolean {
	return hasFindings(findings, (f) => {
		if (f.category !== 'authoritative_dns_infra') return false;
		if (f.severity !== 'critical' && f.severity !== 'high') return false;
		const t = f.title.toLowerCase();
		return t.includes('recursive service exposed') || t.includes('aa flag') || t.includes('zone transfer');
	});
}

// ---------------------------------------------------------------------------
// Attack path definitions
// ---------------------------------------------------------------------------

interface AttackPathDefinition {
	id: string;
	name: string;
	severity: 'critical' | 'high' | 'medium' | 'low';
	/**
	 * Derives the emitted severity from the evidence, overriding `severity`.
	 *
	 * Present only where one `condition` accepts findings of DIFFERENT severities
	 * (#787). A static `severity` then reports the worst case for every match,
	 * and since `overallRisk` is the most severe feasible path, that promotes the
	 * whole domain on the strength of the weakest qualifying finding.
	 */
	severityFrom?: (findings: Finding[]) => 'critical' | 'high' | 'medium' | 'low';
	feasibility: 'trivial' | 'moderate' | 'difficult';
	condition: (findings: Finding[]) => boolean;
	/**
	 * The conditions the path depends on.
	 *
	 * A FUNCTION when the path's condition is a disjunction, so the emitted list
	 * names only the arm that actually fired (#782). A static array asserts every
	 * listed prerequisite holds — which is false for an OR, and produced a path
	 * claiming "X-Frame-Options header missing" about a host that sends it.
	 */
	prerequisites: string[] | ((findings: Finding[]) => string[]);
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
		// Issue #564: direct exact-domain spoofing is trivial ONLY when SPF is missing/permissive
		// AND DMARC is missing/p=none — both stated prerequisites must actually hold. A well-protected
		// domain (SPF -all + DMARC p=quarantine/reject) is NOT trivially spoofable; its residual gap is
		// subdomain spoofing, covered by the separate email_spoof_subdomain path. This was an OR that
		// fired critical/trivial on either signal alone, contradicting assess_spoofability.
		condition: (findings) => isSpfWeakOrMissing(findings) && isDmarcWeakOrMissing(findings),
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
		// Ceiling only — the emitted value is derived (#787).
		severity: 'critical',
		severityFrom: (findings) => subdomainTakeoverSeverity(findings),
		feasibility: 'moderate',
		condition: (findings) => hasSubdomainTakeoverRisk(findings),
		// Derived, not asserted — see `subdomainTakeoverPrerequisites` (#787).
		prerequisites: (findings) => subdomainTakeoverPrerequisites(findings),
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
		// Derived, not asserted — see `clickjackingGaps` (#782).
		prerequisites: (findings) => {
			const gaps = clickjackingGaps(findings);
			const out: string[] = [];
			if (gaps.frameOptions) out.push('X-Frame-Options header missing');
			if (gaps.csp) out.push('No CSP frame-ancestors directive');
			return out;
		},
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
	{
		id: 'authoritative_dns_route_hijack',
		name: 'Authoritative DNS Route Hijack',
		severity: 'critical',
		feasibility: 'moderate',
		condition: (findings) => hasAuthoritativeRouteHijackRisk(findings),
		prerequisites: ['Authoritative DNS prefix has route-leak or hijack signals'],
		steps: [
			'Announce or exploit a competing route for authoritative DNS infrastructure',
			'Attract resolver traffic for the affected authoritative nameserver',
			'Return stale, blocked, or attacker-controlled DNS responses',
		],
		impact: 'Resolvers can receive incorrect authoritative answers, disrupting or redirecting dependent services.',
		mitigations: [
			'Validate BGP origin announcements and RPKI ROAs',
			'Coordinate with upstreams and route-monitoring providers',
			'Confirm anycast path health from independent vantage points',
		],
	},
	{
		id: 'authoritative_dns_service_abuse',
		name: 'Authoritative DNS Service Abuse',
		severity: 'high',
		feasibility: 'moderate',
		condition: (findings) => hasAuthoritativeServiceExposure(findings),
		prerequisites: ['Authoritative server exposes recursion, misses AA behavior, or permits transfer probes'],
		steps: [
			'Query the authoritative endpoint for recursive resolution or zone-transfer behavior',
			'Use exposed behavior for amplification, data exposure, or cache-manipulation attempts',
			'Pivot from DNS infrastructure weakness into broader availability impact',
		],
		impact: 'Authoritative DNS infrastructure can be abused or degraded instead of serving only delegated zones.',
		mitigations: [
			'Disable recursion on authoritative servers',
			'Restrict AXFR/IXFR to approved secondaries',
			'Verify authoritative AA behavior from multiple vantage points',
		],
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

	const feasiblePaths = evaluateAttackPathsFromFindings(allFindings);

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

export function evaluateAttackPathsFromFindings(findings: Finding[]): AttackPath[] {
	const feasiblePaths: AttackPath[] = [];
	for (const def of ATTACK_PATH_DEFINITIONS) {
		if (def.condition(findings)) {
			feasiblePaths.push({
				id: def.id,
				name: def.name,
				severity: def.severityFrom ? def.severityFrom(findings) : def.severity,
				feasibility: def.feasibility,
				prerequisites:
					typeof def.prerequisites === 'function' ? def.prerequisites(findings) : def.prerequisites,
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
	return feasiblePaths;
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
