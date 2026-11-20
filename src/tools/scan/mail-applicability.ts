// SPDX-License-Identifier: BUSL-1.1

/** scan_domain post-processing: mail-auth applicability downgrades, wording fixes and the DMARC impersonation escalation. */

import { type CheckCategory, type CheckResult, type Finding } from '../../lib/scoring';
import { queryTxtRecords } from '../../lib/dns';
import { parseDmarcTags } from '../check-dmarc';
import { applySilentDomainDkimApplicability, mxDeclaresNoInboundMail } from '@blackveil/dns-checks/scoring';
import { rebuildUnlessAbstained, notApplicableMetadata } from './result-rebuild';

// The "does this domain accept inbound mail" predicate is owned by the shared
// package, so the severity branch, the wording branch and every package consumer
// read one answer. Re-exported here because the scan modules import it from here.
export { mxDeclaresNoInboundMail };

/**
 * Mail-applicability pass: downgrade or reword mail-auth findings that cannot apply to
 * this domain (non-apex host, null MX, SPF no-send policy), and escalate weak DMARC on
 * a sending domain with active impersonation.
 */
export async function applyMailApplicability(domain: string, checkResults: CheckResult[], nonApexHost?: boolean): Promise<CheckResult[]> {
	let results = checkResults;
	const mxResult = results.find((result) => result.category === 'mx');

	// ONE non-mail predicate, keyed on a STRUCTURAL signal (#643).
	//
	// This used to be two predicates: a `hasNoMx` that tested for a finding titled
	// 'No MX records found' — a string NO production code path emits — and this
	// `mxDeclaresNoInboundMail`, added later for the wording branch only. `hasNoMx`
	// was therefore permanently `false` against real DNS, so `adjustForNonMailDomain`
	// (the documented "parent DMARC covers it → downgrade email-auth findings to
	// info" rule) had never once run in production, and non-mail domains carried
	// un-downgraded critical/high findings for controls that cannot apply to them.
	// The two are now unified: there is exactly one answer to "does this domain
	// accept inbound mail", and both the severity branch and the wording branch
	// read it.
	const declaresNoInboundMail = mxDeclaresNoInboundMail(mxResult);

	if (declaresNoInboundMail) {
		// A non-delegated host such as www.example.com can legitimately have no MX
		// or mail-auth records of its own. Preserve its web/TLS checks, but do not
		// report absent host-label mail records as security failures.
		if (nonApexHost) {
			results = adjustForNonApexNonMailHost(results);
		}

		// The downgrade is GATED on real inherited protection, not on MX absence alone.
		//
		// Absent MX means the domain cannot RECEIVE mail. It says nothing about whether
		// the domain can be SPOOFED AS A SENDER — SPF/DKIM/DMARC protect outbound
		// identity, and a null-MX domain is still a forgeable From:. Downgrading missing
		// email-auth to `info` on MX absence alone would hand an A+ to a domain that
		// `check_mx` simultaneously reports as spoofable.
		//
		// So we downgrade only where the parent's DMARC `sp=`/`p=` is actually
		// `quarantine`/`reject` — i.e. inherited enforcement genuinely covers this name.
		// That is what CLAUDE.md has always documented ("parent DMARC sp=/p= →
		// downgrade"); the ungated form was an implementation drift that never ran.
		// Apex domains have no parent to inherit from, so they correctly never qualify.
		if (await checkApexDmarcPolicy(domain)) {
			results = adjustForNonMailDomain(results);
		}
		results = adjustBimiForNonMailDomain(results);
	} else if (mxResult) {
		results = clarifyMtaStsForMailDomain(domain, results);
	}

	// Detect no-send SPF policy (v=spf1 -all with no authorizing mechanisms)
	const spfResult = results.find((result) => result.category === 'spf');
	const hasNoSendPolicy = spfResult?.findings.some((f: Finding) => f.metadata?.noSendPolicy === true) ?? false;
	if (hasNoSendPolicy && !declaresNoInboundMail) {
		results = adjustForNoSendDomain(results);
	}
	// Revoked DKIM keys on a domain that neither sends nor receives mail (SQ-535).
	// The rule lives in the shared package, so a consumer that scores the package's
	// check results without this server layer reports the same severity. It reads
	// both conditions (no inbound mail, no-send SPF) from the results itself.
	// test/scan-post-processing-silent-domain-dkim.spec.ts drives the real check, so
	// a renamed DKIM title fails that spec instead of silently re-arming the HIGH.
	// Report-level N/A does not remove DKIM from canonical scoring: non_mail and
	// explicit profiles with nonzero DKIM weight can gain score; default web_only has
	// zero DKIM weight. Scoring model 1.42.0 records the policy.
	results = applySilentDomainDkimApplicability(results);

	// BIMI applicability wording (TEXT ONLY — severity and score untouched).
	// `adjustBimiForNonMailDomain` above only runs on the non-mail branch, so a
	// domain that declares "no mail" some *other* way — an SPF `-all` no-send
	// policy on a domain that still accepts inbound mail — kept the "eligible for
	// BIMI" sales pitch. Recommending BIMI to a domain that cannot send email is a
	// factual error, and it contradicts the same report's own no-send finding.
	if (!declaresNoInboundMail && hasNoSendPolicy) {
		results = adjustBimiForNonMailDomain(results);
	}

	// Impersonation escalation: a mail-sending domain whose DMARC is weak/absent
	// AND that has active lookalike/shadow impersonation domains is the brand-
	// justified critical case. Re-escalate the demoted DMARC finding to critical
	// so it is distinguishable from a routine mail domain with the same gap. Only
	// applies when the domain actually sends mail (has MX, not a no-send policy).
	if (!declaresNoInboundMail && !hasNoSendPolicy && hasActiveImpersonation(results) && dmarcIsWeak(results)) {
		results = escalateDmarcForImpersonation(results);
	}

	return results;
}

function getParentDomain(domain: string): string | null {
	const parts = domain.split('.');
	if (parts.length <= 2) return null;
	return parts.slice(1).join('.');
}

async function checkApexDmarcPolicy(domain: string): Promise<boolean> {
	const parent = getParentDomain(domain);
	if (!parent) return false;

	try {
		const records = await queryTxtRecords(`_dmarc.${parent}`);
		const dmarcRecord = records.find((record) => record.toLowerCase().startsWith('v=dmarc1'));
		if (!dmarcRecord) return false;

		const tags = parseDmarcTags(dmarcRecord);
		const effectivePolicy = tags.get('sp') || tags.get('p') || '';
		return effectivePolicy === 'quarantine' || effectivePolicy === 'reject';
	} catch {
		return false;
	}
}

function isMissingRecordFinding(finding: { title: string; detail: string }): boolean {
	// Match against title only (controlled by check modules, not DNS data) to avoid ReDoS on attacker-controlled detail strings
	const title = finding.title.toLowerCase();
	return (
		title.includes('missing') ||
		title.includes('not found') ||
		title.includes('no mta-sts') ||
		title.includes('no dkim') ||
		/^no\s+\S+\s+record/.test(title)
	);
}

/**
 * Rewrite the MTA-STS "both records missing" summary to name inbound mail as the
 * reason it matters — but ONLY for a domain that actually accepts inbound mail.
 *
 * The caller gates this on `!mxDeclaresNoInboundMail(mxResult)`. Without that
 * gate a null-MX domain was told "Since this domain has MX records and accepts
 * email…" in the very same response that reported "Null MX record (RFC 7505) —
 * Domain explicitly declares it does not accept email". `check-mta-sts` already
 * branches its own copy on a real MX probe (`detectInboundMail`), so for a
 * non-mail domain the correct wording is the one the check itself produced and
 * the right action here is to leave it alone.
 *
 * The gate stays permissive on an INCONCLUSIVE MX result so this keeps serving
 * its original purpose: correcting the check's non-mail copy when the check's own
 * MX probe failed but the scan's `mx` check found real mail routing.
 */
function clarifyMtaStsForMailDomain(domain: string, results: CheckResult[]): CheckResult[] {
	return results.map((result) => {
		if (result.category !== 'mta_sts') return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if (finding.title === 'No MTA-STS or TLS-RPT records found') {
				return {
					...finding,
					detail: `Neither MTA-STS nor TLS-RPT records are present for ${domain}. Since this domain has MX records and accepts email, adding MTA-STS and TLS-RPT is recommended to protect inbound email in transit.`,
				};
			}
			return finding;
		});
		return rebuildUnlessAbstained(result, adjusted);
	});
}

function adjustForNonApexNonMailHost(results: CheckResult[]): CheckResult[] {
	const mailCategories: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'mta_sts', 'bimi', 'tlsrpt', 'dane', 'subdomailing'];
	return results.map((result) => {
		if (!mailCategories.includes(result.category)) return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if ((finding.severity === 'critical' || finding.severity === 'high') && isMissingRecordFinding(finding)) {
				return {
					...finding,
					severity: 'info' as const,
					detail: `${finding.detail} (not applicable — this non-apex host has no MX; mail controls are evaluated at its mail domain)`,
					...notApplicableMetadata(finding),
				};
			}
			return finding;
		});
		return rebuildUnlessAbstained(result, adjusted);
	});
}

function adjustForNonMailDomain(results: CheckResult[]): CheckResult[] {
	const emailCategories: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'mta_sts', 'subdomailing'];
	return results.map((result) => {
		if (!emailCategories.includes(result.category)) return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if ((finding.severity === 'critical' || finding.severity === 'high') && isMissingRecordFinding(finding)) {
				// Callers gate this on enforcing parent DMARC, so the covering wording is
				// unconditional here. The old two-branch version had `severity: 'info'`
				// OUTSIDE the conditional, so the boolean only picked prose while every
				// no-MX domain got the downgrade — keep this single-branch to prevent a
				// re-introduction of that split.
				const reason = 'expected — no MX records and parent domain DMARC policy covers subdomains';
				return { ...finding, severity: 'info' as const, detail: `${finding.detail} (${reason})`, ...notApplicableMetadata(finding) };
			}
			return finding;
		});
		return rebuildUnlessAbstained(result, adjusted);
	});
}

/**
 * Replace the "eligible for BIMI" recommendation with a non-applicability note on
 * a domain that does not send email (no MX / RFC 7505 null MX / SPF `-all`
 * no-send policy).
 *
 * TEXT ONLY — severity, metadata, and therefore the category score are untouched;
 * only the `detail` prose of the one matching finding changes. `scan_domain`
 * already handles the category correctly (`bimi` lands in
 * `notApplicableCategories` with a null score); this closes the prose half.
 */
function adjustBimiForNonMailDomain(results: CheckResult[]): CheckResult[] {
	return results.map((result) => {
		if (result.category !== 'bimi') return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if (finding.title === 'No BIMI record found' && finding.detail.includes('eligible for BIMI')) {
				// Trim the sentence-terminating dot the greedy \S+ swallows, else the
				// rewritten detail reads "…default._bimi.example.com.. This domain…".
				const bimiDomain = (finding.detail.match(/at (default\._bimi\.\S+)/)?.[1] ?? `default._bimi.unknown`).replace(/\.+$/, '');
				return {
					...finding,
					detail: `No BIMI record found at ${bimiDomain}. This domain does not appear to send email, so BIMI is not applicable.`,
				};
			}
			return finding;
		});
		return rebuildUnlessAbstained(result, adjusted);
	});
}

/**
 * Active brand impersonation is signalled by a medium-or-higher `lookalikes`
 * finding (a calibrated lookalike/typosquat with real infrastructure). Info-level
 * findings — defensive registrations, shared-NS matches — are deliberately excluded.
 *
 * TASK 7B (2026-07-27) — what a medium-or-higher `lookalikes` finding MEANS.
 * The severities this predicate sees come from the THREAT-OBSERVATION axis
 * (`metadata.findingAxis === 'threat_observation'`): the #264-calibrated
 * per-candidate observations about infrastructure (e.g. a confusable domain
 * with live MX on a disposable provider), the aggregate HIGH summary, and — on
 * an operator deploy with the BV_RECON binding — the `'medium'` CT-corroboration
 * finding. ATTRIBUTION-axis findings (`'attribution'`) are capped at `info` for
 * every non-`owned_by_seed` verdict and can never trip this, and an
 * `owned_by_seed` candidate emits no threat finding at all — so the DMARC
 * escalation is keyed on OBSERVED impersonation-shaped infrastructure, never on
 * an ownership claim about a third party's domain.
 *
 * CORRECTION (fix round 1, F3): an earlier revision of this note claimed the
 * predicate was "unreachable" under Task 7 because every `lookalikes` finding
 * was capped at `info`. That was FALSE — the recon CT-corroboration finding has
 * never been routed through the ownership gate and emits `'medium'` regardless.
 * The Task 7 gate broke the DNS-derived path only; 7b restored it.
 *
 * This keys on `lookalikes` ONLY (≈ "at least one medium-or-higher finding"). The
 * `impersonation_weak_dmarc` score penalty that once shared this signal was removed
 * with the post-scoring interaction layer (scoring model 2.0.0), so this is now a
 * label-only escalation. `shadow_domains` is a valid corroborator but is left out
 * for now.
 */
function hasActiveImpersonation(results: CheckResult[]): boolean {
	const lookalikes = results.find((result) => result.category === 'lookalikes');
	if (!lookalikes) return false;
	return lookalikes.findings.some(
		(finding: Finding) => finding.severity === 'medium' || finding.severity === 'high' || finding.severity === 'critical',
	);
}

/** Weak DMARC = no record at all, or a published p=none policy (the two demoted findings). */
function dmarcIsWeak(results: CheckResult[]): boolean {
	const dmarc = results.find((result) => result.category === 'dmarc');
	if (!dmarc) return false;
	return dmarc.findings.some(
		(finding: Finding) => finding.title === 'No DMARC record found' || finding.title === 'DMARC policy set to none',
	);
}

/** Re-escalate the weak-DMARC finding(s) to critical, recording why. */
function escalateDmarcForImpersonation(results: CheckResult[]): CheckResult[] {
	return results.map((result) => {
		if (result.category !== 'dmarc') return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if (finding.title === 'No DMARC record found' || finding.title === 'DMARC policy set to none') {
				return {
					...finding,
					severity: 'critical' as const,
					detail: `${finding.detail} (escalated — active lookalike/impersonation domains were detected for this domain, so weak DMARC enforcement is an exploitable spoofing channel)`,
				};
			}
			return finding;
		});
		return rebuildUnlessAbstained(result, adjusted);
	});
}

function adjustForNoSendDomain(results: CheckResult[]): CheckResult[] {
	const noSendCategories: CheckCategory[] = ['dkim', 'mta_sts', 'bimi'];
	return results.map((result) => {
		if (!noSendCategories.includes(result.category)) return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if ((finding.severity === 'critical' || finding.severity === 'high') && isMissingRecordFinding(finding)) {
				return {
					...finding,
					severity: 'info' as const,
					detail: `${finding.detail} (expected — domain SPF policy rejects all outbound mail)`,
					...notApplicableMetadata(finding),
				};
			}
			return finding;
		});
		return rebuildUnlessAbstained(result, adjusted);
	});
}
