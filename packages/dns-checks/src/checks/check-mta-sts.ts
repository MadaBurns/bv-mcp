// SPDX-License-Identifier: BUSL-1.1

/**
 * MTA-STS (Mail Transfer Agent Strict Transport Security) check.
 * Queries _mta-sts TXT records and validates the MTA-STS policy.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, CheckStatus, DNSQueryFunction, FetchFunction, Finding, ZoneContext } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { readResponseTextCapped } from '../response-body';
import { RobotsDisallowedError, describeRobotsScope, robotsAbstentionMetadata } from '../robots-gate';
import { isNullMxRecord, parseMxRecords } from './mx-analysis';
import {
	finalizeMissingMtaStsRecordFinding,
	finalizeMissingTlsRptRecordFinding,
	extractPolicyMxPatterns,
	getMtaStsPolicyFindings,
	getMtaStsTxtFindings,
	getTlsRptRecordFindings,
	getUncoveredMxHostFindings,
	shouldSummarizeMissingMailProtections,
} from './mta-sts-analysis';

/** Default HTTPS timeout (ms) */
const HTTPS_TIMEOUT_MS = 4_000;

/**
 * Why an `mta_sts` result was NOT assessed (issue #889), carried additively in the
 * not-assessed finding's `metadata.notAssessedReason`. `checkStatus` alone cannot say
 * this — its union is deliberately `'completed' | 'timeout' | 'error'` (#743) — so the
 * reason travels here, the same way `robotsAbstentionMetadata` already does for the
 * robots case in `ssl` / `http_security` / `bimi`.
 *
 * - `robots_disallowed`   — the `mta-sts.<domain>` host's robots.txt disallowed the policy fetch.
 * - `policy_fetch_failed` — the policy fetch THREW (transport error, TLS/egress failure, the
 *                            package's own `AbortSignal.timeout`, a resolver failure for the
 *                            `mta-sts.` host) before any HTTP response was received.
 * - `dns_query_failed`    — the `_mta-sts` or `_smtp._tls` TXT lookup rejected.
 */
export type MtaStsNotAssessedReason = 'robots_disallowed' | 'policy_fetch_failed' | 'dns_query_failed';

/**
 * Parse MX records from raw DNS response strings.
 * MX data format: "priority exchange"
 */
function parseMxFromRaw(answers: string[]): Array<{ exchange: string }> {
	return answers.map((answer) => {
		const parts = answer.split(' ');
		const exchange = (parts.slice(1).join(' ') || '').replace(/\.$/, '').toLowerCase();
		return { exchange };
	});
}

/**
 * Classify a thrown fetch / resolver call by the ONLY signal that distinguishes a stall from
 * a refusal: the error's `name`. `AbortSignal.timeout` rejects with a DOMException named
 * `TimeoutError` (workerd, Node ≥ 17.3) or `AbortError` (older runtimes / composed signals);
 * everything else — ECONNRESET, TLS failure, SERVFAIL, an egress refusal — is `'error'`.
 * `'error'` is also the class `scan_domain`'s transient-zero retry fires on.
 */
function classifyTransportFailure(err: unknown): CheckStatus {
	const name = (err as { name?: unknown } | null)?.name;
	return name === 'AbortError' || name === 'TimeoutError' ? 'timeout' : 'error';
}

/**
 * The not-assessed shape (issue #889): `checkStatus` is what EXCLUDES the category from the
 * profile score (renormalised, shown n/a — never zeroed, never penalised); `score: 0` +
 * `passed: false` because an unmeasured check did not pass; `partial: true` keeps the
 * transient outcome OUT of the result cache so the next call re-measures.
 *
 * `controlPresent` / `recordPresent` are passed through ONLY when the `_mta-sts` record was
 * actually observed (`true`); a lookup that never answered leaves them `undefined` (unknown).
 * They are never `false` on this path — that would assert an absence nobody measured.
 */
function buildNotAssessedResult(findings: Finding[], status: CheckStatus, txtRecordObserved: boolean): CheckResult {
	const observed = txtRecordObserved ? true : undefined;
	return {
		...buildCheckResult('mta_sts', findings, observed, observed),
		score: 0,
		passed: false,
		checkStatus: status,
		partial: true,
	};
}

/** The `info` finding documenting a rejected `_mta-sts` / `_smtp._tls` TXT lookup. */
function buildDnsNotAssessedFinding(label: string, name: string, status: CheckStatus): Finding {
	return createFinding(
		'mta_sts',
		`${label} not assessed (DNS lookup ${status === 'timeout' ? 'timed out' : 'failed'})`,
		'info',
		`The scanner's TXT lookup for ${name} did not complete, so ${label} could not be assessed on this run. ` +
			`This is not evidence about the domain — an empty answer would have been graded as a missing record. Retry to re-measure.`,
		// `errorKind: 'dns_error'` is the marker `isDnsErrorFinding` consumers filter on (no
		// remediation, no compliance verdict, nothing to sell against an unmeasured category).
		// Never `missingControl` alongside it (issue #638).
		{ inconclusive: true, errorKind: 'dns_error', notAssessedReason: 'dns_query_failed' satisfies MtaStsNotAssessedReason },
	);
}

/**
 * Check MTA-STS configuration for a domain.
 * Queries _mta-sts.<domain> TXT records and optionally fetches the policy file.
 *
 * Abstention doctrine (issue #889): only a DEFINITE answer from the domain is evidence —
 * a non-ok HTTP status on the policy URL, or an empty TXT answer. A failure of the
 * scanner's OWN I/O (a thrown fetch, a rejecting resolver, a robots.txt disallow) is
 * returned as NOT ASSESSED via `checkStatus` + an `info` finding, never as a scored
 * deficiency against the domain. See {@link MtaStsNotAssessedReason}.
 */
export async function checkMTASTS(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; fetchFn?: FetchFunction; zone?: ZoneContext },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const fetchFn = options?.fetchFn;
	let findings: Finding[] = [];

	// Check for _mta-sts TXT record
	let hasTxtRecord = false;
	try {
		const txtRecords = await queryDNS(`_mta-sts.${domain}`, 'TXT', { timeout });
		const txtAnalysis = getMtaStsTxtFindings(txtRecords);
		hasTxtRecord = txtAnalysis.hasTxtRecord;
		findings.push(...finalizeMissingMtaStsRecordFinding(txtAnalysis.findings, domain));
	} catch (err) {
		// The lookup that everything else hangs off never answered: nothing about MTA-STS was
		// measured. Abstain outright (mirrors `checkMX`) — was a scored `low` "DNS query failed".
		const status = classifyTransportFailure(err);
		return buildNotAssessedResult([buildDnsNotAssessedFinding('MTA-STS', `_mta-sts.${domain}`, status)], status, false);
	}

	// A scanner-side failure observed below. The measured findings gathered so far are KEPT
	// for display; the abstention decides the result shape at the end.
	let notAssessedStatus: CheckStatus | null = null;
	const notAssessedFindings: Finding[] = [];

	// Try to fetch the MTA-STS policy file (only if fetch function provided)
	if (hasTxtRecord && fetchFn) {
		const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
		try {
			const response = await fetchFn(policyUrl, {
				method: 'GET',
				redirect: 'manual',
				signal: AbortSignal.timeout(HTTPS_TIMEOUT_MS),
			});

			if ([301, 302, 303, 307, 308].includes(response.status)) {
				findings.push(
					createFinding(
						'mta_sts',
						'MTA-STS policy redirects',
						'high',
						`MTA-STS policy file at ${policyUrl} returned HTTP ${response.status} redirect. The policy must be served directly at the well-known URL without redirects.`,
					),
				);
				// Body unread on this branch — release it so workerd doesn't cancel a stalled response.
				void response.body?.cancel().catch(() => undefined);
			} else if (!response.ok) {
				// A DEFINITE HTTP answer (404/403/5xx) from the policy host IS evidence and stays
				// scored. (A WAF challenge page is the one known exception — the bv-mcp wrapper
				// fingerprints the response and excludes it; see issue #455.)
				findings.push(
					createFinding(
						'mta_sts',
						'MTA-STS policy file not accessible',
						'high',
						`MTA-STS policy file at ${policyUrl} returned HTTP ${response.status}. The policy file must be accessible over HTTPS.`,
					),
				);
				void response.body?.cancel().catch(() => undefined);
			} else {
				const MAX_BODY_BYTES = 65_536; // 64 KB — RFC 8461 max for MTA-STS
				const body = await readResponseTextCapped(response, MAX_BODY_BYTES);
				if (body === null) {
					findings.push(
						createFinding(
							'mta_sts',
							'MTA-STS policy file oversized',
							'high',
							`MTA-STS policy file at ${policyUrl} exceeds 64 KB. This is abnormally large for an MTA-STS policy and was not parsed.`,
						),
					);
				} else {
					findings.push(...getMtaStsPolicyFindings(body, policyUrl));

					const policyMxPatterns = extractPolicyMxPatterns(body);
					const modeMatch = body.match(/mode:\s*(enforce|testing|none)/i);
					const policyMode = modeMatch ? modeMatch[1].toLowerCase() : '';
					if (policyMxPatterns.length > 0 && (policyMode === 'enforce' || policyMode === 'testing')) {
						try {
							const mxAnswers = await queryDNS(domain, 'MX', { timeout });
							const mxRecords = parseMxFromRaw(mxAnswers);
							findings.push(
								...getUncoveredMxHostFindings(
									mxRecords.map((mx) => mx.exchange),
									policyMxPatterns,
								),
							);
						} catch {
							// MX query failed; skip coverage cross-check. A sub-signal of an otherwise
							// measured policy — silent abstention, neither scored nor excluding.
						}
					}
				}
			}
		} catch (err) {
			// Everything the fetch can THROW lands here: the scanner's own `AbortSignal.timeout`
			// firing, a TLS/egress failure, a `RobotsDisallowedError` from a gate wrapped around
			// `fetchFn`, a resolver failure for `mta-sts.<domain>`. None of these is an
			// observation about the domain (issue #889) — was a scored `medium` "policy fetch
			// failed" (category 85) indistinguishable from a domain that lacks the control.
			if (err instanceof RobotsDisallowedError) {
				notAssessedStatus = 'error';
				notAssessedFindings.push(
					createFinding(
						'mta_sts',
						'MTA-STS policy not independently verified (robots.txt)',
						'info',
						`${policyUrl} could not be fetched: the mta-sts.${domain} host's robots.txt ${describeRobotsScope(err.scope)}. ` +
							`The _mta-sts DNS record itself was observed; only the policy file's own contents were not checked. Not scored — see https://www.blackveilsecurity.com/bot-policy.`,
						{ ...robotsAbstentionMetadata(err.scope), inconclusive: true },
					),
				);
			} else {
				const status = classifyTransportFailure(err);
				notAssessedStatus = status;
				notAssessedFindings.push(
					createFinding(
						'mta_sts',
						`MTA-STS policy not assessed (${status === 'timeout' ? 'scanner timeout' : 'transport error'})`,
						'info',
						`The scanner's fetch of ${policyUrl} did not complete (${status === 'timeout' ? 'the request timed out' : 'a transport error occurred'} before any HTTP response was received), ` +
							`so policy accessibility could not be verified on this run. This is not evidence about ${domain}: the _mta-sts DNS record was observed, and a definite HTTP answer would have been graded. Retry to re-measure.`,
						// No `missingControl` (issue #638): a fetch that never delivered a response
						// established nothing about the policy. `checkStatus` below excludes the category.
						{
							inconclusive: true,
							errorKind: status === 'timeout' ? 'timeout' : 'transport_error',
							notAssessedReason: 'policy_fetch_failed' satisfies MtaStsNotAssessedReason,
						},
					),
				);
			}
		}
	}

	// Check for TLSRPT record
	let hasTlsRptRecord = false;
	// True ONLY when the lookup ANSWERED (an empty answer is a measured absence). A rejected
	// lookup must not read as "we looked" — that was the #889 `tlsRptChecked = true` defect.
	let tlsRptChecked = false;
	try {
		const tlsrptRecords = await queryDNS(`_smtp._tls.${domain}`, 'TXT', { timeout });
		tlsRptChecked = true;
		const tlsRptAnalysis = getTlsRptRecordFindings(tlsrptRecords);
		hasTlsRptRecord = tlsRptAnalysis.hasTlsRptRecord;
		findings.push(...finalizeMissingTlsRptRecordFinding(tlsRptAnalysis.findings, domain));
	} catch (err) {
		// Was a scored `low` "TLS-RPT DNS query failed" (category 95) recorded as measured.
		const status = classifyTransportFailure(err);
		notAssessedStatus ??= status;
		notAssessedFindings.push(buildDnsNotAssessedFinding('TLS-RPT', `_smtp._tls.${domain}`, status));
	}

	if (notAssessedStatus) {
		return buildNotAssessedResult([...findings, ...notAssessedFindings], notAssessedStatus, hasTxtRecord);
	}

	// If no issues found
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'mta_sts',
				'MTA-STS properly configured',
				'info',
				`MTA-STS is properly configured for ${domain} with an accessible policy file.`,
			),
		);
	}

	// If both records are missing, add a clear summary and suppress duplicate findings.
	// Defect K (issue #264 sibling): branch the copy and severity on MX presence —
	// missing MTA-STS on a domain that DOES accept inbound mail is medium (real
	// risk), but on a domain with no inbound mail it's a low-severity informational
	// note. Without the branch, paypal/stripe-class domains (with real MX) get
	// the "do not accept inbound email" copy, which is factually wrong.
	if (shouldSummarizeMissingMailProtections(findings, hasTxtRecord, tlsRptChecked, hasTlsRptRecord)) {
		// MTA-STS applicability follows the scanned LABEL's own inbound-mail role
		// (RFC 8461), NOT its NS-delegation status: a non-apex label can still be a
		// genuine mail-receiving host (its own MX), so ALWAYS probe MX and treat a
		// missing policy as a real finding whenever the label accepts inbound mail.
		// Only when the label accepts NO inbound mail is the absence out of scope —
		// worded as an info "not applicable" for a non-apex (e.g. an ESP sending
		// subdomain), or the existing low informational for an apex with no mail.
		// (Gating the info purely on `!isApex` previously suppressed the real medium
		// on a mail-receiving subdomain — a false negative.)
		const hasMx = await detectInboundMail(domain, queryDNS, timeout);
		const nonApex = !!(options?.zone && !options.zone.isApex);
		findings = [];
		if (hasMx) {
			findings.push(
				createFinding(
					'mta_sts',
					'No MTA-STS or TLS-RPT records found',
					// Graded `medium`, NOT `missingControl: true` — this is the same ABSENCE
					// condition as the single-record path, just the both-missing summary of it.
					// See MTA_STS_ABSENCE_IS_GRADED_NOT_ZEROING in mta-sts-analysis.ts for the
					// corpus evidence (96.5% of measured domains scored 0 on this category).
					'medium',
					`${domain} accepts inbound email (MX records present) but has neither MTA-STS nor TLS-RPT configured. Sending MTAs cannot enforce TLS or report failures for mail to this domain.`,
				),
			);
		} else if (nonApex) {
			findings.push(
				createFinding(
					'mta_sts',
					'MTA-STS not applicable to this label',
					'info',
					`${domain} is a subdomain, not a mail-receiving zone apex. MTA-STS policy is defined per mail host (RFC 8461) and is not inherited from a parent zone, so its absence here is not a deficiency.`,
				),
			);
		} else {
			findings.push(
				createFinding(
					'mta_sts',
					'No MTA-STS or TLS-RPT records found',
					// No inbound MX → this domain does not receive mail, so missing MTA-STS
					// is NOT a deficiency (low, no missingControl → ~95).
					'low',
					`Neither MTA-STS nor TLS-RPT records are present for ${domain}. This is normal for domains that do not accept inbound email, but consider adding these records if you operate a mail server.`,
				),
			);
		}
	}

	// controlPresent: an MTA-STS policy record (_mta-sts TXT) was observed. TLS-RPT alone does not
	// count as MTA-STS.
	//
	// recordPresent asks the narrower question "was an `_mta-sts` TXT record published", so it
	// tracks that SAME RRset — never the TLS-RPT one this check also reports on, and never the
	// policy file (an unfetchable policy is still a published record). On this (measured) path
	// the lookup answered, so `false` is a genuine observed absence; a lookup that never
	// answered returned early above with both flags `undefined`.
	return buildCheckResult('mta_sts', findings, hasTxtRecord, hasTxtRecord);
}

/**
 * Lightweight MX presence probe used by the missing-mail-protections summary
 * to branch its copy and severity. Returns `true` only when the domain has at
 * least one real (non-null, RFC 7505) MX record. Any DNS failure resolves to
 * `false` (treat as "no inbound mail") so a flaky lookup can't synthesise a
 * medium-severity finding out of nothing.
 */
async function detectInboundMail(domain: string, queryDNS: DNSQueryFunction, timeout: number): Promise<boolean> {
	try {
		const mxAnswers = await queryDNS(domain, 'MX', { timeout });
		const parsed = parseMxRecords(mxAnswers);
		return parsed.some((record) => !isNullMxRecord(record));
	} catch {
		return false;
	}
}
