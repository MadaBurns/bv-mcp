// SPDX-License-Identifier: BUSL-1.1

/**
 * DNSSEC (DNS Security Extensions) check.
 * Validates DNSSEC by checking the AD flag, querying for DNSKEY/DS records,
 * and auditing algorithm and digest type security.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding, RawDNSQueryFunction, ZoneContext } from '../types';
import { buildNotAssessedResult, buildCheckResult, createFinding } from '../check-utils';
import { isInconclusiveRcode, queryWithRcode } from '../dns-rcode';
import { auditDnskeyAlgorithms, auditDsDigestTypes, auditNsec3Params } from './dnssec-analysis';
import { isRegistryManagedDnssec } from './registry-managed-dnssec';

export { parseDnskeyAlgorithm, parseDsRecord } from './dnssec-analysis';

/**
 * What the DNSKEY / DS / NSEC3PARAM probes returned.
 *
 * `dnskeyQueryFailed` / `dsQueryFailed` are read by `recordPresentFlag` and the
 * chain-unmeasured lane. The finding logic deliberately treats a failed lookup as absent
 * (fail-soft), but "we could not look" is not "nothing is published" — so the observational
 * flag must stay `undefined` rather than assert a false absence. Same distinction check-dane /
 * check-mta-sts already draw for their own lookups.
 */
interface DnssecLookups {
	dnskeyRecords: string[];
	dsRecords: string[];
	nsec3ParamRecords: string[];
	dnskeyQueryFailed: boolean;
	dsQueryFailed: boolean;
}

/**
 * Check DNSSEC configuration for a domain.
 * Verifies the AD (Authenticated Data) flag, checks for DNSKEY/DS records,
 * and audits algorithm and digest type security.
 *
 * Requires a rawQueryDNS function that returns the full DoH response (including AD flag).
 * Falls back to queryDNS for DNSKEY/DS record queries.
 *
 * Phases, in the original (query-order-significant) sequence: zone gate → AD probe →
 * DNSKEY → DS → NSEC3PARAM → findings → result. Do not reorder, parallelise or add queries.
 */
export async function checkDNSSEC(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; rawQueryDNS?: RawDNSQueryFunction; zone?: ZoneContext },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const zoneAbstention = abstainOnUnknownZone(options?.zone);
	if (zoneAbstention) return zoneAbstention;

	const target = resolveDnssecTarget(domain, options?.zone);
	const adFlag = await probeAdFlag(target, options?.rawQueryDNS, timeout);
	if (adFlag === null) return notAssessedResult(`Could not query DNSSEC status for ${target} due to a transient DNS failure; this control was not assessed.`);

	const lookups = await fetchDnssecLookups(target, queryDNS, timeout);
	const findings = await collectDnssecFindings(domain, target, lookups, adFlag, queryDNS, timeout);
	return finalizeDnssecResult(target, lookups, findings, adFlag, Boolean(options?.rawQueryDNS));
}

function notAssessedResult(detail: string): CheckResult {
	return buildNotAssessedResult('dnssec', createFinding('dnssec', 'DNSSEC not assessed', 'info', detail));
}

/**
 * Zone walk did not complete: an abstention (score 0 + partial + checkStatus 'error'),
 * NOT an info-only pass. The old shape spread checkStatus over buildCheckResult's
 * score-100 result, so scan_domain's transient-zero retry (checkStatus error && score 0)
 * never fired and the non-answer was cached for five minutes (#900).
 */
function abstainOnUnknownZone(zone: ZoneContext | undefined): CheckResult | null {
	if (zone && !zone.isApex && zone.delegationStatus === 'unknown') {
		return notAssessedResult(
			`Could not determine the authoritative zone for ${zone.scannedLabel} due to a transient DNS failure; DNSSEC posture was not assessed.`,
		);
	}
	return null;
}

/**
 * A non-apex label with no zone of its own inherits DNSSEC posture from its
 * signed zone apex (resolved by `resolveZoneApex` upstream) — evaluate the
 * AD flag / DNSKEY / DS / NSEC3PARAM at the apex instead of the empty
 * subdomain, else every such label gets a false "DNSSEC not enabled" −40
 * penalty. Apex targets (or no zone context) are unaffected: target === domain.
 */
function resolveDnssecTarget(domain: string, zone: ZoneContext | undefined): string {
	return zone && !zone.isApex && zone.delegationStatus === 'inherited' ? zone.zoneApex : domain;
}

/**
 * Check the AD flag via a raw DoH query. Returns `null` when the probe threw.
 *
 * A transient resolver failure on the AD-flag probe means we could not MEASURE DNSSEC. The
 * caller marks the category INCONCLUSIVE (checkStatus) so the scoring engine renormalizes over
 * the remaining categories instead of penalizing a possibly-healthy domain with a scored
 * deficiency. (The DNSKEY/DS/NSEC3PARAM catches below are legitimate fail-soft "treat as
 * absent" and stay unchanged.) Same retryable, non-cacheable abstention shape as caa/mx/ns (#900).
 * With no rawQueryDNS we can't check the AD flag — continue without it (false).
 */
async function probeAdFlag(target: string, rawQueryDNS: RawDNSQueryFunction | undefined, timeout: number): Promise<boolean | null> {
	try {
		if (!rawQueryDNS) return false;
		const resp = await rawQueryDNS(target, 'A', true, { timeout });
		return resp.AD === true;
	} catch {
		return null;
	}
}

/**
 * One DNSKEY / DS lookup. A SERVFAIL/REFUSED answer is an EMPTY record set exactly like a
 * NOERROR/NODATA one, but it measured nothing — a DNSSEC-bogus zone typically SERVFAILs its
 * DNSKEY. It is recorded as a failed lookup (same as a throw) so the unmeasured-chain lane
 * owns it (SQ-279).
 */
async function lookupRrset(
	queryDNS: DNSQueryFunction,
	target: string,
	type: 'DNSKEY' | 'DS',
	timeout: number,
): Promise<{ records: string[]; failed: boolean }> {
	try {
		const outcome = await queryWithRcode(queryDNS, target, type, timeout);
		return { records: outcome.records, failed: outcome.records.length === 0 && isInconclusiveRcode(outcome.rcode) };
	} catch {
		// Non-critical: query failure — treat as absent
		return { records: [], failed: true };
	}
}

async function lookupNsec3Param(queryDNS: DNSQueryFunction, target: string, timeout: number): Promise<string[]> {
	try {
		return await queryDNS(target, 'NSEC3PARAM', { timeout });
	} catch {
		// Non-critical: NSEC3PARAM query failure — domain may use NSEC instead of NSEC3
		return [];
	}
}

/** Query DNSKEY, DS, and NSEC3PARAM records independently, in that order; default to empty on failure. */
async function fetchDnssecLookups(target: string, queryDNS: DNSQueryFunction, timeout: number): Promise<DnssecLookups> {
	const dnskey = await lookupRrset(queryDNS, target, 'DNSKEY', timeout);
	const ds = await lookupRrset(queryDNS, target, 'DS', timeout);
	const nsec3ParamRecords = await lookupNsec3Param(queryDNS, target, timeout);
	return {
		dnskeyRecords: dnskey.records,
		dsRecords: ds.records,
		nsec3ParamRecords,
		dnskeyQueryFailed: dnskey.failed,
		dsQueryFailed: ds.failed,
	};
}

/** Non-apex inherited target: lead with an INFO note attributing the verdict back to the scanned label. */
function inheritedPostureFinding(domain: string, target: string): Finding {
	return createFinding(
		'dnssec',
		'DNSSEC posture inherited from zone apex',
		'info',
		`${domain} is not a separately delegated zone, so its DNSSEC posture is inherited from and evaluated at the zone apex ${target} — the verdict below applies to ${target}.`,
		{ inheritedFromApex: target },
	);
}

/** Findings in the original order: inheritance note, presence verdict, registry-managed note, audits. */
async function collectDnssecFindings(
	domain: string,
	target: string,
	lookups: DnssecLookups,
	adFlag: boolean,
	queryDNS: DNSQueryFunction,
	timeout: number,
): Promise<Finding[]> {
	const findings: Finding[] = [];
	if (target !== domain) findings.push(inheritedPostureFinding(domain, target));
	const presence = classifyPresence(target, lookups, adFlag);
	if (presence) findings.push(presence);
	findings.push(...(await registryManagedFindings(target, lookups, adFlag, queryDNS, timeout)));
	findings.push(...auditDnssecMaterial(target, lookups));
	return findings;
}

function isFullyAbsent(l: DnssecLookups): boolean {
	return l.dnskeyRecords.length === 0 && l.dsRecords.length === 0 && !l.dnskeyQueryFailed && !l.dsQueryFailed;
}

/** ⚠️ The `!dsQueryFailed` gate is LOAD-BEARING — see {@link islandOfTrustFinding}. */
function isIslandOfTrust(l: DnssecLookups): boolean {
	return l.dnskeyRecords.length > 0 && l.dsRecords.length === 0 && !l.dsQueryFailed;
}

function isChainIncomplete(l: DnssecLookups): boolean {
	return l.dnskeyRecords.length === 0 && l.dsRecords.length > 0 && !l.dnskeyQueryFailed;
}

function isValidationFailing(l: DnssecLookups, adFlag: boolean): boolean {
	return l.dnskeyRecords.length > 0 && l.dsRecords.length > 0 && !adFlag;
}

/** Both DNSKEY and DS observed AND the resolver set AD — the only state that counts as a validated chain. */
function isValidatedChain(l: DnssecLookups, adFlag: boolean): boolean {
	return adFlag && l.dnskeyRecords.length > 0 && l.dsRecords.length > 0;
}

/**
 * The consolidated presence verdict: at most one of the four mutually exclusive shapes
 * (unsigned, island of trust, incomplete chain, validation failing), checked in the original order.
 */
function classifyPresence(target: string, l: DnssecLookups, adFlag: boolean): Finding | undefined {
	if (isFullyAbsent(l)) return unsignedZoneFinding(target);
	if (isIslandOfTrust(l)) return islandOfTrustFinding(target);
	if (isChainIncomplete(l)) return chainIncompleteFinding(target);
	if (isValidationFailing(l, adFlag)) return validationFailingFinding(target);
	return undefined;
}

function unsignedZoneFinding(target: string): Finding {
	// Fully absent — HIGH severity, but the SCORE penalty is decoupled to −40 via
	// `penaltyOverride`. NIST SP 800-81r3 (Mar 2026) makes DNSSEC a baseline
	// deployment goal and RFC 9364 (BCP 237) states origin-authentication via DNSSEC
	// is "the best current practice", so an unsigned PUBLIC zone is a near-failing
	// deficiency (−40 → ~60) — far heavier than the previous lenient 75. The severity
	// LABEL is `high` (not `critical`): DNSSEC is one of several integrity controls,
	// not a sole baseline, so it doesn't warrant the top triage tier — but the heavy
	// proportionate deduction the prior `critical` carried is preserved via the
	// override, keeping the category score unchanged at 60.
	//
	// `missingControl: false` is the STRUCTURAL statement of that decision: an unsigned
	// zone is a graded deficiency, never a zeroing. It replaces a copywriting constraint
	// that used to live in this comment — the detail text was required to avoid the words
	// "no … record", "missing" and "not found" so `scoreIndicatesMissingControl`'s regex
	// could not auto-zero the finding. Nothing enforced that, and `dnssec` is a critical
	// category in EVERY profile, so a reword would not merely have zeroed the category: it
	// would have capped the whole domain at `criticalGapCeiling` (64 → grade D). The
	// declaration outranks the prose (scoring/model.ts `findingsIndicateMissingControl`),
	// so the sentence below is now ordinary, editable prose.
	return createFinding(
		'dnssec',
		'DNSSEC not enabled',
		'high',
		`DNSSEC is not configured for ${target}. Without DNSSEC, DNS responses are not cryptographically verified, leaving SPF, DMARC, and DKIM records vulnerable to DNS-level manipulation.`,
		{ penaltyOverride: 40, missingControl: false },
	);
}

function islandOfTrustFinding(target: string): Finding {
	// DNSKEY published without a parent DS is an island of trust. Validating
	// resolvers classify the delegation as INSECURE, not BOGUS: the zone gets no
	// origin authentication, but answers do not fail validation solely because the
	// parent has not anchored the child. Grade it like an unsigned zone (60) and
	// declare `missingControl: false`, since asserting the control absent would zero
	// this critical category and cap the entire domain at grade D.
	//
	// ⚠️ The `!dsQueryFailed` gate (isIslandOfTrust) is LOAD-BEARING. A DS probe that
	// THREW leaves `dsRecords` empty, which is structurally indistinguishable here from a
	// measured "the parent holds no DS" — and this branch's missingControl zeroes
	// the category. Because `dnssec` is a critical category in every profile, that
	// zero also caps the ENTIRE domain at `criticalGapCeiling` (64 → grade D). So
	// without this gate a single transient DS timeout re-grades a correctly signed
	// domain to D off a delegation nobody observed. Unmeasured probes route to the
	// inconclusive lane (buildChainUnmeasuredResult) instead (#638 law: `inconclusive` +
	// `errorKind` for a probe that never completed, `missingControl` only for a MEASURED
	// absence). The sibling check_dnssec_chain gained the same gate in #844's review.
	return createFinding(
		'dnssec',
		'DNSSEC island of trust',
		'high',
		`DNSKEY records are published for ${target}, but the parent zone does not publish a DS linkage. Validating resolvers therefore treat the delegation as insecure: answers remain available, but DNSSEC provides no origin authentication until the registrar publishes the DS.`,
		{ penaltyOverride: 40, missingControl: false },
	);
}

function chainIncompleteFinding(target: string): Finding {
	// Parent DS published but the child DNSKEY is absent — also a broken chain.
	// A validating resolver cannot match the delegation to a zone key, regardless
	// of a transient/cached AD observation, so this must never become a clean pass.
	return createFinding(
		'dnssec',
		'DNSSEC chain of trust incomplete',
		'high',
		`DS records are published for ${target} in the parent zone but no DNSKEY records are available from the child zone. The chain of trust is broken — DNSSEC validation will fail.`,
		{ missingControl: true },
	);
}

function validationFailingFinding(target: string): Finding {
	// Deployed but validation failing (BOGUS) — worse than not having DNSSEC.
	// DNSSEC-1 decision: explicit missingControl → score 0 (same BOGUS principle as
	// the broken chain — a validating resolver rejects the zone's data outright).
	return createFinding(
		'dnssec',
		'DNSSEC validation failing',
		'high',
		`DNSKEY and DS records are present for ${target} but the AD flag is not set. DNSSEC is deployed but validation is failing — this is worse than not having DNSSEC.`,
		{ missingControl: true },
	);
}

/**
 * Registry-managed DNSSEC: when the chain validates (AD set + DS + DNSKEY), some
 * ccTLD registries auto-signed the zone rather than the owner. The zone is still
 * protected, so this is a MODERATE deduction (medium → ~85), not the punitive 50
 * bv-web historically used — 50 would rank a validated zone BELOW an unsigned one
 * (60), which is incoherent. Detection is fail-safe (false when indeterminate).
 */
async function registryManagedFindings(
	target: string,
	lookups: DnssecLookups,
	adFlag: boolean,
	queryDNS: DNSQueryFunction,
	timeout: number,
): Promise<Finding[]> {
	if (!isValidatedChain(lookups, adFlag)) return [];
	return (await isRegistryManagedDnssec(target, queryDNS, timeout)) ? [registryManagedFinding(target)] : [];
}

function registryManagedFinding(target: string): Finding {
	return createFinding(
		'dnssec',
		'DNSSEC is registry-managed',
		'medium',
		`The DNSSEC chain for ${target} validates, but the zone is signed by its ccTLD registry rather than independently configured by the domain owner. The zone is cryptographically protected, but the owner has less direct control over key management.`,
	);
}

/** Algorithm/digest audits (only when records exist). */
function auditDnssecMaterial(target: string, l: DnssecLookups): Finding[] {
	const findings: Finding[] = [];
	if (l.dnskeyRecords.length > 0) findings.push(...auditDnskeyAlgorithms(target, l.dnskeyRecords));
	if (l.dsRecords.length > 0) findings.push(...auditDsDigestTypes(target, l.dsRecords));
	if (l.nsec3ParamRecords.length > 0) findings.push(...auditNsec3Params(target, l.nsec3ParamRecords));
	return findings;
}

/**
 * ⚠️ Evaluated BEFORE the affirmative fallback, deliberately. A failed DS/DNSKEY probe alongside
 * published DNSSEC material leaves the chain genuinely unknown: the broken-chain branches withheld
 * their verdict, so this run has nothing honest left to score. Returning there also stops the
 * `findings.length === 0` fallback from appending "DNSSEC enabled and validated" — which it
 * otherwise would for the DNSKEY-failed/DS-present shape, printing a confident affirmative for a
 * chain whose child key was never observed.
 *
 * A failed leg with NOTHING published on either side is also unmeasured: "DNSSEC not enabled"
 * needs BOTH legs observed empty, and the gate on that branch routes the failed-leg shape here
 * instead (SQ-279). A failed leg beside a published one (e.g. DS failed while the DNSKEY
 * answered) is the original shape this lane was built for.
 */
function isChainUnmeasured(l: DnssecLookups): boolean {
	return (l.dsQueryFailed && l.dsRecords.length === 0) || (l.dnskeyQueryFailed && l.dnskeyRecords.length === 0);
}

function unmeasuredLeg(l: DnssecLookups): string {
	return l.dsQueryFailed && l.dnskeyQueryFailed ? 'DS and DNSKEY' : l.dsQueryFailed ? 'DS' : 'DNSKEY';
}

function anyDnssecRecordObserved(l: DnssecLookups): boolean {
	return l.dnskeyRecords.length > 0 || l.dsRecords.length > 0;
}

/**
 * Shape matches the repo's standard unmeasured contract (`buildDnsErrorResult`):
 * `checkStatus: 'error'` EXCLUDES the category from scoring; `score: 0` is what
 * scan_domain's `shouldRetry` (`checkStatus === 'error' && score === 0`) requires to
 * re-run the leg; `partial: true` is what `runCachedCheck`'s `!r.partial` predicate
 * requires to keep a transient non-answer out of the 5-minute cache. Never
 * `missingControl` — the probe did not complete (#638 law).
 */
function buildChainUnmeasuredResult(target: string, l: DnssecLookups, findings: Finding[]): CheckResult {
	findings.push(
		createFinding(
			'dnssec',
			'DNSSEC chain of trust not assessable',
			'info',
			`The ${unmeasuredLeg(l)} lookup for ${target} did not complete, so the delegation linking the parent zone to the child's DNSSEC material could not be observed. The chain of trust is unverified for this run — this reflects the lookup, not the zone's configuration. Re-run to assess it.`,
			{ inconclusive: true, confidence: 'heuristic', errorKind: 'dns_error' },
		),
	);
	return {
		// `recordPresent` is TRUE when material really was observed on the leg that
		// answered, and `undefined` when no leg published anything (both lookups failed:
		// nothing was observed either way). `controlPresent` must be `undefined`, not
		// `false`: `false` is a definitive "not doing work" observation, and one leg of
		// this chain was never read. `undefined` is the contract's "could not be determined".
		...buildCheckResult('dnssec', findings, undefined, anyDnssecRecordObserved(l) ? true : undefined),
		checkStatus: 'error',
		score: 0,
		passed: false,
		partial: true,
	};
}

function enabledAndValidatedFinding(target: string): Finding {
	return createFinding(
		'dnssec',
		'DNSSEC enabled and validated',
		'info',
		`DNSSEC is properly configured for ${target}. DNS responses are cryptographically verified.`,
	);
}

/**
 * Structured adoption signal. DNSSEC is the ONE scored category whose score band cannot answer
 * "is this control present". Every other category zeroes on absence, so `score > 0` is a valid
 * presence test — but an unsigned zone here lands at exactly 60 via the `penaltyOverride: 40`
 * (only a BROKEN chain sets `missingControl` and zeroes). A uniform `score > 0` sweep therefore
 * reports ~95-100% DNSSEC adoption against a true single-digit rate; measured on a 2,123-domain
 * NZ corpus the raw category values were {0: 44, 55: 1, 60: 1942, >60: 136} — 91% of domains
 * sitting on that magic 60.
 *
 * These two flags are the repo's existing presence idiom (see `CheckResult.recordPresent`)
 * and separate the three states a consumer actually needs, with no magic number:
 *
 *   | state                          | recordPresent | controlPresent |
 *   | ------------------------------ | ------------- | -------------- |
 *   | unsigned zone                  | false         | false          |
 *   | published but BROKEN/bogus     | true          | false          |
 *   | signed and validating          | true          | true           |
 *
 * The AD flag alone never makes an unsigned zone's control present. A secure delegation requires
 * both the child DNSKEY and parent DS; this also prevents a resolver's transient AD=true response
 * from becoming an affirmative safety claim. Score-neutral by construction: `buildCheckResult`
 * only copies these onto the result, and `detectDomainContext` reads `controlPresent` for
 * mx/ssl/caa/dkim/mta_sts/bimi/dmarc ONLY — never dnssec — so profile selection cannot move.
 */
function recordPresentFlag(l: DnssecLookups): boolean | undefined {
	return anyDnssecRecordObserved(l) ? true : l.dnskeyQueryFailed || l.dsQueryFailed ? undefined : false;
}

/**
 * Terminal phase: the unmeasured-chain abstention, else the (possibly affirmative-fallback) result.
 * With a non-apex inherited target the prepended INFO finding means `findings.length === 0` never
 * holds, so the affirmative fallback only ever fires for the apex/direct case.
 *
 * The AD flag is only an observation when a raw resolver was actually available to ask; without
 * `rawQueryDNS` the local `adFlag` is a default-false placeholder, not a measurement.
 */
function finalizeDnssecResult(target: string, l: DnssecLookups, findings: Finding[], adFlag: boolean, hasRawResolver: boolean): CheckResult {
	if (isChainUnmeasured(l)) return buildChainUnmeasuredResult(target, l, findings);
	if (findings.length === 0) findings.push(enabledAndValidatedFinding(target));
	return buildCheckResult('dnssec', findings, hasRawResolver ? isValidatedChain(l, adFlag) : undefined, recordPresentFlag(l));
}
