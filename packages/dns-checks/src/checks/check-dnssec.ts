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
import { buildCheckResult, createFinding } from '../check-utils';
import { auditDnskeyAlgorithms, auditDsDigestTypes, auditNsec3Params } from './dnssec-analysis';
import { isRegistryManagedDnssec } from './registry-managed-dnssec';

export { parseDnskeyAlgorithm, parseDsRecord } from './dnssec-analysis';

/**
 * Check DNSSEC configuration for a domain.
 * Verifies the AD (Authenticated Data) flag, checks for DNSKEY/DS records,
 * and audits algorithm and digest type security.
 *
 * Requires a rawQueryDNS function that returns the full DoH response (including AD flag).
 * Falls back to queryDNS for DNSKEY/DS record queries.
 */
export async function checkDNSSEC(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; rawQueryDNS?: RawDNSQueryFunction; zone?: ZoneContext },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const rawQueryDNS = options?.rawQueryDNS;
	const findings: Finding[] = [];

	if (options?.zone && !options.zone.isApex && options.zone.delegationStatus === 'unknown') {
		return {
			...buildCheckResult('dnssec', [
				createFinding(
					'dnssec',
					'DNSSEC not assessed',
					'info',
					`Could not determine the authoritative zone for ${options.zone.scannedLabel} due to a transient DNS failure; DNSSEC posture was not assessed.`,
				),
			]),
			checkStatus: 'error',
		};
	}

	// A non-apex label with no zone of its own inherits DNSSEC posture from its
	// signed zone apex (resolved by `resolveZoneApex` upstream) — evaluate the
	// AD flag / DNSKEY / DS / NSEC3PARAM at the apex instead of the empty
	// subdomain, else every such label gets a false "DNSSEC not enabled" −40
	// penalty. Apex targets (or no zone context) are unaffected: target === domain.
	const target = options?.zone && !options.zone.isApex && options.zone.delegationStatus === 'inherited' ? options.zone.zoneApex : domain;

	// Check AD flag via raw DoH query
	let adFlag = false;
	try {
		if (rawQueryDNS) {
			const resp = await rawQueryDNS(target, 'A', true, { timeout });
			adFlag = resp.AD === true;
		}
		// If no rawQueryDNS provided, we can't check AD flag — continue without it
	} catch {
		// Transient resolver failure on the AD-flag probe — we could not MEASURE DNSSEC. Mark the
		// category INCONCLUSIVE (checkStatus) so the scoring engine renormalizes over the remaining
		// categories instead of penalizing a possibly-healthy domain with a scored deficiency.
		// (The DNSKEY/DS/NSEC3PARAM catches below are legitimate fail-soft "treat as absent" and
		// stay unchanged.)
		return {
			...buildCheckResult('dnssec', [
				createFinding(
					'dnssec',
					'DNSSEC not assessed',
					'info',
					`Could not query DNSSEC status for ${target} due to a transient DNS failure; this control was not assessed.`,
				),
			]),
			checkStatus: 'error',
		};
	}

	// Query DNSKEY, DS, and NSEC3PARAM records independently; default to empty on failure
	let dnskeyRecords: string[] = [];
	let dsRecords: string[] = [];
	let nsec3ParamRecords: string[] = [];
	// Read ONLY by `recordPresent` below. The finding logic deliberately treats a failed
	// lookup as absent (fail-soft), but "we could not look" is not "nothing is published" —
	// so the observational flag must stay `undefined` rather than assert a false absence.
	// Same distinction check-dane / check-mta-sts already draw for their own lookups.
	let dnskeyQueryFailed = false;
	let dsQueryFailed = false;

	try {
		dnskeyRecords = await queryDNS(target, 'DNSKEY', { timeout });
	} catch {
		// Non-critical: DNSKEY query failure — treat as absent
		dnskeyQueryFailed = true;
	}

	try {
		dsRecords = await queryDNS(target, 'DS', { timeout });
	} catch {
		// Non-critical: DS query failure — treat as absent
		dsQueryFailed = true;
	}

	try {
		nsec3ParamRecords = await queryDNS(target, 'NSEC3PARAM', { timeout });
	} catch {
		// Non-critical: NSEC3PARAM query failure — domain may use NSEC instead of NSEC3
	}

	// Non-apex inherited target: lead with an INFO note attributing the verdict
	// that follows (for `target`) back to the scanned label.
	if (target !== domain) {
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC posture inherited from zone apex',
				'info',
				`${domain} is not a separately delegated zone, so its DNSSEC posture is inherited from and evaluated at the zone apex ${target} — the verdict below applies to ${target}.`,
				{ inheritedFromApex: target },
			),
		);
	}

	// Consolidated finding logic
	if (dnskeyRecords.length === 0 && dsRecords.length === 0) {
		// Fully absent — HIGH severity, but the SCORE penalty is decoupled to −40 via
		// `penaltyOverride`. NIST SP 800-81r3 (Mar 2026) makes DNSSEC a baseline
		// deployment goal and RFC 9364 (BCP 237) states origin-authentication via DNSSEC
		// is "the best current practice", so an unsigned PUBLIC zone is a near-failing
		// deficiency (−40 → ~60) — far heavier than the previous lenient 75. The severity
		// LABEL is `high` (not `critical`): DNSSEC is one of several integrity controls,
		// not a sole baseline, so it doesn't warrant the top triage tier — but the heavy
		// proportionate deduction the prior `critical` carried is preserved via the
		// override, keeping the category score unchanged at 60. We do NOT set
		// `missingControl: true` (which would zero the category). The detail text
		// deliberately avoids "no … record / missing / not found" so
		// `scoreIndicatesMissingControl` cannot auto-zero the finding.
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC not enabled',
				'high',
				`DNSSEC is not configured for ${target}. Without DNSSEC, DNS responses are not cryptographically verified, leaving SPF, DMARC, and DKIM records vulnerable to DNS-level manipulation.`,
				{ penaltyOverride: 40 },
			),
		);
	} else if (dnskeyRecords.length > 0 && dsRecords.length === 0 && !dsQueryFailed) {
		// DNSKEY published without a parent DS is an island of trust. Validating
		// resolvers classify the delegation as INSECURE, not BOGUS: the zone gets no
		// origin authentication, but answers do not fail validation solely because the
		// parent has not anchored the child. Grade it like an unsigned zone (60) and do
		// not assert missingControl, which would zero this critical category and cap the
		// entire domain at grade D.
		//
		// ⚠️ The `!dsQueryFailed` gate is LOAD-BEARING. A DS probe that THREW leaves
		// `dsRecords` empty, which is structurally indistinguishable here from a
		// measured "the parent holds no DS" — and this branch's missingControl zeroes
		// the category. Because `dnssec` is a critical category in every profile, that
		// zero also caps the ENTIRE domain at `criticalGapCeiling` (64 → grade D). So
		// without this gate a single transient DS timeout re-grades a correctly signed
		// domain to D off a delegation nobody observed. Unmeasured probes route to the
		// inconclusive lane below instead (#638 law: `inconclusive` + `errorKind` for a
		// probe that never completed, `missingControl` only for a MEASURED absence).
		// The sibling check_dnssec_chain gained the same gate in #844's review.
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC island of trust',
				'high',
				`DNSKEY records are published for ${target}, but the parent zone does not publish a DS linkage. Validating resolvers therefore treat the delegation as insecure: answers remain available, but DNSSEC provides no origin authentication until the registrar publishes the DS.`,
				{ penaltyOverride: 40 },
			),
		);
	} else if (dnskeyRecords.length === 0 && dsRecords.length > 0 && !dnskeyQueryFailed) {
		// Parent DS published but the child DNSKEY is absent — also a broken chain.
		// A validating resolver cannot match the delegation to a zone key, regardless
		// of a transient/cached AD observation, so this must never become a clean pass.
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC chain of trust incomplete',
				'high',
				`DS records are published for ${target} in the parent zone but no DNSKEY records are available from the child zone. The chain of trust is broken — DNSSEC validation will fail.`,
				{ missingControl: true },
			),
		);
	} else if (dnskeyRecords.length > 0 && dsRecords.length > 0 && !adFlag) {
		// Deployed but validation failing (BOGUS) — worse than not having DNSSEC.
		// DNSSEC-1 decision: explicit missingControl → score 0 (same BOGUS principle as
		// the broken chain — a validating resolver rejects the zone's data outright).
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC validation failing',
				'high',
				`DNSKEY and DS records are present for ${target} but the AD flag is not set. DNSSEC is deployed but validation is failing — this is worse than not having DNSSEC.`,
				{ missingControl: true },
			),
		);
	}

	// Registry-managed DNSSEC: when the chain validates (AD set + DS + DNSKEY), some
	// ccTLD registries auto-signed the zone rather than the owner. The zone is still
	// protected, so this is a MODERATE deduction (medium → ~85), not the punitive 50
	// bv-web historically used — 50 would rank a validated zone BELOW an unsigned one
	// (60), which is incoherent. Detection is fail-safe (false when indeterminate).
	if (adFlag && dnskeyRecords.length > 0 && dsRecords.length > 0) {
		if (await isRegistryManagedDnssec(target, queryDNS, timeout)) {
			findings.push(
				createFinding(
					'dnssec',
					'DNSSEC is registry-managed',
					'medium',
					`The DNSSEC chain for ${target} validates, but the zone is signed by its ccTLD registry rather than independently configured by the domain owner. The zone is cryptographically protected, but the owner has less direct control over key management.`,
				),
			);
		}
	}

	// Algorithm/digest audits (only when records exist)
	if (dnskeyRecords.length > 0) {
		findings.push(...auditDnskeyAlgorithms(target, dnskeyRecords));
	}
	if (dsRecords.length > 0) {
		findings.push(...auditDsDigestTypes(target, dsRecords));
	}
	if (nsec3ParamRecords.length > 0) {
		findings.push(...auditNsec3Params(target, nsec3ParamRecords));
	}

	// ⚠️ Ordered BEFORE the affirmative fallback below, deliberately. A failed DS/DNSKEY
	// probe alongside published DNSSEC material leaves the chain genuinely unknown: the
	// broken-chain branches above withheld their verdict, so this run has nothing honest
	// left to score. Returning here also stops the `findings.length === 0` fallback from
	// appending "DNSSEC enabled and validated" — which it otherwise would for the
	// DNSKEY-failed/DS-present shape, printing a confident affirmative for a chain whose
	// child key was never observed.
	//
	// Shape matches the repo's standard unmeasured contract (`buildDnsErrorResult`):
	// `checkStatus: 'error'` EXCLUDES the category from scoring; `score: 0` is what
	// scan_domain's `shouldRetry` (`checkStatus === 'error' && score === 0`) requires to
	// re-run the leg; `partial: true` is what `runCachedCheck`'s `!r.partial` predicate
	// requires to keep a transient non-answer out of the 5-minute cache. Never
	// `missingControl` — the probe did not complete (#638 law).
	const chainUnmeasured =
		(dsQueryFailed && dnskeyRecords.length > 0 && dsRecords.length === 0) ||
		(dnskeyQueryFailed && dsRecords.length > 0 && dnskeyRecords.length === 0);
	if (chainUnmeasured) {
		const unmeasuredLeg = dsQueryFailed ? 'DS' : 'DNSKEY';
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC chain of trust not assessable',
				'info',
				`The ${unmeasuredLeg} lookup for ${target} did not complete, so the delegation linking the parent zone to the child's DNSSEC material could not be observed. The chain of trust is unverified for this run — this reflects the lookup, not the zone's configuration. Re-run to assess it.`,
				{ inconclusive: true, confidence: 'heuristic', errorKind: 'dns_error' },
			),
		);
		return {
			// `recordPresent` stays TRUE (material really was observed on the leg that
			// answered), but `controlPresent` must be `undefined`, not `false`: `false` is
			// a definitive "not doing work" observation, and one leg of this chain was
			// never read. `undefined` is the contract's "could not be determined".
			...buildCheckResult('dnssec', findings, undefined, true),
			checkStatus: 'error',
			score: 0,
			passed: false,
			partial: true,
		};
	}

	// If DNSSEC is valid and no issues found (only info findings at most)
	// Note: with a non-apex inherited target, the prepended INFO finding above
	// means `findings.length === 0` never holds here, so this branch only ever
	// fires for the apex/direct case — intentionally unchanged.
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC enabled and validated',
				'info',
				`DNSSEC is properly configured for ${target}. DNS responses are cryptographically verified.`,
			),
		);
	}

	// ── Structured adoption signal ────────────────────────────────────────────────
	// DNSSEC is the ONE scored category whose score band cannot answer "is this control
	// present". Every other category zeroes on absence, so `score > 0` is a valid presence
	// test — but an unsigned zone here lands at exactly 60 via the `penaltyOverride: 40`
	// above (only a BROKEN chain sets `missingControl` and zeroes). A uniform `score > 0`
	// sweep therefore reports ~95-100% DNSSEC adoption against a true single-digit rate;
	// measured on a 2,123-domain NZ corpus the raw category values were
	// {0: 44, 55: 1, 60: 1942, >60: 136} — 91% of domains sitting on that magic 60.
	//
	// These two flags are the repo's existing presence idiom (see `CheckResult.recordPresent`)
	// and separate the three states a consumer actually needs, with no magic number:
	//
	//   | state                          | recordPresent | controlPresent |
	//   | ------------------------------ | ------------- | -------------- |
	//   | unsigned zone                  | false         | false          |
	//   | published but BROKEN/bogus     | true          | false          |
	//   | signed and validating          | true          | true           |
	//
	// The AD flag alone never makes an unsigned zone's control present. A secure
	// delegation requires both the child DNSKEY and parent DS; this also prevents a
	// resolver's transient AD=true response from becoming an affirmative safety claim.
	//
	// Score-neutral by construction: `buildCheckResult` only copies these onto the result,
	// and `detectDomainContext` reads `controlPresent` for mx/ssl/caa/dkim/mta_sts/bimi/dmarc
	// ONLY — never dnssec — so profile selection cannot move. `recordPresent` is read by
	// nothing in the scoring path at all.
	const anyDnssecRecordObserved = dnskeyRecords.length > 0 || dsRecords.length > 0;
	const recordPresent = anyDnssecRecordObserved ? true : dnskeyQueryFailed || dsQueryFailed ? undefined : false;
	// The AD flag is only an observation when a raw resolver was actually available to ask;
	// without `rawQueryDNS` the local `adFlag` is a default-false placeholder, not a measurement.
	const controlPresent = rawQueryDNS ? adFlag && dnskeyRecords.length > 0 && dsRecords.length > 0 : undefined;

	return buildCheckResult('dnssec', findings, controlPresent, recordPresent);
}
