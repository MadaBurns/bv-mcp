// SPDX-License-Identifier: BUSL-1.1

/**
 * DMARC (Domain-based Message Authentication, Reporting & Conformance) check.
 * RFC 9989 (DMARCbis, obsoletes 7489/9091).
 *
 * Organizational-Domain / policy discovery uses the RFC 9989 §4.10 DNS tree walk
 * (NOT a Public Suffix List): query `_dmarc.<name>` walking up the hierarchy to the
 * first record found. A record found above the queried domain applies via the org
 * domain's `sp` (subdomain policy), with `inheritedFromParent` set.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult } from '../check-utils';
import { classifyDmarc, appendDmarcCleanInfo, type DmarcFacts } from '../scoring/classifiers/dmarc';
import { checkRuaAuthorization, detectThirdPartyAggregators, isValidDmarcUri, parseDmarcTags } from './dmarc-utils';

export { parseDmarcTags } from './dmarc-utils';

const TREE_WALK_LABEL_LIMIT = 8;

/**
 * RFC 9989 §4.10 ordered query names: the full domain first; if it has ≥8 labels,
 * collapse to the last 7; then strip the left-most label one at a time down to the
 * last two-label name. No Public Suffix List.
 */
function treeWalkTargets(domain: string): string[] {
	const labels = domain.toLowerCase().split('.').filter(Boolean);
	if (labels.length === 0) return [];

	const targets: string[] = [labels.join('.')];
	let working = labels;
	if (labels.length >= TREE_WALK_LABEL_LIMIT) {
		working = labels.slice(labels.length - 7);
		targets.push(working.join('.'));
	}
	while (working.length > 1) {
		working = working.slice(1);
		const name = working.join('.');
		if (name !== targets[targets.length - 1]) targets.push(name);
	}
	return targets;
}

/**
 * Walk `_dmarc.<name>` up the hierarchy (RFC 9989 §4.10), stopping at the first
 * name with a v=DMARC1 record. NXDOMAIN (DNS status 3) halts the walk; NODATA
 * continues up. Returns the found name's TXT records + where it was found.
 */
async function dmarcTreeWalk(
	domain: string,
	queryDNS: DNSQueryFunction,
	timeout: number,
): Promise<{ txtRecords: string[]; foundAt: string | null }> {
	for (const name of treeWalkTargets(domain)) {
		let txt: string[];
		try {
			txt = await queryDNS(`_dmarc.${name}`, 'TXT', { timeout });
		} catch (error) {
			if ((error as { dnsStatus?: number })?.dnsStatus === 3) {
				return { txtRecords: [], foundAt: null };
			}
			throw error;
		}
		if (/v=dmarc1/i.test(txt.join(''))) {
			return { txtRecords: txt, foundAt: name };
		}
		// NODATA at this name — continue up the tree.
	}
	return { txtRecords: [], foundAt: null };
}

const DMARC_POLICY_TOKENS = new Set(['none', 'quarantine', 'reject']);

/**
 * Map a raw `p=` / `sp=` / `np=` token onto the closed {@link DmarcPolicyValue}
 * union, WITHOUT applying any RFC 9989 §4.7 inheritance.
 *
 * `undefined` in (tag absent from a published record) becomes `not-specified`,
 * and anything else unrecognised becomes `invalid`. Both are measured facts
 * about a record that exists; neither is `none`. The np -> sp -> p fallback
 * chain is deliberately NOT resolved here — a consumer needs to see which tags
 * were actually published in order to explain its own verdict, and a resolved
 * value would erase that evidence.
 */
function normalizeDmarcPolicyTag(raw: string | null | undefined): 'none' | 'quarantine' | 'reject' | 'not-specified' | 'invalid' {
	if (raw === undefined || raw === null) return 'not-specified';
	const token = raw.trim().toLowerCase();
	if (token === '') return 'not-specified';
	return DMARC_POLICY_TOKENS.has(token) ? (token as 'none' | 'quarantine' | 'reject') : 'invalid';
}

/**
 * Check DMARC records for a domain (RFC 9989, with §4.10 tree-walk discovery).
 */
export async function checkDMARC(domain: string, queryDNS: DNSQueryFunction, options?: { timeout?: number }): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;

	const walk = await dmarcTreeWalk(domain, queryDNS, timeout);

	if (!walk.foundAt) {
		// No DMARC record at all → not an active control. controlPresent:false (definitively
		// absent; a DNS *error* throws out of the tree-walk instead, leaving controlPresent undefined).
		return buildCheckResult('dmarc', classifyDmarc({ recordCount: 0, policy: null, domain }), false, false);
	}

	// A record found above the queried domain is inherited via the org domain.
	const inheritedFromParent = walk.foundAt !== domain;

	// Concatenate to handle DMARC data split across multiple TXT strings.
	const concatenatedTxt = walk.txtRecords.join('');
	const dmarcMatch = concatenatedTxt.match(/v=dmarc1[^]*/i);
	const dmarcRecords = dmarcMatch ? [dmarcMatch[0]] : [];
	const dmarcMatches = concatenatedTxt.match(/v=dmarc1/gi);
	const recordCount = dmarcMatches?.length ?? 1;

	const tags = parseDmarcTags(dmarcRecords[0]);
	const p = tags.get('p') ?? null;
	const sp = tags.get('sp');

	// Effective policy: inherited subdomains apply the org domain's sp (falling
	// back to p); the queried domain itself applies p directly. (RFC 9989 §4.10/§5.)
	const policy = inheritedFromParent ? sp || p : p;

	const rua = tags.get('rua');
	const ruf = tags.get('ruf');
	const ruaUris = rua ? rua.split(',').map((u) => u.trim()) : [];
	const rufUris = ruf ? ruf.split(',').map((u) => u.trim()) : [];

	const facts: DmarcFacts = {
		recordCount,
		policy,
		domain,
		sp,
		np: tags.get('np'),
		pct: tags.get('pct'),
		ri: tags.get('ri'),
		fo: tags.get('fo'),
		rua,
		ruf,
		adkim: tags.get('adkim'),
		aspf: tags.get('aspf'),
		t: tags.get('t'),
		inheritedFromParent,
		// On an inherited scan, carry the org domain's OWN p= (and where it was found) so the
		// classifier can name the parent-enforcing / subdomain-open asymmetry. `policy` above is
		// already the effective (sp-resolved) value and no longer holds the parent's p=.
		orgPolicy: inheritedFromParent ? (p ?? undefined) : undefined,
		orgDomain: inheritedFromParent ? (walk.foundAt ?? undefined) : undefined,
		aggregators: rua ? detectThirdPartyAggregators(ruaUris) : [],
		invalidRuaUris: ruaUris.filter((uri) => !isValidDmarcUri(uri)),
		invalidRufUris: rufUris.filter((uri) => !isValidDmarcUri(uri)),
	};

	const findings: Finding[] = classifyDmarc(facts);

	// DNS-dependent cross-domain RUA authorization (RFC 9990 §4) — stays in the
	// check wrapper, not the pure classifier.
	if (rua) {
		findings.push(...(await checkRuaAuthorization(walk.foundAt, ruaUris, queryDNS, timeout)));
	}

	// Closing reassurance finding, evaluated over the COMPLETE finding set.
	appendDmarcCleanInfo(findings, facts.policy);

	// controlPresent = DMARC is an ACTIVE anti-spoofing control = enforcing (p=quarantine|reject).
	// p=none is monitoring-only (not enforcing → false). Consumed by detectDomainContext as the
	// enterprise_mail maturity gate. pct< 100 is intentionally not de-rated here, matching the
	// existing scan post-processing enforcement convention.
	const dmarcEnforcing = policy === 'quarantine' || policy === 'reject';

	// POLICY-STRENGTH METADATA (bv-mcp #991, following the #987 shape for spf/mta_sts).
	//
	// `sp`, `np` and `pct` have been parsed into DmarcFacts above since long before this,
	// and were then discarded: their only surviving trace was a finding TITLE, and prose
	// inference is forbidden downstream (findingsIndicatePartialEnforcement's docblock
	// records why). A compliance consumer asking "does this p=reject domain leave its
	// subdomains open?" had no structured answer at all.
	//
	// UNMEASURED IS NOT A VALUE. This block is reached only when the tree walk FOUND a
	// record; the no-record path returns above and carries no metadata, so every reader
	// reports `undefined` there. Within a found record, an omitted tag is the DISTINCT
	// member `not-specified` and an out-of-union token is `invalid` — neither is `none`,
	// because reporting an unstated subdomain policy as "none" would invent an exposure.
	//
	// `pct` is recorded as PRESENCE only: RFC 9989 Appendix A.6 removes the tag, so the
	// value is irrelevant to the question, and the raw token is subject-controlled while
	// top-level metadata does NOT pass through sanitizeFindingMetadata.
	//
	// Observational, never read by the scoring path — identical to controlPresent /
	// recordPresent / spfAll / mtaStsMode in that respect. No score, severity, `passed`
	// or grade depends on any of it.
	const metadata = {
		dmarcPolicy: normalizeDmarcPolicyTag(p),
		dmarcSubdomainPolicy: normalizeDmarcPolicyTag(sp),
		dmarcNonExistentSubdomainPolicy: normalizeDmarcPolicyTag(tags.get('np')),
		dmarcPctPresent: tags.get('pct') !== undefined,
		dmarcInheritedFromParent: inheritedFromParent,
	};

	// recordPresent = a DMARC record was PUBLISHED (the tree walk found one, here or at the org
	// domain) — true even for p=none, which reads controlPresent false. This is the exact pair the
	// CheckResult docs table calls out; do not collapse it into `dmarcEnforcing`.
	const result = buildCheckResult('dmarc', findings, dmarcEnforcing, true, metadata);
	return findings.some((f) => f.metadata?.assessment === 'not_assessed') ? { ...result, partial: true } : result;
}
