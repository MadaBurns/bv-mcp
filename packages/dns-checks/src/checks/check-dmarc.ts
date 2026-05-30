// SPDX-License-Identifier: BUSL-1.1

/**
 * DMARC (Domain-based Message Authentication, Reporting & Conformance) check.
 * Queries _dmarc TXT records and validates the policy.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult } from '../check-utils';
import { classifyDmarc, appendDmarcCleanInfo, type DmarcFacts } from '../scoring/classifiers/dmarc';
import { checkRuaAuthorization, detectThirdPartyAggregators, isValidDmarcUri, parseDmarcTags } from './dmarc-utils';

export { parseDmarcTags } from './dmarc-utils';

/**
 * Check DMARC records for a domain.
 * Queries _dmarc.<domain> TXT records and validates policy configuration.
 */
export async function checkDMARC(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const txtRecords = await queryDNS(`_dmarc.${domain}`, 'TXT', { timeout });

	// Concatenate all TXT records to handle cases where DMARC data is split across multiple records
	const concatenatedTxt = txtRecords.join('');

	// Extract DMARC record from concatenated TXT data
	const dmarcMatch = concatenatedTxt.match(/v=dmarc1[^]*/i);
	const dmarcRecords = dmarcMatch ? [dmarcMatch[0]] : [];

	if (dmarcRecords.length === 0) {
		return buildCheckResult('dmarc', classifyDmarc({ recordCount: 0, policy: null, domain }));
	}

	// Check for multiple DMARC records in the concatenated data
	const dmarcMatches = concatenatedTxt.match(/v=dmarc1/gi);
	const recordCount = dmarcMatches?.length ?? 1;

	const tags = parseDmarcTags(dmarcRecords[0]);
	const rua = tags.get('rua');
	const ruf = tags.get('ruf');
	const ruaUris = rua ? rua.split(',').map((u) => u.trim()) : [];
	const rufUris = ruf ? ruf.split(',').map((u) => u.trim()) : [];

	const facts: DmarcFacts = {
		recordCount,
		policy: tags.get('p') ?? null,
		domain,
		sp: tags.get('sp'),
		np: tags.get('np'),
		pct: tags.get('pct'),
		ri: tags.get('ri'),
		fo: tags.get('fo'),
		rua,
		ruf,
		adkim: tags.get('adkim'),
		aspf: tags.get('aspf'),
		t: tags.get('t'),
		inheritedFromParent: false,
		aggregators: rua ? detectThirdPartyAggregators(ruaUris) : [],
		invalidRuaUris: ruaUris.filter((uri) => !isValidDmarcUri(uri)),
		invalidRufUris: rufUris.filter((uri) => !isValidDmarcUri(uri)),
	};

	const findings: Finding[] = classifyDmarc(facts);

	// DNS-dependent cross-domain RUA authorization (RFC 7489 §7.1) — stays in the
	// check wrapper, not the pure classifier.
	if (rua) {
		findings.push(...(await checkRuaAuthorization(domain, ruaUris, queryDNS, timeout)));
	}

	// Closing reassurance finding, evaluated over the COMPLETE finding set
	// (synchronous + RUA-auth), matching the original ordering.
	appendDmarcCleanInfo(findings, facts.policy);

	return buildCheckResult('dmarc', findings);
}
