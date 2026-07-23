// SPDX-License-Identifier: BUSL-1.1

/**
 * CAA (Certificate Authority Authorization) check.
 * Validates CAA DNS records that restrict which CAs can issue certificates.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding, ZoneContext } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { type CaaRecord, parseCaaRecord, getCaaConfiguredFinding, getCaaValidationFindings, summarizeCaaTags } from './caa-analysis';

/** Hard cap on ancestor hops during the RFC 8659 CAA climb — mirrors the zone-apex walk bound. */
const MAX_CAA_CLIMB_DEPTH = 8;

/** Enumerate label → floor ancestors (inclusive of both ends), bounded by MAX_CAA_CLIMB_DEPTH. */
function ancestorChainToFloor(label: string, floor: string): string[] {
	const chain: string[] = [];
	let current = label;
	for (let i = 0; i <= MAX_CAA_CLIMB_DEPTH; i += 1) {
		chain.push(current);
		if (current === floor) break;
		const dot = current.indexOf('.');
		if (dot === -1) break;
		current = current.slice(dot + 1);
	}
	return chain;
}

/**
 * RFC 8659 CAA tree-climb: starting at the nearest ancestor above `start`, query CAA
 * up to (and including) `floor` — the PSL registrable domain, never crossed. Returns
 * the first non-empty parsed CAA RRset found. Fail-soft: a query error at a given
 * ancestor is treated as "no CAA here" and the climb continues to the next ancestor.
 */
async function climbForCaa(
	start: string,
	floor: string,
	queryDNS: DNSQueryFunction,
	timeout: number,
): Promise<{ records: CaaRecord[]; foundAt: string | null }> {
	const ancestors = ancestorChainToFloor(start, floor).slice(1);
	for (const ancestor of ancestors) {
		try {
			const raw = await queryDNS(ancestor, 'CAA', { timeout });
			const parsed = raw.map(parseCaaRecord).filter((record): record is CaaRecord => record !== null);
			if (parsed.length > 0) {
				return { records: parsed, foundAt: ancestor };
			}
		} catch {
			// Fail-soft: a resolver error at this ancestor doesn't fail the whole check —
			// treat as "no CAA at this level" and keep climbing toward the floor.
		}
	}
	return { records: [], foundAt: null };
}

/**
 * Check CAA records for a domain.
 * Validates that CAA records exist and are properly configured.
 *
 * Queries CAA record type and parses the raw DNS data into structured records.
 */
export async function checkCAA(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; zone?: ZoneContext },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const findings: Finding[] = [];
	const zone = options?.zone;

	let rawRecords: string[];
	try {
		rawRecords = await queryDNS(domain, 'CAA', { timeout });
	} catch {
		findings.push(createFinding('caa', 'CAA query failed', 'medium', `Could not query CAA records for ${domain}.`));
		return buildCheckResult('caa', findings);
	}

	// Parse raw CAA record data into structured records
	const caaRecords: CaaRecord[] = rawRecords
		.map(parseCaaRecord)
		.filter((record): record is CaaRecord => record !== null);

	if (caaRecords.length === 0) {
		// RFC 8659: CAA is located by climbing from the FQDN toward the apex. A non-apex
		// label with no CAA of its own inherits the nearest ancestor's CAA RRset. Bounded
		// by the PSL registrable floor (zone.registrableDomain). Apex targets (zone.isApex,
		// or no zone) skip this — byte-identical output. Gated strictly on isApex, NOT
		// delegationStatus: CAA inheritance follows the DNS tree, independent of NS delegation.
		if (zone && !zone.isApex) {
			const climbed = await climbForCaa(domain, zone.registrableDomain, queryDNS, timeout);
			if (climbed.records.length > 0 && climbed.foundAt) {
				findings.push(
					createFinding(
						'caa',
						'CAA inherited from parent zone',
						'info',
						`${domain} has no CAA records of its own; CAA policy is inherited from ${climbed.foundAt} per RFC 8659.`,
					),
				);
				findings.push(...getCaaValidationFindings(summarizeCaaTags(climbed.records)));
				return buildCheckResult('caa', findings, true);
			}
			// Climb reached the registrable floor with nothing found — genuinely no CAA
			// anywhere up the tree. Fall through to the existing "No CAA records" finding.
		}

		// RFC 8659: absence of CAA means ANY CA may issue — a real defense-in-depth gap,
		// but NOT a zeroed control (CA/B-Forum hardening, not a NIST-DNS baseline). MEDIUM
		// (→85), no missingControl. Severity MUST stay medium: at high/critical the
		// "no … record" text would trip scoreIndicatesMissingControl and re-zero it.
		// (D3: a managed-CDN domain still owes a CAA record listing its CDN's CA.)
		findings.push(
			createFinding(
				'caa',
				'No CAA records',
				'medium',
				`No CAA records found for ${domain}. CAA records restrict which Certificate Authorities can issue certificates for your domain, preventing unauthorized issuance.`,
			),
		);
		// No CAA records observed → control absent (a query failure above leaves controlPresent undefined).
		return buildCheckResult('caa', findings, false);
	}

	findings.push(...getCaaValidationFindings(summarizeCaaTags(caaRecords)));

	// If no issues found
	if (findings.length === 0) {
		findings.push(getCaaConfiguredFinding());
	}

	// CAA records present → control present.
	return buildCheckResult('caa', findings, true);
}
