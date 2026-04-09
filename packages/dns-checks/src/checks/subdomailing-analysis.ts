// SPDX-License-Identifier: BUSL-1.1

/**
 * SubdoMailing analysis helpers.
 * Detects SPF include/redirect domains vulnerable to takeover via
 * dangling CNAME, hijackable NS delegation, or expired/parked domains.
 *
 * Reference: Guardio Labs SubdoMailing report (Feb 2024).
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { DNSQueryFunction, Finding, Severity } from '../types';
import { createFinding } from '../check-utils';
import { isThirdPartyTakeoverService } from './subdomain-takeover-analysis';
import { extractLookupDomains } from './spf-analysis';

/** Maximum number of include domains to probe (latency cap). */
export const MAX_INCLUDE_PROBES = 15;

/** Maximum SPF include recursion depth. */
const MAX_RECURSION_DEPTH = 3;

/** Per-domain probe timeout (ms). */
const PROBE_TIMEOUT_MS = 3_000;

/** Parallel probe batch size. */
const BATCH_SIZE = 5;

export type SubdomailingRiskType = 'dangling_cname' | 'dangling_ns' | 'expired_domain' | 'void_include';

export interface SubdomailingProbeResult {
	domain: string;
	mechanism: string;
	riskType: SubdomailingRiskType | null;
	severity: Severity;
	cnameTarget?: string;
	nsTargets?: string[];
	takeoverService?: string;
	detail: string;
}

/**
 * Recursively extract all include/redirect domains from an SPF record chain.
 * Capped at MAX_RECURSION_DEPTH and MAX_INCLUDE_PROBES total domains.
 */
export async function extractSpfIncludeChain(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<{ domains: Map<string, string>; spfRecord: string | null }> {
	const timeout = options?.timeout ?? PROBE_TIMEOUT_MS;
	const collected = new Map<string, string>(); // domain → mechanism (e.g., "include:spf.example.com")
	const visited = new Set<string>();

	let rootSpf: string | null = null;

	async function resolve(d: string, depth: number): Promise<void> {
		if (depth > MAX_RECURSION_DEPTH || collected.size >= MAX_INCLUDE_PROBES) return;
		const normalized = d.toLowerCase();
		if (visited.has(normalized)) return;
		visited.add(normalized);

		let txtRecords: string[];
		try {
			txtRecords = await queryDNS(normalized, 'TXT', { timeout });
		} catch {
			return;
		}

		const spfRecord = txtRecords.find((r) => r.trimStart().startsWith('v=spf1'));
		if (!spfRecord) return;

		if (depth === 0) rootSpf = spfRecord;

		const { includes, redirect } = extractLookupDomains(spfRecord);

		for (const inc of includes) {
			if (collected.size >= MAX_INCLUDE_PROBES) break;
			if (!collected.has(inc)) {
				collected.set(inc, `include:${inc}`);
			}
			await resolve(inc, depth + 1);
		}

		if (redirect && !collected.has(redirect) && collected.size < MAX_INCLUDE_PROBES) {
			collected.set(redirect, `redirect=${redirect}`);
			await resolve(redirect, depth + 1);
		}
	}

	await resolve(domain, 0);
	return { domains: collected, spfRecord: rootSpf };
}

/**
 * Probe a single SPF include domain for SubdoMailing risk indicators.
 *
 * Checks (in order):
 * 1. CNAME → dangling CNAME to a known takeover service
 * 2. NS → unresolvable nameserver targets (NS delegation hijack)
 * 3. TXT → void include (no SPF record on the included domain)
 */
export async function probeIncludeDomain(
	includeDomain: string,
	mechanism: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<SubdomailingProbeResult> {
	const timeout = options?.timeout ?? PROBE_TIMEOUT_MS;
	const base: Omit<SubdomailingProbeResult, 'riskType' | 'severity' | 'detail'> = {
		domain: includeDomain,
		mechanism,
	};

	// ── 1. CNAME probe ──────────────────────────────────────────────────────
	try {
		const cnameRecords = await queryDNS(includeDomain, 'CNAME', { timeout });
		if (cnameRecords.length > 0) {
			const cname = cnameRecords[0].replace(/\.$/, '').toLowerCase();

			if (isThirdPartyTakeoverService(cname)) {
				// Check if the CNAME target actually resolves
				let resolves = false;
				try {
					const aRecords = await queryDNS(cname, 'A', { timeout });
					resolves = aRecords.length > 0;
				} catch {
					// Query failure = does not resolve
				}

				if (!resolves) {
					return {
						...base,
						riskType: 'dangling_cname',
						severity: 'critical',
						cnameTarget: cname,
						takeoverService: cname,
						detail: `SPF ${mechanism} points to ${includeDomain} which has a dangling CNAME to ${cname}. An attacker could claim this resource and send authenticated email as the target domain.`,
					};
				}
			}
		}
	} catch {
		// CNAME query failure — continue to NS check
	}

	// ── 2. NS delegation probe ──────────────────────────────────────────────
	try {
		const nsRecords = await queryDNS(includeDomain, 'NS', { timeout });
		if (nsRecords.length > 0) {
			const danglingNs: string[] = [];
			for (const ns of nsRecords) {
				const nsHost = ns.replace(/\.$/, '').toLowerCase();
				try {
					const aRecords = await queryDNS(nsHost, 'A', { timeout });
					if (aRecords.length === 0) {
						danglingNs.push(nsHost);
					}
				} catch {
					danglingNs.push(nsHost);
				}
			}

			if (danglingNs.length > 0) {
				return {
					...base,
					riskType: 'dangling_ns',
					severity: 'high',
					nsTargets: danglingNs,
					detail: `SPF ${mechanism} points to ${includeDomain} whose nameserver(s) do not resolve: ${danglingNs.join(', ')}. An attacker could register these NS targets and control the SPF authorization for the domain.`,
				};
			}
		}
	} catch {
		// NS query failure — continue to TXT check
	}

	// ── 3. Void include (no SPF record) ─────────────────────────────────────
	try {
		const txtRecords = await queryDNS(includeDomain, 'TXT', { timeout });
		const hasSpf = txtRecords.some((r) => r.trimStart().startsWith('v=spf1'));
		if (!hasSpf) {
			return {
				...base,
				riskType: 'void_include',
				severity: 'low',
				detail: `SPF ${mechanism} points to ${includeDomain} which has no SPF record. This wastes a DNS lookup and could become exploitable if the domain is abandoned.`,
			};
		}
	} catch {
		// TXT query also failed — treat as void
		return {
			...base,
			riskType: 'void_include',
			severity: 'low',
			detail: `SPF ${mechanism} points to ${includeDomain} which could not be queried. This could indicate a DNS resolution issue or abandoned domain.`,
		};
	}

	// All clean
	return {
		...base,
		riskType: null,
		severity: 'info',
		detail: `SPF ${mechanism} points to ${includeDomain} — no takeover risk detected.`,
	};
}

/**
 * Probe all include domains in parallel batches.
 * Returns findings for any domains with detected risks.
 */
export async function probeAllIncludes(
	includes: Map<string, string>,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<Finding[]> {
	const findings: Finding[] = [];
	const entries = Array.from(includes.entries());

	// Process in batches to bound concurrent DNS queries
	for (let i = 0; i < entries.length; i += BATCH_SIZE) {
		const batch = entries.slice(i, i + BATCH_SIZE);
		const results = await Promise.allSettled(
			batch.map(([domain, mechanism]) => probeIncludeDomain(domain, mechanism, queryDNS, options)),
		);

		for (const result of results) {
			if (result.status !== 'fulfilled') continue;
			const probe = result.value;
			if (probe.riskType === null) continue;

			findings.push(
				createFinding('subdomailing', titleForRisk(probe.riskType), probe.severity, probe.detail, {
					includeDomain: probe.domain,
					mechanism: probe.mechanism,
					riskType: probe.riskType,
					...(probe.cnameTarget ? { cnameTarget: probe.cnameTarget } : {}),
					...(probe.nsTargets ? { nsTargets: probe.nsTargets } : {}),
					...(probe.takeoverService ? { takeoverService: probe.takeoverService } : {}),
				}),
			);
		}
	}

	return findings;
}

function titleForRisk(riskType: SubdomailingRiskType): string {
	switch (riskType) {
		case 'dangling_cname':
			return 'Dangling CNAME in SPF include chain';
		case 'dangling_ns':
			return 'Dangling NS delegation in SPF include chain';
		case 'expired_domain':
			return 'Expired domain in SPF include chain';
		case 'void_include':
			return 'Void SPF include';
	}
}
