// SPDX-License-Identifier: MIT

/**
 * Shadow domain detection tool.
 * Discovers alternate-TLD variants of a domain and assesses email spoofing risk.
 * For each variant, probes NS, A, MX, SPF, and DMARC records to classify risk.
 */

import { queryDnsRecords, queryMxRecords, queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { extractBrandName, getEffectiveTld } from '../lib/public-suffix';
import { validateDomain } from '../lib/sanitize';

/** Wall-clock timeout for the entire shadow domain check (ms). */
const SHADOW_TIMEOUT_MS = 20_000;

/** Batch size for adaptive batching. */
const INITIAL_BATCH_SIZE = 4;
const MIN_BATCH_SIZE = 2;
const BACKOFF_DELAY_MS = 500;

/** Global ccTLD set always appended. */
const GLOBAL_TLDS = [
	'.com', '.net', '.org', '.io', '.ai', '.co',
	'.de', '.fr', '.nl', '.eu', '.co.uk', '.com.au',
	'.ca', '.jp', '.in', '.sg', '.za',
];

/** Regional variant TLD sets by TLD family. */
const NZ_REGIONAL = ['.nz', '.co.nz', '.org.nz', '.net.nz', '.govt.nz', '.ac.nz', '.school.nz', '.gen.nz', '.kiwi'];
const UK_REGIONAL = ['.co.uk', '.org.uk', '.uk'];
const AU_REGIONAL = ['.com.au', '.org.au', '.net.au', '.gov.au'];
const GENERIC_EXTRA = ['.dev', '.app'];

/** Generic TLD family members. */
const GENERIC_TLDS = new Set(['.com', '.org', '.net', '.io', '.dev', '.app', '.co', '.ai']);

/** Probe result for a single variant domain. */
interface VariantProbeResult {
	variant: string;
	ns: string[];
	hasA: boolean;
	mx: string[];
	hasSpf: boolean;
	dmarcPolicy: string | null;
}

/**
 * Generate alternate-TLD variants for a given brand name and effective TLD.
 * Excludes the primary domain from the result.
 */
export function generateVariants(brand: string, effectiveTld: string, primaryDomain: string): string[] {
	const tldLower = effectiveTld.toLowerCase();
	const primaryLower = primaryDomain.toLowerCase();
	const allTlds = new Set<string>();

	// Add global TLDs
	for (const tld of GLOBAL_TLDS) {
		allTlds.add(tld);
	}

	// Add regional variants based on TLD family
	if (tldLower.endsWith('.nz') || tldLower === '.kiwi') {
		for (const tld of NZ_REGIONAL) allTlds.add(tld);
	} else if (tldLower === '.co.uk' || tldLower === '.org.uk' || tldLower === '.uk') {
		for (const tld of UK_REGIONAL) allTlds.add(tld);
	} else if (tldLower.endsWith('.au')) {
		for (const tld of AU_REGIONAL) allTlds.add(tld);
	} else if (GENERIC_TLDS.has(tldLower)) {
		for (const tld of GENERIC_EXTRA) allTlds.add(tld);
	}

	const variants: string[] = [];
	for (const tld of allTlds) {
		const candidate = `${brand}${tld}`;
		if (candidate.toLowerCase() === primaryLower) continue;

		const validation = validateDomain(candidate);
		if (validation.valid) {
			variants.push(candidate);
		}
	}

	return variants.sort();
}

/**
 * Probe a single variant domain for NS, A, MX, SPF, and DMARC records.
 * All 5 DNS queries run in parallel with skipSecondaryConfirmation.
 */
async function probeVariant(variant: string, dnsOpts: QueryDnsOptions): Promise<VariantProbeResult> {
	const [nsResult, aResult, mxResult, txtResult, dmarcResult] = await Promise.allSettled([
		queryDnsRecords(variant, 'NS', dnsOpts),
		queryDnsRecords(variant, 'A', dnsOpts),
		queryMxRecords(variant, dnsOpts),
		queryTxtRecords(variant, dnsOpts),
		queryTxtRecords(`_dmarc.${variant}`, dnsOpts),
	]);

	const ns = nsResult.status === 'fulfilled' ? nsResult.value : [];
	const hasA = aResult.status === 'fulfilled' && aResult.value.length > 0;
	const mx = mxResult.status === 'fulfilled' ? mxResult.value.map((r) => r.exchange) : [];

	// Check for SPF
	const txtValues = txtResult.status === 'fulfilled' ? txtResult.value : [];
	const hasSpf = txtValues.some((r) => r.toLowerCase().startsWith('v=spf1'));

	// Parse DMARC policy
	let dmarcPolicy: string | null = null;
	const dmarcValues = dmarcResult.status === 'fulfilled' ? dmarcResult.value : [];
	const dmarcRecord = dmarcValues.find((r) => r.toLowerCase().startsWith('v=dmarc1'));
	if (dmarcRecord) {
		const pMatch = dmarcRecord.match(/;\s*p=([^;\s]+)/i);
		dmarcPolicy = pMatch ? pMatch[1].toLowerCase() : 'none';
	}

	return { variant, ns, hasA, mx, hasSpf, dmarcPolicy };
}

/**
 * Check whether the variant MX set is a subset of the primary MX set.
 * Compares sorted exchange hostnames (case-insensitive).
 */
function isSameMxInfra(variantMx: string[], primaryMx: string[]): boolean {
	if (variantMx.length === 0) return false;
	const primarySet = new Set(primaryMx.map((h) => h.toLowerCase().replace(/\.$/, '')));
	return variantMx.every((h) => primarySet.has(h.toLowerCase().replace(/\.$/, '')));
}

/**
 * Classify a probed variant into a finding based on risk.
 */
function classifyVariant(probe: VariantProbeResult, primaryMx: string[]): Finding {
	const { variant, ns, mx, hasSpf, dmarcPolicy } = probe;
	const hasMx = mx.length > 0;
	const hasNs = ns.length > 0;
	const meta = { variant, ns, mx, hasSpf, dmarcPolicy };

	if (hasMx) {
		if (!hasSpf && dmarcPolicy === null) {
			// MX present, no SPF AND no DMARC → critical
			return createFinding(
				'shadow_domains',
				'Shadow domain fully spoofable',
				'critical',
				`${variant} has mail servers but no SPF or DMARC records. Any sender can forge email from this domain.`,
				meta,
			);
		}

		if (hasSpf && dmarcPolicy === null) {
			// MX present, SPF but no DMARC → high
			return createFinding(
				'shadow_domains',
				'Shadow domain lacks DMARC',
				'high',
				`${variant} has mail servers and SPF but no DMARC record. Without DMARC, SPF alone cannot prevent spoofing.`,
				meta,
			);
		}

		if (dmarcPolicy === 'none') {
			// MX present, DMARC p=none → high
			return createFinding(
				'shadow_domains',
				'Shadow domain DMARC not enforcing',
				'high',
				`${variant} has mail servers with DMARC policy set to "none" — spoofed emails are monitored but not blocked.`,
				meta,
			);
		}

		// DMARC is quarantine or reject — check MX infrastructure match
		if (dmarcPolicy === 'quarantine' || dmarcPolicy === 'reject') {
			if (!isSameMxInfra(mx, primaryMx)) {
				// Divergent MX infrastructure → medium
				return createFinding(
					'shadow_domains',
					'Shadow domain divergent mail infrastructure',
					'medium',
					`${variant} uses different mail servers than the primary domain despite having enforcing DMARC. This may indicate separate management.`,
					meta,
				);
			}

			// Same MX infra, properly authenticated → low
			return createFinding(
				'shadow_domains',
				'Shadow domain well-managed',
				'low',
				`${variant} has matching mail infrastructure and enforcing DMARC — properly managed shadow domain.`,
				meta,
			);
		}

		// DMARC present with unknown policy — treat as high-ish (SPF but unclear DMARC)
		if (!isSameMxInfra(mx, primaryMx)) {
			return createFinding(
				'shadow_domains',
				'Shadow domain divergent mail infrastructure',
				'medium',
				`${variant} uses different mail servers than the primary domain.`,
				meta,
			);
		}

		return createFinding(
			'shadow_domains',
			'Shadow domain well-managed',
			'low',
			`${variant} has matching mail infrastructure and DMARC configured.`,
			meta,
		);
	}

	if (hasNs) {
		// Registered but no MX → info
		return createFinding(
			'shadow_domains',
			'Shadow domain registered, no mail',
			'info',
			`${variant} is registered (has NS records) but has no mail infrastructure configured.`,
			meta,
		);
	}

	// Not registered → info
	return createFinding(
		'shadow_domains',
		'Brand variant unregistered',
		'info',
		`${variant} does not appear to be registered. Consider defensive registration to prevent brand abuse.`,
		meta,
	);
}

/**
 * Detect shared NS pairs across registered variants.
 * Returns info findings for groups of 2+ variants sharing the same NS pair.
 */
function detectSharedNs(probes: VariantProbeResult[]): Finding[] {
	const nsMap = new Map<string, string[]>();

	for (const probe of probes) {
		if (probe.ns.length < 2) continue;
		const nsKey = probe.ns
			.map((n) => n.toLowerCase().replace(/\.$/, ''))
			.sort()
			.join(',');
		const existing = nsMap.get(nsKey);
		if (existing) {
			existing.push(probe.variant);
		} else {
			nsMap.set(nsKey, [probe.variant]);
		}
	}

	const findings: Finding[] = [];
	for (const [nsKey, variants] of nsMap) {
		if (variants.length >= 2) {
			findings.push(
				createFinding(
					'shadow_domains',
					'Shared NS across shadow domains',
					'info',
					`${variants.join(', ')} share the same nameserver pair (${nsKey}), suggesting common ownership or registrar.`,
					{ variants, nameservers: nsKey },
				),
			);
		}
	}

	return findings;
}

/** Severity order for sorting findings (critical first). */
const SEVERITY_ORDER: Record<string, number> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};

/**
 * Check shadow domains for a given domain.
 * Discovers alternate-TLD variants and assesses email spoofing risk.
 * Uses cooperative timeout with partial result preservation.
 */
export async function checkShadowDomains(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];
	const startTime = Date.now();
	const deadline = startTime + SHADOW_TIMEOUT_MS;

	const brand = extractBrandName(domain);
	const effectiveTld = getEffectiveTld(domain);

	if (!brand || !effectiveTld) {
		findings.push(
			createFinding(
				'shadow_domains',
				'Unable to extract brand name',
				'info',
				`Could not determine the registrable brand name from \`${domain}\`.`,
			),
		);
		return buildCheckResult('shadow_domains', findings);
	}

	const variants = generateVariants(brand, effectiveTld, domain);

	if (variants.length === 0) {
		findings.push(
			createFinding(
				'shadow_domains',
				'No shadow domain variants generated',
				'info',
				`No alternate-TLD variants could be generated for ${domain}.`,
			),
		);
		return buildCheckResult('shadow_domains', findings);
	}

	// Query primary domain MX for comparison
	const dnsOpts: QueryDnsOptions = { ...dnsOptions, skipSecondaryConfirmation: true };
	let primaryMx: string[] = [];
	try {
		const mxResult = await queryMxRecords(domain, dnsOpts);
		primaryMx = mxResult.map((r) => r.exchange);
	} catch {
		// Primary MX query failure — continue with empty set
	}

	// Adaptive batching
	let batchSize = INITIAL_BATCH_SIZE;
	let delayMs = 0;
	const completedProbes: VariantProbeResult[] = [];
	let variantsChecked = 0;
	let timedOut = false;

	for (let i = 0; i < variants.length; i += batchSize) {
		// Cooperative timeout check between batches
		if (Date.now() >= deadline) {
			timedOut = true;
			break;
		}

		if (delayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, delayMs));
		}

		const batch = variants.slice(i, i + batchSize);
		const batchResults = await Promise.allSettled(batch.map((v) => probeVariant(v, dnsOpts)));

		let failures = 0;
		for (const result of batchResults) {
			if (result.status === 'fulfilled') {
				completedProbes.push(result.value);
			} else {
				failures++;
			}
		}
		variantsChecked += batch.length;

		// Adaptive batch sizing
		if (failures > 0) {
			batchSize = Math.max(MIN_BATCH_SIZE, Math.floor(batchSize / 2));
			delayMs = BACKOFF_DELAY_MS;
		} else if (delayMs > 0) {
			batchSize = Math.min(INITIAL_BATCH_SIZE, batchSize + 1);
			delayMs = 0;
		}
	}

	// Classify each completed probe
	for (const probe of completedProbes) {
		findings.push(classifyVariant(probe, primaryMx));
	}

	// Detect shared NS pairs
	findings.push(...detectSharedNs(completedProbes));

	// Add timeout finding if we didn't finish
	if (timedOut) {
		findings.push(
			createFinding(
				'shadow_domains',
				'Shadow domain check timed out',
				'info',
				`Shadow domain check timed out — ${variantsChecked} of ${variants.length} variants were checked.`,
			),
		);
	}

	// Sort findings by severity (critical first)
	findings.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));

	// If no findings at all (shouldn't happen, but safeguard)
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'shadow_domains',
				'No shadow domain issues detected',
				'info',
				`Checked ${variants.length} alternate-TLD variants of ${domain}. No email spoofing risks detected.`,
			),
		);
	}

	return buildCheckResult('shadow_domains', findings);
}
