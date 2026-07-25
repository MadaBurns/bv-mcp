// SPDX-License-Identifier: BUSL-1.1

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
import {
	resolveRegistration,
	UNKNOWN_REASON_PHRASES,
	type RegistrationCache,
	type RegistrationEvidence,
	type UnknownReason,
} from '../lib/registration-state';
import { getLogger } from '../lib/log';

/** Wall-clock timeout for the entire shadow domain check (ms). */
const SHADOW_TIMEOUT_MS = 20_000;

/** Batch size for adaptive batching. */
const INITIAL_BATCH_SIZE = 4;
const MIN_BATCH_SIZE = 2;
const BACKOFF_DELAY_MS = 500;

export const FAILURE_THRESHOLD = 0;

/** Lean DNS options for Phase 1 existence checks. */
export const PHASE1_DNS_OPTS: QueryDnsOptions = {
	timeoutMs: 2000,
	retries: 0,
	skipSecondaryConfirmation: true,
};

/** Global ccTLD set always appended. */
const GLOBAL_TLDS = [
	'.com',
	'.net',
	'.org',
	'.io',
	'.ai',
	'.co',
	'.de',
	'.fr',
	'.nl',
	'.eu',
	'.co.uk',
	'.com.au',
	'.ca',
	'.jp',
	'.in',
	'.sg',
	'.za',
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
	const rawTld = effectiveTld.toLowerCase();
	// Normalize: getEffectiveTld() returns without leading dot (e.g. 'com', 'co.nz'),
	// but the constant sets use leading dots. Ensure consistent format for comparison.
	const tldLower = rawTld.startsWith('.') ? rawTld : '.' + rawTld;
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
async function probeVariant(variant: string, dnsOpts: QueryDnsOptions, prefetchedNs?: string[]): Promise<VariantProbeResult> {
	const nsPromise: Promise<string[]> = prefetchedNs !== undefined ? Promise.resolve(prefetchedNs) : queryDnsRecords(variant, 'NS', dnsOpts);

	const [nsResult, aResult, mxResult, txtResult, dmarcResult] = await Promise.allSettled([
		nsPromise,
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
 * What Phase 1 learned about a registered variant.
 *
 * `evidence` is carried alongside `ns` deliberately: an empty `ns` means
 * something completely different depending on whether NS was the record type
 * that PROVED registration. Collapsing the two — passing a bare `string[]`
 * downstream — makes "NS measured and empty" indistinguishable from "NS never
 * measured", which is how an incomplete Phase-1 lookup ended up driving a
 * confident Phase-2 severity.
 */
interface RegisteredVariant {
	/** NS records observed in Phase 1. Empty unless `evidence` includes `'ns'`. */
	ns: string[];
	/** Which record types positively demonstrated the name exists. */
	evidence: RegistrationEvidence[];
}

/** Per-variant registration outcome, partitioned three ways. */
interface VariantRegistrationBuckets {
	/** Registered variants → what proved it, and any NS observed while proving it. */
	registered: Map<string, RegisteredVariant>;
	/** Variants proven non-existent by NXDOMAIN. */
	unregistered: string[];
	/** Variants whose registration could not be determined, with the reason. */
	unknown: Array<{ variant: string; reason: UnknownReason }>;
}

/**
 * Phase 1: resolve registration for every variant.
 *
 * Replaces the previous NS-existence filter, which treated an empty NS result
 * as proof of non-registration and so reported SERVFAILing and slow-resolving
 * domains as available for defensive registration.
 */
async function bucketVariantsByRegistration(
	variants: string[],
	dnsOpts: QueryDnsOptions,
	cache?: RegistrationCache,
): Promise<VariantRegistrationBuckets> {
	const registered = new Map<string, RegisteredVariant>();
	const unregistered: string[] = [];
	const unknown: Array<{ variant: string; reason: UnknownReason }> = [];

	const results = await Promise.allSettled(
		variants.map(async (variant) => ({
			variant,
			state: await resolveRegistration(variant, { ...dnsOpts, ...PHASE1_DNS_OPTS }, cache),
		})),
	);

	for (let i = 0; i < results.length; i++) {
		const outcome = results[i];
		if (outcome.status !== 'fulfilled') {
			// resolveRegistration does not reject, but stay defensive: an unexpected
			// throw is a measurement failure, never evidence of non-registration.
			unknown.push({ variant: variants[i], reason: 'network' });
			continue;
		}
		const { variant, state } = outcome.value;
		if (state.state === 'registered') registered.set(variant, { ns: state.ns, evidence: state.evidence });
		else if (state.state === 'unregistered') unregistered.push(variant);
		else unknown.push({ variant, reason: state.reason });
	}

	return { registered, unregistered, unknown };
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
 * Check whether a variant's NS records overlap with the primary domain's NS records.
 * Compares normalized (lowercased, trailing-dot-stripped) nameserver hostnames.
 * Returns true when at least 2 nameservers are shared (typical NS pair).
 */
function sharesNsWithPrimary(variantNs: string[], primaryNs: string[]): boolean {
	if (variantNs.length === 0 || primaryNs.length === 0) return false;
	const primarySet = new Set(primaryNs.map((n) => n.toLowerCase().replace(/\.$/, '')));
	const shared = variantNs.filter((n) => primarySet.has(n.toLowerCase().replace(/\.$/, '')));
	return shared.length >= 2;
}

/**
 * RFC 7505 null MX detection. After `queryMxRecords`'s trailing-dot strip, the canonical
 * null-MX target (`MX 0 .`) appears as an empty exchange; the older `MX 0 localhost.`
 * convention used by some operators for the same intent appears as `'localhost'`. Both
 * are explicit "this domain does not accept mail" declarations and MUST NOT be treated
 * as evidence of a mail-active surface. Misclassifying them as "has mail servers"
 * generates false-positive HIGH/CRITICAL findings on domains that have applied the
 * recommended anti-spoofing posture for non-mail names.
 */
function isNullMxExchange(exchange: string): boolean {
	const lowered = exchange.toLowerCase();
	return lowered === '' || lowered === 'localhost';
}

/**
 * Hard invariant: a domain exhibiting ANY observed record cannot be
 * unregistered. Any code path about to emit an "unregistered" claim must
 * clear this first. Deliberately a total function over the observed record
 * set rather than a heuristic — there is no threshold to tune.
 */
export function canClaimUnregistered(observed: { ns: string[]; mx: string[]; hasSpf: boolean }): boolean {
	return observed.ns.length === 0 && observed.mx.length === 0 && !observed.hasSpf;
}

/**
 * Classify a probed variant into a finding based on risk.
 * When the variant shares nameservers with the primary domain (indicating common ownership),
 * email-auth findings are downgraded one severity level.
 */
function classifyVariant(probe: VariantProbeResult, primaryMx: string[], primaryNs: string[]): Finding {
	const { variant, ns, mx, hasSpf, dmarcPolicy } = probe;
	const hasNullMxOnly = mx.length > 0 && mx.every(isNullMxExchange);
	const hasMx = mx.length > 0 && !hasNullMxOnly;
	const hasNs = ns.length > 0;
	const sameOwner = sharesNsWithPrimary(ns, primaryNs);
	const meta = { variant, ns, mx, hasSpf, dmarcPolicy };
	const ownerNote = ' Likely same owner based on shared nameservers — still recommended to add DMARC.';

	// RFC 7505 explicit non-mail posture — the domain is doing the right thing for a
	// non-mail name. Don't pretend it's spoofable.
	if (hasNullMxOnly) {
		return createFinding(
			'shadow_domains',
			'Shadow domain explicit non-mail (RFC 7505)',
			'info',
			`${variant} declares an RFC 7505 null MX (priority 0 to "." or "localhost"), explicitly refusing mail. This is the recommended anti-spoofing posture for non-mail domains.`,
			meta,
		);
	}

	if (hasMx) {
		if (!hasSpf && dmarcPolicy === null) {
			// MX present, no SPF AND no DMARC → critical (or high if same owner)
			return createFinding(
				'shadow_domains',
				'Shadow domain fully spoofable',
				sameOwner ? 'high' : 'critical',
				`${variant} has mail servers but no SPF or DMARC records. Any sender can forge email from this domain.${sameOwner ? ownerNote : ''}`,
				meta,
			);
		}

		if (hasSpf && dmarcPolicy === null) {
			// MX present, SPF but no DMARC → high (or medium if same owner)
			return createFinding(
				'shadow_domains',
				'Shadow domain lacks DMARC',
				sameOwner ? 'medium' : 'high',
				`${variant} has mail servers and SPF but no DMARC record. Without DMARC, SPF alone cannot prevent spoofing.${sameOwner ? ownerNote : ''}`,
				meta,
			);
		}

		if (dmarcPolicy === 'none') {
			// MX present, DMARC p=none → high (or medium if same owner)
			return createFinding(
				'shadow_domains',
				'Shadow domain DMARC not enforcing',
				sameOwner ? 'medium' : 'high',
				`${variant} has mail servers with DMARC policy set to "none" — spoofed emails are monitored but not blocked.${sameOwner ? ownerNote.replace('add DMARC', 'enforce DMARC') : ''}`,
				meta,
			);
		}

		// DMARC is quarantine or reject — check MX infrastructure match
		if (dmarcPolicy === 'quarantine' || dmarcPolicy === 'reject') {
			if (!isSameMxInfra(mx, primaryMx)) {
				// Divergent MX infrastructure → medium
				const divergentNote = sameOwner ? ` Shared nameservers suggest common ownership despite different mail servers.` : '';
				return createFinding(
					'shadow_domains',
					'Shadow domain divergent mail infrastructure',
					'medium',
					`${variant} uses different mail servers than the primary domain despite having enforcing DMARC. This may indicate separate management.${divergentNote}`,
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
			const divergentNote = sameOwner ? ` Shared nameservers suggest common ownership despite different mail servers.` : '';
			return createFinding(
				'shadow_domains',
				'Shadow domain divergent mail infrastructure',
				'medium',
				`${variant} uses different mail servers than the primary domain.${divergentNote}`,
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

	// Reached only for a variant Phase 1 proved registered whose detail probe
	// observed no records. That is a measurement gap, never an availability
	// claim — the pre-fix code emitted "unregistered" here while carrying the
	// live probe's own metadata, producing findings that asserted a domain did
	// not exist while reporting its SPF record.
	//
	// No `canClaimUnregistered` guard here: this branch makes no unregistered
	// claim, and a parked defensive registration proven via SOA/A that publishes
	// `v=spf1 -all` legitimately fails that predicate. The guard belongs at the
	// sites that actually claim non-existence (see `checkShadowDomains`), not
	// here, where it fired `warn` on every correct result.
	//
	// The detail must describe only what was ACTUALLY observed. `ns` and `mx` are
	// always empty here (both earlier branches return first), but `hasSpf` may be
	// true — a domain registered via an A record can still publish SPF. Asserting
	// "no SPF records were observed" in that case reproduces the same
	// prose-contradicts-metadata defect this task exists to remove.
	return createFinding(
		'shadow_domains',
		'Shadow domain registered, records not observed',
		'info',
		hasSpf
			? `${variant} is registered and publishes an SPF record, but no nameserver or mail records were observed during this scan.`
			: `${variant} is registered but no nameserver, mail or SPF records were observed during this scan.`,
		{ ...meta, registrationState: 'registered', confidence: 'heuristic' },
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

	// Query primary domain MX and NS for comparison
	const dnsOpts: QueryDnsOptions = { ...dnsOptions, skipSecondaryConfirmation: true };
	let primaryMx: string[] = [];
	let primaryNs: string[] = [];
	let primaryDnsUnavailable = false;
	try {
		const [mxResult, nsResult] = await Promise.allSettled([queryMxRecords(domain, dnsOpts), queryDnsRecords(domain, 'NS', dnsOpts)]);
		primaryMx = mxResult.status === 'fulfilled' ? mxResult.value.map((r) => r.exchange) : [];
		primaryNs = nsResult.status === 'fulfilled' ? nsResult.value : [];
		// If both queries rejected, treat as unavailable
		if (mxResult.status === 'rejected' && nsResult.status === 'rejected') {
			primaryDnsUnavailable = true;
		}
	} catch {
		primaryDnsUnavailable = true;
	}

	if (primaryDnsUnavailable) {
		findings.push(
			createFinding(
				'shadow_domains',
				'Primary domain DNS unavailable',
				'info',
				`DNS queries for ${domain} failed — shadow domain analysis may be incomplete.`,
			),
		);
	}

	// Phase 1: partition variants by registration state. The cache is scoped to
	// this single invocation, so there is no cross-request state — it exists to
	// dedup repeat lookups of the same variant within one scan and to guarantee
	// two lookups of one name cannot disagree inside a single report.
	const registrationCache: RegistrationCache = new Map();
	const buckets = await bucketVariantsByRegistration(variants, dnsOpts, registrationCache);
	const registeredVariants = buckets.registered;

	// Only NXDOMAIN supports an "unregistered" claim.
	for (const variant of buckets.unregistered) {
		// Nothing was observed for these variants — they are never detail-probed.
		// The guard below is defence in depth at the point of the claim: it reads
		// the SAME object the finding carries, so any future change that threads
		// real observed records into this site is checked rather than trusted.
		// The other half of this net lives in `resolveRegistrationUncached`, where
		// the `unregistered` arm is reachable only from an NXDOMAIN with no
		// contradicting positive record.
		const observed = { ns: [] as string[], mx: [] as string[], hasSpf: false };
		if (!canClaimUnregistered(observed)) {
			// Fail-safe: downgrade to the inconclusive wording, never throw, never
			// emit a non-existence claim that its own metadata contradicts.
			getLogger().warn('shadow_domains registration invariant violated', {
				category: 'shadow-domains',
				variant,
				hasNs: observed.ns.length > 0,
				hasMx: observed.mx.length > 0,
				hasSpf: observed.hasSpf,
			});
			findings.push(
				createFinding(
					'shadow_domains',
					'Brand variant registration unknown',
					'info',
					`Could not determine whether ${variant} is registered — the lookup reported it as non-existent while records were still observed for it. No conclusion is drawn about this domain.`,
					{ variant, ...observed, dmarcPolicy: null, registrationState: 'unknown', confidence: 'heuristic' },
				),
			);
			continue;
		}
		findings.push(
			createFinding(
				'shadow_domains',
				'Brand variant unregistered',
				'info',
				`${variant} returned NXDOMAIN and does not appear to be registered. Consider defensive registration to prevent brand abuse.`,
				{ variant, ...observed, dmarcPolicy: null, registrationState: 'unregistered', confidence: 'deterministic' },
			),
		);
	}

	// Everything else is a measurement failure, NOT an availability claim.
	for (const { variant, reason } of buckets.unknown) {
		findings.push(
			createFinding(
				'shadow_domains',
				'Brand variant registration unknown',
				'info',
				`Could not determine whether ${variant} is registered — ${UNKNOWN_REASON_PHRASES[reason]}. No conclusion is drawn about this domain.`,
				{ variant, ns: [], mx: [], hasSpf: false, dmarcPolicy: null, registrationState: 'unknown', reason, confidence: 'heuristic' },
			),
		);
	}

	// Phase 2: Detail probe only registered variants with NS passthrough
	const registeredList = [...registeredVariants.entries()];
	let batchSize = INITIAL_BATCH_SIZE;
	let delayMs = 0;
	const completedProbes: VariantProbeResult[] = [];
	const variantsChecked = registeredList.length;
	let timedOut = false;

	for (let i = 0; i < registeredList.length; i += batchSize) {
		if (Date.now() >= deadline) {
			timedOut = true;
			break;
		}

		if (delayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, delayMs));
		}

		const batch = registeredList.slice(i, i + batchSize);
		const batchResults = await Promise.allSettled(
			// Reuse the Phase-1 NS answer ONLY when NS is what proved registration.
			// For soa/a-evidence variants Phase 1 never established an NS answer, so
			// hand `undefined` and let `probeVariant` re-query under full options —
			// at most one extra NS query per variant Phase 2 already probes, with no
			// new fan-out stage.
			batch.map(([variant, reg]) => probeVariant(variant, dnsOpts, reg.evidence.includes('ns') ? reg.ns : undefined)),
		);

		let failures = 0;
		for (const result of batchResults) {
			if (result.status === 'fulfilled') {
				completedProbes.push(result.value);
			} else {
				failures++;
			}
		}

		// Adaptive batch sizing
		if (failures > FAILURE_THRESHOLD) {
			batchSize = Math.max(MIN_BATCH_SIZE, Math.floor(batchSize / 2));
			delayMs = BACKOFF_DELAY_MS;
		} else if (delayMs > 0) {
			batchSize = Math.min(INITIAL_BATCH_SIZE, batchSize + 1);
			delayMs = 0;
		}
	}

	// Classify each completed probe
	for (const probe of completedProbes) {
		findings.push(classifyVariant(probe, primaryMx, primaryNs));
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
