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
import {
	attributionConfidence,
	capAttributionSeverity,
	classifyOwnership,
	MIN_ATTRIBUTION_LABEL_LENGTH,
	type OwnershipAssessment,
} from '../lib/ownership-attribution';
import { isSharedNsHost } from '../tenants/discovery/shared-ns-hosts';

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
 * Compares exchange hostnames case-insensitively, tolerating a trailing root
 * dot on either side.
 *
 * EXPORTED FOR TEST (fix round 1, F3): the trailing-dot normalisation is
 * unobservable through `checkShadowDomains`, because `queryMxRecords` already
 * strips the root dot before either side reaches here — deleting both
 * `.replace(/\.$/, '')` calls leaves every integration test green. The
 * normalisation is still a real part of this predicate's contract for any
 * caller that passes unnormalised hostnames, so it is pinned by a direct unit
 * test instead of by an integration test that cannot see it. Mirrors the
 * existing `canClaimUnregistered` export precedent below.
 */
export function isSameMxInfra(variantMx: string[], primaryMx: string[]): boolean {
	if (variantMx.length === 0) return false;
	const primarySet = new Set(primaryMx.map((h) => h.toLowerCase().replace(/\.$/, '')));
	return variantMx.every((h) => primarySet.has(h.toLowerCase().replace(/\.$/, '')));
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
 * unregistered. Deliberately a total function over the observed record set
 * rather than a heuristic — there is no threshold to tune.
 *
 * Not called on the current claim path: `RegistrationState`'s `unregistered`
 * arm carries no payload, so the invariant is enforced by the type rather than
 * at runtime. Exported and unit-tested so any FUTURE site that threads real
 * observed records alongside a non-existence claim has a ready predicate to
 * clear rather than reinventing one.
 */
export function canClaimUnregistered(observed: { ns: string[]; mx: string[]; hasSpf: boolean }): boolean {
	return observed.ns.length === 0 && observed.mx.length === 0 && !observed.hasSpf;
}

/**
 * Classify a probed variant into a finding based on risk.
 * When the variant is owned by the seed organisation, email-auth findings are
 * downgraded one severity level (it is the customer's own domain to fix, not a
 * hostile shadow).
 *
 * D4 (2026-07-26 correctness-defects design §5) — same-owner detection is
 * driven by `classifyOwnership()`'s structural verdict, replacing the naive
 * `sharesNsWithPrimary()` >=2-shared-hostname set-overlap heuristic. That
 * heuristic was actively dangerous on shared-NS providers (§3.3): two unrelated
 * banks pooled onto Akamai could reach its threshold by luck and have a genuine
 * third party's finding softened, while a customer's own domain delegated
 * in-bailiwick (`ns1.<seed>`) scored zero overlap and was reported to them as a
 * hostile CRITICAL. The severity CEILING is applied separately, by
 * {@link applyOwnershipGate}; this function only computes the unclamped ladder.
 */
function classifyVariant(probe: VariantProbeResult, primaryMx: string[], ownership: OwnershipAssessment): Finding {
	const { variant, ns, mx, hasSpf, dmarcPolicy } = probe;
	const hasNullMxOnly = mx.length > 0 && mx.every(isNullMxExchange);
	const hasMx = mx.length > 0 && !hasNullMxOnly;
	const hasNs = ns.length > 0;
	const sameOwner = ownership.verdict === 'owned_by_seed';
	// The verdict travels on EVERY classified finding, owned or not, so the
	// structured payload carries the same attribution the prose does.
	const meta = {
		variant,
		ns,
		mx,
		hasSpf,
		dmarcPolicy,
		ownershipVerdict: ownership.verdict,
		ownershipRationale: ownership.rationale,
	};
	// States the evidence that actually produced the verdict rather than a fixed
	// "shared nameservers" sentence, which is wrong for the in-bailiwick case.
	const ownerNote = ` Likely same owner (${ownership.rationale}) — still recommended to add DMARC.`;

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
		// LADDER ARMS ARE OWNED-ONLY BY CONSTRUCTION (fix round 1, F2). Each rung
		// below used to read `sameOwner ? X : Y`, where the `Y` (non-owned) arm
		// carried the harsher severity — `'critical'` on the rung immediately
		// below. Those arms are now UNREACHABLE in output: `sameOwner` is exactly
		// `verdict === 'owned_by_seed'`, so `Y` is only ever computed for a finding
		// `applyOwnershipGate()` immediately clamps to `info` and re-words. Leaving
		// a live `'critical'` literal here was a latent trap — any future
		// relaxation of the gate would silently resurrect a critical
		// shadow-domain finding about a third party's mail hygiene. The arms are
		// collapsed to the owned-domain severity so the dead arm cannot be reached
		// by construction; the rung itself is still named by the finding title.
		if (!hasSpf && dmarcPolicy === null) {
			// MX present, no SPF AND no DMARC → the top rung, on the seed's own domain.
			return createFinding(
				'shadow_domains',
				'Shadow domain fully spoofable',
				'high',
				`${variant} has mail servers but no SPF or DMARC records. Any sender can forge email from this domain.${sameOwner ? ownerNote : ''}`,
				meta,
			);
		}

		if (hasSpf && dmarcPolicy === null) {
			// MX present, SPF but no DMARC.
			return createFinding(
				'shadow_domains',
				'Shadow domain lacks DMARC',
				'medium',
				`${variant} has mail servers and SPF but no DMARC record. Without DMARC, SPF alone cannot prevent spoofing.${sameOwner ? ownerNote : ''}`,
				meta,
			);
		}

		if (dmarcPolicy === 'none') {
			// MX present, DMARC p=none.
			return createFinding(
				'shadow_domains',
				'Shadow domain DMARC not enforcing',
				'medium',
				`${variant} has mail servers with DMARC policy set to "none" — spoofed emails are monitored but not blocked.${sameOwner ? ownerNote.replace('add DMARC', 'enforce DMARC') : ''}`,
				meta,
			);
		}

		// DMARC is quarantine or reject — check MX infrastructure match
		if (dmarcPolicy === 'quarantine' || dmarcPolicy === 'reject') {
			if (!isSameMxInfra(mx, primaryMx)) {
				// Divergent MX infrastructure → medium
				const divergentNote = sameOwner
					? ` Nameserver evidence indicates common ownership (${ownership.rationale}) despite the different mail servers.`
					: '';
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
	// `v=spf1 -all` legitimately fails that predicate — the guard fired `warn` on
	// every correct result.
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
 * Neutral replacements for the `info`-severity titles that use ownership
 * framing. "Shadow domain" is a possessive noun phrase: it files the name into
 * the SCANNED organisation's inventory. Applied only to non-owned candidates —
 * an `owned_by_seed` variant genuinely IS a shadow domain of the seed and keeps
 * the original wording.
 */
const NEUTRAL_INFO_TITLES: Record<string, string> = {
	'Shadow domain explicit non-mail (RFC 7505)': 'Confusable domain declares no mail (RFC 7505)',
	'Shadow domain registered, no mail': 'Confusable domain registered, no mail',
};

/**
 * KNOWN RESIDUAL, verified by execution (not by reading): the third
 * ownership-framed `info` title, `'Shadow domain registered, records not
 * observed'` (the Phase-2 fallthrough), is NOT in the map above because
 * `test/audits/registration-invariant.audit.test.ts:163` filters
 * `result.findings` on that exact title literal, and that audit is a slice-3
 * safety net that may not be edited from here. Adding the entry was tried and
 * fails it with `expected 0 to be greater than 0`. The clean fix belongs in a
 * task permitted to touch the audit: re-pin its assertion on
 * `metadata.registrationState === 'registered'` + `confidence === 'heuristic'`
 * instead of the title string, then add the third entry here. Tracked by
 * {@link AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE}, which the D4 title-framing
 * guard carves out explicitly rather than silently.
 */
export const AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE = 'Shadow domain registered, records not observed';

/**
 * D4 severity ceiling. `owned_by_seed` findings pass through untouched —
 * `classifyVariant`'s ladder already applies to a domain the customer controls.
 * Every other verdict is clamped to `info` with wording that never implies the
 * scanned organisation controls the domain or owes it any action.
 *
 * DEMOTE, NEVER DELETE (binding ruling): this returns a `Finding`, never
 * `null`/`undefined`. A real measurement is never suppressed — an unrelated
 * organisation's domain is still reported, just neutrally and at `info`.
 * `attributionConfidence()` is consulted for WORDING ONLY; it can never move
 * the ceiling, which `capAttributionSeverity()` derives from the verdict alone.
 *
 * WORDING, not just severity. "Shadow domain X" files a name into the
 * CUSTOMER's inventory; on a domain that is demonstrably not theirs, that is
 * the same false attribution the severity cap exists to prevent, just spelled
 * in the title. So:
 *   - above `info`: the risk-ladder title AND detail are replaced outright —
 *     they assert a spoofing posture the customer supposedly owns and owes
 *     action on;
 *   - at `info`: the detail is a bare observation and is kept (plus the
 *     attribution sentence), but the TITLE is still remapped through
 *     {@link NEUTRAL_INFO_TITLES} when it uses ownership framing. An earlier
 *     revision claimed info-level titles "are already bare registration
 *     observations"; that was false — two of the three begin with the
 *     ownership noun.
 */
function applyOwnershipGate(finding: Finding, ownership: OwnershipAssessment, brand: string, corroborated: boolean): Finding {
	const ceiling = capAttributionSeverity(ownership.verdict);
	if (ceiling === 'unbounded') return finding;

	const confidence = attributionConfidence(ownership.verdict, brand, corroborated);
	const variant = typeof finding.metadata?.variant === 'string' ? finding.metadata.variant : 'This domain';
	const metadata = {
		...finding.metadata,
		ownershipVerdict: ownership.verdict,
		ownershipRationale: ownership.rationale,
		attributionConfidence: confidence,
		severityCappedBy: 'ownership_attribution',
	};

	if (finding.severity === 'info') {
		return createFinding(
			'shadow_domains',
			NEUTRAL_INFO_TITLES[finding.title] ?? finding.title,
			ceiling,
			`${finding.detail} ${ownership.rationale}`,
			metadata,
		);
	}

	const relation =
		ownership.verdict === 'third_party'
			? 'is registered to a different organisation'
			: 'could not be attributed to the scanned organisation';
	const hedge =
		confidence === 'uncorroborated'
			? ` The shared label is under ${MIN_ATTRIBUTION_LABEL_LENGTH} characters and nothing else corroborates a link, so the name similarity alone means little.`
			: '';
	return createFinding(
		'shadow_domains',
		`Unrelated domain, confusable label: ${variant}`,
		ceiling,
		`${variant} shares the "${brand}" label with the scanned domain but ${relation}. ${ownership.rationale} Its mail posture is reported for awareness only: no action by the scanned organisation is implied, and this finding asserts no control over ${variant}.${hedge}`,
		metadata,
	);
}

/**
 * Assess ownership for one probed variant and emit its GATED finding.
 *
 * The single chokepoint through which every `classifyVariant` result reaches
 * `findings` — used by BOTH emission sites (the unknown-bucket re-probe and the
 * Phase-2 completed-probe loop). Wiring the gate at only one of them left the
 * other emitting ungated `critical`/`high` findings with no ownership verdict
 * at all, so the decision is centralised here rather than duplicated per site.
 *
 * `classifyOwnership()` is pure and does no DNS I/O: it is fed from what the
 * probe already resolved.
 */
function classifyAndGate(probe: VariantProbeResult, seedDomain: string, seedNs: string[], primaryMx: string[], brand: string): Finding {
	// Evidence is recorded for honesty only — `classifyOwnership()` reads
	// `state` and `ns`. A probe proven registered by MX/SPF alone legitimately
	// contributes no NS/SOA/A evidence.
	const evidence: RegistrationEvidence[] = [];
	if (probe.ns.length > 0) evidence.push('ns');
	if (probe.hasA) evidence.push('a');

	const ownership = classifyOwnership({
		seedDomain,
		seedNs,
		candidateDomain: probe.variant,
		registration: { state: 'registered', ns: probe.ns, evidence },
		isSharedNsHost,
	});

	// Shared mail infrastructure with the primary is the one corroborating
	// signal available here (neither cert SANs nor page content are fetched).
	return applyOwnershipGate(classifyVariant(probe, primaryMx, ownership), ownership, brand, isSameMxInfra(probe.mx, primaryMx));
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
		// Nothing was observed for these variants — they are never detail-probed,
		// so `observed` is a constant empty record set.
		//
		// The invariant "an unregistered claim may not carry observed records" is
		// enforced STRUCTURALLY by the `RegistrationState` type, not by a runtime
		// check here: its `unregistered` arm carries no payload, so there is no
		// conflicting evidence for a guard to cross-check. A
		// `canClaimUnregistered(observed)` call at this site read the hardcoded
		// literal below and was therefore unconditionally true — an unreachable,
		// untestable branch. The other half of the net lives in
		// `resolveRegistrationUncached`, where the `unregistered` arm is reachable
		// only from an NXDOMAIN with no contradicting positive record and no
		// failure rcode anywhere in the response set.
		const observed = { ns: [] as string[], mx: [] as string[], hasSpf: false };
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

	// Everything else is a measurement failure, NOT an availability claim — but
	// "the NS/SOA/A probe could not settle it" is not the same as "nothing is
	// there". `resolveRegistration` deliberately looks only at NS, SOA and A,
	// which leaves a real blind spot: a MAIL-ONLY registration (MX + SPF, no web
	// A record, NS missed under the tight Phase-1 window) resolves to
	// `empty_noerror` and would be reported as unknown while carrying a hardcoded
	// `hasSpf: false` — suppressing a measurement we can actually make, and
	// asserting a measured-looking negative about a domain that publishes SPF.
	//
	// So each unknown variant is re-probed ONCE at the full timeout. Positive
	// records prove the name exists, so it is classified from its real records;
	// only a variant that still shows nothing keeps the unknown verdict, and even
	// then the finding carries the probe's ACTUAL observations rather than
	// hardcoded falses.
	//
	// This never widens the `unregistered` claim: variants only move from
	// `unknown` to `registered`. NXDOMAIN remains the sole path to "unregistered".
	//
	// The re-probe is BATCHED and DEADLINE-CHECKED exactly like Phase 2 below.
	// Unbatched it would fan out `unknown.length × 5` DoH queries at once (~26
	// variants → ~130 concurrent full-timeout queries); if those burn
	// SHADOW_TIMEOUT_MS, Phase 2 breaks on its first iteration and the REAL
	// criticals from the registered variants are never emitted — trading a
	// cosmetic metadata fix for the loss of the check's actual output. Sharing
	// the same `deadline` keeps this stage from starving the one that matters.
	if (buckets.unknown.length > 0) {
		/** Emit the honest unknown verdict, carrying whatever the probe actually observed. */
		const pushUnknownFinding = (variant: string, reason: UnknownReason, probe?: VariantProbeResult) => {
			findings.push(
				createFinding(
					'shadow_domains',
					'Brand variant registration unknown',
					'info',
					`Could not determine whether ${variant} is registered — ${UNKNOWN_REASON_PHRASES[reason]}. No conclusion is drawn about this domain.`,
					{
						variant,
						ns: probe?.ns ?? [],
						mx: probe?.mx ?? [],
						hasSpf: probe?.hasSpf ?? false,
						dmarcPolicy: probe?.dmarcPolicy ?? null,
						registrationState: 'unknown',
						reason,
						confidence: 'heuristic',
					},
				),
			);
		};

		// STAGE SUB-DEADLINE — this stage may consume at most half the check's budget.
		//
		// Sharing Phase 2's `deadline` bounded the overrun but reserved nothing for
		// Phase 2 itself, and batching (correctly) serialized what used to be one
		// burst, so the wall clock this stage can burn grew. A flaky ccTLD family
		// with ~26 unknowns at ~7s per batch of 4 needs ~7 batches — it would eat
		// the whole 20s, and Phase 2 would then break on its FIRST iteration with
		// `timedOut`, emitting ZERO detail findings. That silently discards the
		// registered variants' fully-spoofable / lacks-DMARC criticals, which are
		// the check's most valuable output — a strictly worse trade than the
		// metadata honesty this stage buys.
		//
		// Derived from the same `startTime` reference `deadline` uses (see the top of
		// this function), so the two can never drift apart. Phase 2 keeps checking
		// the FULL `deadline` and is therefore guaranteed at least half the budget.
		const reprobeDeadline = Math.min(deadline, startTime + SHADOW_TIMEOUT_MS / 2);

		let unknownBatchSize = INITIAL_BATCH_SIZE;
		let unknownDelayMs = 0;
		let unknownCursor = 0;
		while (unknownCursor < buckets.unknown.length) {
			// Capture the batch size BEFORE the adaptive resize at the end of the body
			// can mutate it. A `for (…; i += unknownBatchSize)` advance evaluates the
			// size AFTER that resize: on SHRINK the cursor advances less than the slice
			// consumed, so variants are re-probed and emit DOUBLE findings; on GROW it
			// advances further than the slice consumed, silently SKIPPING a variant —
			// the exact drop the deadline branch below exists to prevent. Latent only
			// while `probeVariant` cannot reject; live the moment it gains a throwing
			// path. Do not fold this back into a for-loop increment.
			const size = unknownBatchSize;

			// Stage budget exhausted: every remaining variant KEEPS its unknown finding
			// (never silently dropped) — it just keeps it un-re-probed, which is the
			// honest pre-re-probe state rather than a fabricated verdict.
			if (Date.now() >= reprobeDeadline) {
				for (const { variant, reason } of buckets.unknown.slice(unknownCursor)) pushUnknownFinding(variant, reason);
				break;
			}

			if (unknownDelayMs > 0) {
				await new Promise((resolve) => setTimeout(resolve, unknownDelayMs));
			}

			const batch = buckets.unknown.slice(unknownCursor, unknownCursor + size);
			const batchResults = await Promise.allSettled(batch.map(({ variant }) => probeVariant(variant, dnsOpts)));

			let failures = 0;
			for (let j = 0; j < batch.length; j++) {
				const { variant, reason } = batch[j];
				const settled = batchResults[j];
				if (settled.status !== 'fulfilled') {
					failures++;
					pushUnknownFinding(variant, reason);
					continue;
				}
				const probe = settled.value;
				// Positive records prove the name exists → classify from its real
				// records. Nothing observed → the unknown verdict stands, carrying the
				// probe's ACTUAL (empty) observations rather than hardcoded literals.
				//
				// There is deliberately NO `unregistered` branch here: this path can
				// only ever move a variant `unknown → registered`. NXDOMAIN, resolved
				// in Phase 1 by `resolveRegistration`, remains the sole path to an
				// "unregistered" claim.
				const hasEvidence = probe.ns.length > 0 || probe.hasA || probe.mx.length > 0 || probe.hasSpf || probe.dmarcPolicy !== null;
				//
				// CALL SITE 1 of 2 for `classifyAndGate` — this path is as capable of
				// emitting a `critical` as Phase 2 is, so it is gated identically.
				if (hasEvidence) findings.push(classifyAndGate(probe, domain, primaryNs, primaryMx, brand));
				else pushUnknownFinding(variant, reason, probe);
			}

			// Same adaptive sizing as Phase 2. This is the mutation `size` guards against.
			if (failures > FAILURE_THRESHOLD) {
				unknownBatchSize = Math.max(MIN_BATCH_SIZE, Math.floor(unknownBatchSize / 2));
				unknownDelayMs = BACKOFF_DELAY_MS;
			} else if (unknownDelayMs > 0) {
				unknownBatchSize = Math.min(INITIAL_BATCH_SIZE, unknownBatchSize + 1);
				unknownDelayMs = 0;
			}

			// Advance by what was actually consumed, never by the resized value.
			unknownCursor += size;
		}
	}

	// Phase 2: Detail probe only registered variants with NS passthrough
	const registeredList = [...registeredVariants.entries()];
	let batchSize = INITIAL_BATCH_SIZE;
	let delayMs = 0;
	const completedProbes: VariantProbeResult[] = [];
	const variantsChecked = registeredList.length;
	let timedOut = false;

	let cursor = 0;
	while (cursor < registeredList.length) {
		// Same cursor-capture trap as the unknown re-probe loop above: the adaptive
		// resize at the end of this body mutates `batchSize`, and a
		// `for (…; i += batchSize)` advance would read the RESIZED value — shrinking
		// re-probes variants (duplicate detail findings), growing skips one entirely.
		// Capture what this iteration actually consumes and advance by that.
		const size = batchSize;

		if (Date.now() >= deadline) {
			timedOut = true;
			break;
		}

		if (delayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, delayMs));
		}

		const batch = registeredList.slice(cursor, cursor + size);
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

		// Adaptive batch sizing. This is the mutation `size` guards against.
		if (failures > FAILURE_THRESHOLD) {
			batchSize = Math.max(MIN_BATCH_SIZE, Math.floor(batchSize / 2));
			delayMs = BACKOFF_DELAY_MS;
		} else if (delayMs > 0) {
			batchSize = Math.min(INITIAL_BATCH_SIZE, batchSize + 1);
			delayMs = 0;
		}

		// Advance by what was actually consumed, never by the resized value.
		cursor += size;
	}

	// Classify each completed probe.
	// CALL SITE 2 of 2 for `classifyAndGate`.
	for (const probe of completedProbes) {
		findings.push(classifyAndGate(probe, domain, primaryNs, primaryMx, brand));
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
