// SPDX-License-Identifier: BUSL-1.1

/**
 * MX-overlap ownership detector.
 *
 * Compares each caller-asserted candidate's MX RRset against the seed's MX
 * RRset. Confidence depends on the kind of overlap:
 *   - Both endpoints under seed apex (e.g. `mx.brand-zeta.example.com`) → 0.95
 *   - Exact hostname overlap on non-shared SaaS → 0.7
 *   - Partial overlap (subset) → 0.5
 *   - Shared multi-tenant SaaS with same tenant string → 0.5
 *   - Shared SaaS where a provider extractor isolates the SAME per-customer
 *     tenant id (Proofpoint `mxa-<id>.gslb.pphosted.com`, Forcepoint
 *     `cust<N>-1.in.mailcontrol.com`) → 0.65, labelled `evidence.sharedTenant`.
 *     A bare shared-platform match never gets it.
 *   - Different tenants on same SaaS provider → no signal
 */

import { validateDomain } from '../../lib/sanitize';
import { mapConcurrent } from '../../lib/map-concurrent';
import { safeFetch } from '../../lib/safe-fetch';
import type { DiscoveryDnsContext } from './dns-context';
import { CLOUDFLARE_DOH_ENDPOINT } from '../../lib/dns-endpoints';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../../lib/response-body';

const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_DOH_BODY_BYTES = 256 * 1024;

/** Multi-tenant mail SaaS providers — overlap on these is provider-level, not ownership. */
const SHARED_MAIL_SAAS = [
	'mail.protection.outlook.com',
	'googlemail.com',
	'aspmx.l.google.com',
	'pphosted.com',
	'mimecast.com',
	'mailcontrol.com',
	'sendgrid.net',
	'mxa.mailgun.org',
	'mxb.mailgun.org',
	'inbound.mail.mailgun.org',
];

export interface MxOverlapOptions {
	candidateDomains: string[];
	dohFn?: typeof fetch;
	dohUrl?: string;
	timeoutMs?: number;
	dnsContext?: DiscoveryDnsContext;
}

export interface MxOverlapResult {
	coOwnedDomains: Array<{
		domain: string;
		confidence: number;
		/** `sharedTenant` (`<suffix>:<id>`) is set only when an isolated per-customer id matched. */
		evidence: { matched: string[]; sharedSaas: boolean; sharedTenant?: string };
	}>;
	queryStatus: 'ok' | 'error';
}

type MxOverlapCandidate = MxOverlapResult['coOwnedDomains'][number];

interface DohResponse {
	Status: number;
	Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

/** Query MX records via DoH. Returns the host list (lowercased, sorted) or [] on failure. */
async function queryMx(name: string, dohFn: typeof fetch, dohUrl: string, timeoutMs: number): Promise<string[]> {
	const url = `${dohUrl}?name=${encodeURIComponent(name)}&type=MX`;
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const resp = await dohFn(url, {
			headers: { Accept: 'application/dns-json' },
			signal: controller.signal,
			redirect: 'manual',
		});
		if (!resp.ok) {
			await disposeUnreadResponseBody(resp);
			return [];
		}
		const json = await readJsonResponseCapped<DohResponse>(resp, MAX_DOH_BODY_BYTES);
		if (!json) return [];
		if (json.Status !== 0 || !json.Answer) return [];
		// MX rdata is "<priority> <hostname>"; extract just the host.
		return json.Answer
			.map((a) => a.data.split(/\s+/).pop() ?? '')
			.map((h) => h.toLowerCase().replace(/\.$/, ''))
			.filter((h) => h.length > 0)
			.sort();
	} catch {
		return [];
	} finally {
		clearTimeout(timeoutId);
	}
}

async function queryMxWithContext(name: string, dnsContext: DiscoveryDnsContext): Promise<string[]> {
	try {
		const json = await dnsContext.query(name, 'MX');
		if (json.Status !== 0 || !json.Answer) return [];
		return json.Answer
			.map((a) => a.data.split(/\s+/).pop() ?? '')
			.map((h) => h.toLowerCase().replace(/\.$/, ''))
			.filter((h) => h.length > 0)
			.sort();
	} catch {
		return [];
	}
}

/** Returns the SHARED_MAIL_SAAS suffix if `host` matches one, else null. */
function sharedSaasSuffix(host: string): string | null {
	const lower = host.toLowerCase();
	for (const suffix of SHARED_MAIL_SAAS) {
		if (lower === suffix || lower.endsWith('.' + suffix)) return suffix;
	}
	return null;
}

/** True if the host is under the seed apex. */
function isUnderSeed(host: string, seed: string): boolean {
	const h = host.toLowerCase().replace(/\.$/, '');
	const s = seed.toLowerCase().replace(/\.$/, '');
	return h === s || h.endsWith('.' + s);
}

/**
 * Proofpoint per-customer MX hosts. Two verified families carry the same
 * 8-hex customer id behind a rotating label: `mx0a|mx0b-<id>.pphosted.com` and
 * `mxa|mxb-<id>.gslb.pphosted.com`. The id is the only per-customer part.
 * Checked live (17 Proofpoint customers: att, proofpoint, pfizer, blackrock,
 * ibm, sainsburys, linklaters, allenovery, kpmg.co.uk, hsbc.co.uk,
 * barclays.co.uk, tesco, rolls-royce, gsk, astrazeneca, qantas.com.au, 3ds):
 * all use only these two families; no pod-style pphosted host was observed.
 */
const PPHOSTED_TENANT = /^mx0?[a-z]?-([0-9a-f]{8})(?:\.gslb)?\.pphosted\.com$/;

/**
 * Forcepoint (MailControl) per-customer MX hosts: `cust<N>-<rotation>.in.mailcontrol.com`.
 * `<N>` is the customer account number; the trailing `-<rotation>` is the
 * rotating label. Source: Forcepoint Email Security cloud docs
 * (`cust0000-1/-2.in.mailcontrol.com`); live forcepoint.com MX is
 * `cust78413-1` + `cust78413-2`. Cluster hosts (e.g. `cluster-a.mailcontrol.com`) do not match.
 */
const MAILCONTROL_TENANT = /^cust(\d+)-\d+\.in\.mailcontrol\.com$/;

/** Isolated per-customer-id extractors, keyed by SHARED_MAIL_SAAS suffix. */
const ISOLATED_TENANT_EXTRACTORS: Record<string, RegExp> = {
	'pphosted.com': PPHOSTED_TENANT,
	'mailcontrol.com': MAILCONTROL_TENANT,
};

/**
 * `isolated` is true only when a provider-specific extractor pulled a
 * per-customer id out of the host. A bare shared-platform host never is.
 */
interface SaasTenant {
	id: string;
	isolated: boolean;
}

/**
 * Per-provider tenant extractor keyed by SaaS suffix. Providers without an
 * isolated extractor fall back to host-minus-suffix and are never `isolated`:
 * outlook's `<tenant>.mail.protection.outlook.com` prefix is already the
 * tenant (kept at provider-level weight by design), and mimecast
 * (eu-smtp-inbound-1/2, service-alpha-inbound-a/b), google, sendgrid and
 * mailgun MX are shared regional pools with no per-customer id.
 */
function saasTenant(host: string, saasSuffix: string): SaasTenant {
	const id = ISOLATED_TENANT_EXTRACTORS[saasSuffix]?.exec(host)?.[1];
	if (id) return { id, isolated: true };
	const prefix = host.endsWith('.' + saasSuffix) ? host.slice(0, host.length - saasSuffix.length - 1) : host;
	return { id: prefix, isolated: false };
}

/** True when both hosts sit on the same shared-SaaS provider and normalize to the same tenant. */
function sameSaasTenant(a: string, b: string): boolean {
	const suffix = sharedSaasSuffix(a);
	if (!suffix || suffix !== sharedSaasSuffix(b)) return false;
	const ta = saasTenant(a, suffix);
	const tb = saasTenant(b, suffix);
	return ta.isolated === tb.isolated && ta.id === tb.id;
}

/** Confidence for a per-customer tenant id shared across both domains — ownership-bearing, unlike a shared platform. */
const ISOLATED_TENANT_CONFIDENCE = 0.65;
/** Confidence for a shared platform with no isolated per-customer id (provider-level). */
const SHARED_PLATFORM_CONFIDENCE = 0.5;

/**
 * Scores an all-shared-SaaS match. Every `matched` host already shares a
 * normalized tenant with a seed host (the caller filters on it), so tenants
 * that differ never reach here.
 */
function classifySharedSaas(matched: string[]): Pick<MxOverlapCandidate, 'confidence' | 'evidence'> {
	for (const h of matched) {
		const suffix = sharedSaasSuffix(h);
		const tenant = suffix ? saasTenant(h, suffix) : null;
		if (suffix && tenant?.isolated) {
			return {
				confidence: ISOLATED_TENANT_CONFIDENCE,
				evidence: { matched, sharedSaas: true, sharedTenant: `${suffix}:${tenant.id}` },
			};
		}
	}
	return { confidence: SHARED_PLATFORM_CONFIDENCE, evidence: { matched, sharedSaas: true } };
}

export async function detectMxOverlap(seedDomain: string, options: MxOverlapOptions): Promise<MxOverlapResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const dohFn = options.dohFn ?? safeFetch;
	const dohUrl = options.dohUrl ?? CLOUDFLARE_DOH_ENDPOINT;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const dnsContext = options.dnsContext;
	const queryMxRecords = dnsContext
		? (name: string) => queryMxWithContext(name, dnsContext)
		: (name: string) => queryMx(name, dohFn, dohUrl, timeoutMs);

	if (options.candidateDomains.length === 0) {
		return { coOwnedDomains: [], queryStatus: 'ok' };
	}

	const seedMx = await queryMxRecords(seedLower);
	if (seedMx.length === 0) {
		return { coOwnedDomains: [], queryStatus: 'ok' };
	}

	const settled = await mapConcurrent(options.candidateDomains, 6, async (cand): Promise<PromiseSettledResult<MxOverlapCandidate | null>> => {
		try {
			const candLower = cand.trim().toLowerCase().replace(/\.$/, '');
			if (!validateDomain(candLower).valid) return { status: 'fulfilled', value: null };
			const candMx = await queryMxRecords(candLower);
			if (candMx.length === 0) return { status: 'fulfilled', value: null };

			// Determine overlap class.
			// Exact host overlap, or the same normalized shared-SaaS tenant on a
			// different rotation label (e.g. Proofpoint mxa- vs mxb-/mx0a-).
			const matched = candMx.filter((h) => seedMx.some((s) => s === h || sameSaasTenant(h, s)));
			if (matched.length === 0) return { status: 'fulfilled', value: null };

			// Strong bump only when the CANDIDATE is fully aligned with seed
			// (every candidate MX matches a seed MX, and all matched hosts are
			// under the seed apex). Partial alignment on seed-rooted hosts is
			// suggestive but not deterministic.
			const allUnderSeed = matched.every((h) => isUnderSeed(h, seedLower));
			const candFullyAligned = matched.length === candMx.length;
			if (allUnderSeed && candFullyAligned) {
				return {
					status: 'fulfilled',
					value: { domain: candLower, confidence: 0.9, evidence: { matched, sharedSaas: false } },
				};
			}
			if (allUnderSeed) {
				// Partial overlap on seed-rooted MX — still indicative.
				return {
					status: 'fulfilled',
					value: { domain: candLower, confidence: 0.7, evidence: { matched, sharedSaas: false } },
				};
			}

			// Check SaaS-shared classification.
			const sharedSaasHosts = matched.filter((h) => sharedSaasSuffix(h) !== null);
			if (sharedSaasHosts.length === matched.length && matched.length > 0) {
				// All matches are shared-SaaS — compare on the normalized tenant.
				return { status: 'fulfilled', value: { domain: candLower, ...classifySharedSaas(matched) } };
			}

			// Partial overlap on non-SaaS hosts.
			const overlapRatio = matched.length / Math.max(candMx.length, seedMx.length);
			const confidence = overlapRatio >= 0.5 ? 0.7 : 0.5;
			return {
				status: 'fulfilled',
				value: { domain: candLower, confidence, evidence: { matched, sharedSaas: false } },
			};
		} catch (reason) {
			return { status: 'rejected', reason };
		}
	});

	const coOwnedDomains = settled
		.filter((r): r is PromiseFulfilledResult<MxOverlapCandidate> => r.status === 'fulfilled' && r.value !== null)
		.map((r) => r.value);

	return { coOwnedDomains, queryStatus: 'ok' };
}
