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
 *   - Different tenants on same SaaS provider → no signal
 */

import { validateDomain } from '../../lib/sanitize';
import { mapConcurrent } from '../../lib/map-concurrent';
import { safeFetch } from '../../lib/safe-fetch';
import type { DiscoveryDnsContext } from './dns-context';

const DEFAULT_DOH_URL = 'https://cloudflare-dns.com/dns-query';
const DEFAULT_TIMEOUT_MS = 5_000;

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
		evidence: { matched: string[]; sharedSaas: boolean };
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
		});
		clearTimeout(timeoutId);
		if (!resp.ok) return [];
		const json = (await resp.json()) as DohResponse;
		if (json.Status !== 0 || !json.Answer) return [];
		// MX rdata is "<priority> <hostname>"; extract just the host.
		return json.Answer
			.map((a) => a.data.split(/\s+/).pop() ?? '')
			.map((h) => h.toLowerCase().replace(/\.$/, ''))
			.filter((h) => h.length > 0)
			.sort();
	} catch {
		clearTimeout(timeoutId);
		return [];
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

/** Tenant-string extractor for shared SaaS — e.g. `acme-com` from `acme-com.mail.protection.outlook.com`. */
function tenantPrefix(host: string, saasSuffix: string): string {
	if (!host.endsWith('.' + saasSuffix)) return host;
	return host.slice(0, host.length - saasSuffix.length - 1);
}

export async function detectMxOverlap(seedDomain: string, options: MxOverlapOptions): Promise<MxOverlapResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const dohFn = options.dohFn ?? safeFetch;
	const dohUrl = options.dohUrl ?? DEFAULT_DOH_URL;
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
			const matched = candMx.filter((h) => seedMx.includes(h));
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
				// All matches are shared-SaaS — check if same tenant.
				const sameTenant = matched.every((h) => {
					const suffix = sharedSaasSuffix(h);
					if (!suffix) return false;
					const candTenant = tenantPrefix(h, suffix);
					const seedHost = seedMx.find((s) => sharedSaasSuffix(s) === suffix);
					if (!seedHost) return false;
					const seedTenant = tenantPrefix(seedHost, suffix);
					return candTenant === seedTenant;
				});
				if (!sameTenant) return { status: 'fulfilled', value: null };
				return {
					status: 'fulfilled',
					value: { domain: candLower, confidence: 0.5, evidence: { matched, sharedSaas: true } },
				};
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
