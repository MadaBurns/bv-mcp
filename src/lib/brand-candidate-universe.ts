// SPDX-License-Identifier: BUSL-1.1

export type BrandAuditDepth = 'standard' | 'deep';
export type CandidateSeedSource =
	| 'caller_candidate'
	| 'tld_sweep'
	| 'alias_tld_sweep'
	| 'enterprise_affix'
	| 'markov'
	| 'active_lookalike';

export interface CandidateSeed {
	domain: string;
	sources: CandidateSeedSource[];
	reasons: string[];
}

export interface BrandCandidateUniverse {
	candidates: CandidateSeed[];
	stats: {
		seeded: number;
		sources: Record<CandidateSeedSource, number>;
		dropped: {
			cap: number;
		};
	};
}

const STANDARD_TLDS = [
	'com',
	'net',
	'org',
	'co',
	'io',
	'de',
	'fr',
	'es',
	'it',
	'nl',
	'se',
	'co.uk',
	'uk',
	'ie',
	'co.jp',
	'jp',
	'cn',
	'sg',
	'com.au',
	'au',
	'nz',
	'ca',
	'mx',
	'br',
	'in',
	'ae',
	'za',
];

const DEEP_ONLY_TLDS = [
	'app',
	'art',
	'biz',
	'care',
	'dev',
	'cloud',
	'email',
	'global',
	'group',
	'health',
	'help',
	'id',
	'jobs',
	'life',
	'live',
	'media',
	'news',
	'online',
	'pro',
	'services',
	'site',
	'software',
	'solutions',
	'store',
	'shop',
	'support',
	'systems',
	'tech',
	'technology',
	'tools',
	'us',
	'eu',
	'fi',
	'ch',
	'at',
	'be',
	'pl',
	'no',
	'dk',
	'cz',
	'pt',
	'gr',
	'ro',
	'hu',
	'lu',
	'kr',
	'tw',
	'hk',
	'my',
	'ph',
	'id',
	'th',
	'vn',
	'ar',
	'cl',
	'pe',
	'uy',
	'co',
	'tr',
	'sa',
	'il',
	'qa',
	'kw',
	'eg',
];

const ENTERPRISE_AFFIXES = [
	'secure',
	'security',
	'id',
	'cloud',
	'pay',
	'shop',
	'support',
	'login',
	'portal',
	'auth',
	'corp',
	'global',
];

const ENTERPRISE_AFFIX_TLDS = ['com', 'net', 'org', 'co', 'io', 'app', 'cloud', 'dev', 'support', 'shop'];
// Hard caps reduced from 120/250 (2026-05-19) after walmart audits wedged at
// the Cloudflare Worker CPU budget. Each candidate is probed by ~12 signal
// detectors at concurrency 6 through a shared DoH semaphore — 100 candidates
// × 12 signals = up to 1200 DoH queries plus per-candidate RDAP fan-out.
// Tier-1 brands (walmart, disney) routinely exceed CPU budget at the prior
// caps. Universe candidates beyond the cap are dropped with stats.dropped.cap
// so downstream telemetry surfaces the truncation.
const STANDARD_CANDIDATE_CAP = 50;
const DEEP_CANDIDATE_CAP = 150;

function normalizeDomain(domain: string): string | null {
	const lower = domain.trim().toLowerCase().replace(/\.+$/, '');
	if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(lower)) return null;
	return lower;
}

function seedLabel(seedDomain: string): string | null {
	const normalized = normalizeDomain(seedDomain);
	if (!normalized) return null;
	return normalized.split('.')[0] ?? null;
}

function normalizeAlias(alias: string): string | null {
	const lower = alias.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
	return lower.length >= 2 ? lower : null;
}

export function buildBrandCandidateUniverse(input: {
	seedDomain: string;
	brandAliases?: string[];
	candidateDomains?: string[];
	markovCandidates?: string[];
	activeLookalikes?: string[];
	depth?: BrandAuditDepth;
}): BrandCandidateUniverse {
	const seed = normalizeDomain(input.seedDomain);
	const base = seedLabel(input.seedDomain);
	const depth = input.depth ?? 'standard';
	const tlds = depth === 'deep' ? [...STANDARD_TLDS, ...DEEP_ONLY_TLDS] : STANDARD_TLDS;
	const cap = depth === 'deep' ? DEEP_CANDIDATE_CAP : STANDARD_CANDIDATE_CAP;
	const byDomain = new Map<string, CandidateSeed>();
	const dropped = { cap: 0 };

	function add(domain: string, source: CandidateSeedSource, reason: string): void {
		const normalized = normalizeDomain(domain);
		if (!normalized || normalized === seed) return;
		const existing = byDomain.get(normalized);
		if (existing) {
			if (!existing.sources.includes(source)) existing.sources.push(source);
			existing.reasons.push(reason);
			return;
		}
		if (byDomain.size >= cap) {
			dropped.cap++;
			return;
		}
		byDomain.set(normalized, { domain: normalized, sources: [source], reasons: [reason] });
	}

	// Source priority order (highest signal first) — matters when the cap
	// truncates: caller_candidate and active_lookalike carry direct human or
	// DNS-active evidence; tld_sweep / alias_tld_sweep target the brand name
	// directly; enterprise_affix generates noisy `<brand>+<affix>` permutations
	// that swamp lower-priority sources; markov is purely speculative.
	for (const domain of input.candidateDomains ?? []) add(domain, 'caller_candidate', 'caller supplied candidate');
	for (const domain of input.activeLookalikes ?? []) add(domain, 'active_lookalike', 'active lookalike candidate');

	if (base) {
		for (const tld of tlds) add(`${base}.${tld}`, 'tld_sweep', `seed label across .${tld}`);
	}

	for (const rawAlias of input.brandAliases ?? []) {
		const alias = normalizeAlias(rawAlias);
		if (!alias) continue;
		for (const tld of tlds) add(`${alias}.${tld}`, 'alias_tld_sweep', `brand alias across .${tld}`);
	}

	if (depth === 'deep' && base) {
		for (const affix of ENTERPRISE_AFFIXES) {
			for (const tld of ENTERPRISE_AFFIX_TLDS) {
				add(`${base}${affix}.${tld}`, 'enterprise_affix', `enterprise affix ${affix} across .${tld}`);
			}
		}
	}

	for (const domain of input.markovCandidates ?? []) add(domain, 'markov', 'generated lookalike candidate');

	const sourceCounts: Record<CandidateSeedSource, number> = {
		caller_candidate: 0,
		tld_sweep: 0,
		alias_tld_sweep: 0,
		enterprise_affix: 0,
		markov: 0,
		active_lookalike: 0,
	};
	const candidates = Array.from(byDomain.values()).sort((a, b) => a.domain.localeCompare(b.domain));
	for (const candidate of candidates) {
		for (const source of candidate.sources) sourceCounts[source]++;
	}

	return {
		candidates,
		stats: {
			seeded: candidates.length,
			sources: sourceCounts,
			dropped,
		},
	};
}
