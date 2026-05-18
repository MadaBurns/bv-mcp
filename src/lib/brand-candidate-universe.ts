// SPDX-License-Identifier: BUSL-1.1

export type BrandAuditDepth = 'standard' | 'deep';
export type CandidateSeedSource = 'caller_candidate' | 'tld_sweep' | 'alias_tld_sweep' | 'markov' | 'active_lookalike';

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
	'dev',
	'cloud',
	'online',
	'site',
	'store',
	'shop',
	'fi',
	'ch',
	'at',
	'be',
	'pl',
	'no',
	'dk',
	'kr',
	'tw',
	'hk',
	'ar',
	'cl',
	'tr',
	'sa',
];

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
	const byDomain = new Map<string, CandidateSeed>();

	function add(domain: string, source: CandidateSeedSource, reason: string): void {
		const normalized = normalizeDomain(domain);
		if (!normalized || normalized === seed) return;
		const existing = byDomain.get(normalized);
		if (existing) {
			if (!existing.sources.includes(source)) existing.sources.push(source);
			existing.reasons.push(reason);
			return;
		}
		byDomain.set(normalized, { domain: normalized, sources: [source], reasons: [reason] });
	}

	for (const domain of input.candidateDomains ?? []) add(domain, 'caller_candidate', 'caller supplied candidate');
	for (const domain of input.markovCandidates ?? []) add(domain, 'markov', 'generated lookalike candidate');
	for (const domain of input.activeLookalikes ?? []) add(domain, 'active_lookalike', 'active lookalike candidate');

	if (base) {
		for (const tld of tlds) add(`${base}.${tld}`, 'tld_sweep', `seed label across .${tld}`);
	}

	for (const rawAlias of input.brandAliases ?? []) {
		const alias = normalizeAlias(rawAlias);
		if (!alias) continue;
		for (const tld of tlds) add(`${alias}.${tld}`, 'alias_tld_sweep', `brand alias across .${tld}`);
	}

	const sourceCounts: Record<CandidateSeedSource, number> = {
		caller_candidate: 0,
		tld_sweep: 0,
		alias_tld_sweep: 0,
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
		},
	};
}
