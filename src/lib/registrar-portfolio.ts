// SPDX-License-Identifier: BUSL-1.1

/**
 * Registrar-portfolio aggregator.
 *
 * Pure rollup over the brand-audit sidecar candidate list. Buckets each
 * apex (anchor + discovered candidates) by registrar family using
 * `classifyRegistrarFamily`, computes percentages, and surfaces the
 * off-portfolio set (candidates whose family differs from the anchor's)
 * as the headline CSC-narrative artifact.
 *
 * `registrarSource ∈ {'unknown', 'lookup_failed'}` forces the candidate
 * into the `unknown` family regardless of any name string — we don't
 * trust a registrar string we couldn't independently verify.
 *
 * No I/O. Worker-runtime safe.
 */

import { classifyRegistrarFamily } from './registrar-identity';

const UNUSABLE_REGISTRAR_SOURCES = new Set(['unknown', 'lookup_failed']);
const UNKNOWN_FAMILY = 'unknown';
const MAX_EXAMPLE_APEXES = 5;

/**
 * Structural subset of the brand-audit sidecar candidate shape — the fields
 * the portfolio aggregator depends on. Avoids importing the test helper's
 * full DiscoveryReportCandidate type into production code.
 */
export interface PortfolioCandidate {
	domain: string;
	registrar: string;
	registrarSource: string;
}

export interface RegistrarPortfolioAnchor {
	apex: string;
	registrar: string | null;
	registrarSource: string;
}

export interface RegistrarPortfolioFamilyEntry {
	family: string;
	count: number;
	percent: number;
	exampleApexes: string[];
}

export interface RegistrarPortfolio {
	totalApexes: number;
	byFamily: RegistrarPortfolioFamilyEntry[];
	offPortfolioCount: number;
	offPortfolioApexes: string[];
}

interface FamilyAccumulator {
	family: string;
	apexes: string[];
}

function familyFor(registrar: string | null | undefined, registrarSource: string): string {
	if (UNUSABLE_REGISTRAR_SOURCES.has(registrarSource)) return UNKNOWN_FAMILY;
	return classifyRegistrarFamily(registrar) ?? UNKNOWN_FAMILY;
}

/**
 * Aggregate registrar portfolio from a list of candidates and an anchor domain.
 *
 * Groups each apex (anchor + all candidates) by registrar family using
 * `classifyRegistrarFamily`. Returns a summary with total count, per-family
 * statistics (count, percent, example apexes capped at 5), and the
 * off-portfolio set (candidates whose family differs from anchor's family).
 *
 * Families are sorted descending by count.
 */
export function aggregateRegistrarPortfolio(
	candidates: ReadonlyArray<PortfolioCandidate>,
	anchor: RegistrarPortfolioAnchor,
): RegistrarPortfolio {
	const byFamily = new Map<string, FamilyAccumulator>();

	const addApex = (apex: string, family: string): void => {
		const existing = byFamily.get(family);
		if (existing) {
			existing.apexes.push(apex);
		} else {
			byFamily.set(family, { family, apexes: [apex] });
		}
	};

	const anchorFamily = familyFor(anchor.registrar, anchor.registrarSource);
	addApex(anchor.apex, anchorFamily);

	for (const candidate of candidates) {
		const family = familyFor(candidate.registrar, candidate.registrarSource);
		addApex(candidate.domain, family);
	}

	const totalApexes = candidates.length + 1;

	const entries: RegistrarPortfolioFamilyEntry[] = Array.from(byFamily.values())
		.map((acc) => ({
			family: acc.family,
			count: acc.apexes.length,
			percent: (acc.apexes.length / totalApexes) * 100,
			exampleApexes: acc.apexes.slice(0, MAX_EXAMPLE_APEXES),
		}))
		.sort((a, b) => b.count - a.count);

	const offPortfolioApexes: string[] = [];
	if (anchorFamily !== UNKNOWN_FAMILY) {
		for (const candidate of candidates) {
			const family = familyFor(candidate.registrar, candidate.registrarSource);
			if (family !== anchorFamily && family !== UNKNOWN_FAMILY) {
				offPortfolioApexes.push(candidate.domain);
			}
		}
	}

	return {
		totalApexes,
		byFamily: entries,
		offPortfolioCount: offPortfolioApexes.length,
		offPortfolioApexes,
	};
}
