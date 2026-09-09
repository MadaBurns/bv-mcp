// SPDX-License-Identifier: BUSL-1.1

/**
 * CSC-complement payload builder.
 *
 * Composes the fast-stage registrarComplement payload from the brand-audit pipeline's
 * classified findings:
 *   1. Per-candidate enrichment (MX + HTTP) → defensive-registration labels
 *   2. Registrar portfolio aggregation
 *   3. Shadow-IT highlight filter
 *   4. Defensive-registration count + examples
 *   5. Initial postureSnapshot + deepScan in 'pending' state (filled by deep-scan job)
 *
 * Receives the pipeline's already-classified findings rather than the raw discovery
 * report, avoiding any dependency on the discovery output shape.
 */

import { REGISTRAR_VIEW_VERSION, type BrandAuditRegistrar } from '../schemas/brand-audit-registrar';
import { aggregateRegistrarPortfolio, type PortfolioCandidate } from './registrar-portfolio';
import { enrichCandidatesForDefensiveDetection } from './brand-audit-registrar-enrichment';
import { classifyRegistrarFamily } from './registrar-identity';
import type { Finding } from './scoring';

const KSUID_PREFIX = 'reg_rpt_';

function makeReportId(now: () => number): string {
	const ts = now().toString(36);
	const bytes = new Uint8Array(16);
	crypto.getRandomValues(bytes);
	const rand = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
	return `${KSUID_PREFIX}${ts}${rand}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Extract the minimal PortfolioCandidate shape from a classified finding's metadata.
 */
function candidateFromFinding(finding: Finding): PortfolioCandidate | null {
	const md = finding.metadata;
	if (!isRecord(md) || typeof md.candidate !== 'string') return null;
	const registrar = typeof md.registrar === 'string' ? md.registrar : '';
	const registrarSource = typeof md.registrarSource === 'string' ? md.registrarSource : 'unknown';
	return { domain: md.candidate, registrar, registrarSource };
}

export interface BuildRegistrarComplementInput {
	/** The seed domain — top-level target of the brand audit. */
	seedDomain: string;
	/** Registrar name for the anchor domain (from RDAP/WHOIS lookup). */
	primaryRegistrar: string;
	/** Registrar source quality indicator for the anchor. */
	primaryRegistrarSource: string;
	/** IANA registrar ID for the anchor, if available. */
	primaryRegistrarIanaId: string | null;
	/** Classified candidate findings from the pipeline's classification phase. */
	classifiedFindings: Finding[];
	/** Clock function for deterministic tests. */
	now: () => number;
}

/**
 * Build the fast-stage registrarComplement payload for a brand audit.
 *
 * Constructs the CSC complement view from classified findings by:
 * 1. Extracting portfolio candidates from finding metadata
 * 2. Running inline enrichment (MX + HTTP checks) on top-N candidates to determine defensive registration
 * 3. Aggregating registrar portfolio from detected candidates
 * 4. Extracting shadow-IT highlights (owned off primary registrar)
 * 5. Initializing postureSnapshot and deepScan with 'pending' stage (to be filled by deep-scan job)
 *
 * @param input - Contains seedDomain, primaryRegistrar, classifiedFindings, and clock function
 * @returns Populated BrandAuditRegistrar with anchor, portfolio, defensive registrations, and pending posture/deep-scan stages
 */
export async function buildRegistrarComplement(input: BuildRegistrarComplementInput): Promise<BrandAuditRegistrar> {
	const { seedDomain, primaryRegistrar, primaryRegistrarSource, primaryRegistrarIanaId, classifiedFindings, now } = input;

	// Derive PortfolioCandidate list from classified findings.
	const portfolioCandidates: PortfolioCandidate[] = [];
	for (const finding of classifiedFindings) {
		const candidate = candidateFromFinding(finding);
		if (candidate) portfolioCandidates.push(candidate);
	}

	// Prepare enrichment input: domain + combinedConfidence from each candidate finding.
	const enrichInput = classifiedFindings.flatMap((finding) => {
		const md = finding.metadata;
		if (!isRecord(md) || typeof md.candidate !== 'string') return [];
		const combinedConfidence = typeof md.combinedConfidence === 'number' ? md.combinedConfidence : null;
		return [{ domain: md.candidate as string, combinedConfidence }];
	});

	const enrichResult = await enrichCandidatesForDefensiveDetection({
		target: seedDomain,
		candidates: enrichInput,
	});

	// Anchor section.
	const anchorFamily = classifyRegistrarFamily(primaryRegistrar);
	const anchor: BrandAuditRegistrar['anchor'] = {
		apex: seedDomain,
		primaryRegistrar: {
			family: anchorFamily,
			name: primaryRegistrar || null,
			ianaId: primaryRegistrarIanaId,
		},
		managedByRegistrar: anchorFamily === 'corporate domains registrar',
	};

	// Portfolio aggregation.
	const portfolio = aggregateRegistrarPortfolio(portfolioCandidates, {
		apex: seedDomain,
		registrar: primaryRegistrar || null,
		registrarSource: primaryRegistrarSource,
	});

	// Shadow-IT highlights: classified as shadowIt + owned_off_primary_registrar.
	const shadowItHighlights: BrandAuditRegistrar['shadowItHighlights'] = classifiedFindings.flatMap((finding) => {
		const md = finding.metadata;
		if (!isRecord(md)) return [];
		if (md.bucket !== 'shadowIt' || md.relationshipType !== 'owned_off_primary_registrar') return [];
		const apex = typeof md.candidate === 'string' ? md.candidate : null;
		if (!apex) return [];
		const registrar = typeof md.registrar === 'string' ? md.registrar : null;
		const combinedConfidence = typeof md.combinedConfidence === 'number' ? md.combinedConfidence : null;
		const reasons = Array.isArray(md.reasons) ? (md.reasons as string[]) : [];
		const evidence = typeof md.detail === 'string' ? md.detail : undefined;
		return [{ apex, registrar, combinedConfidence, reasons, evidence }];
	});

	// Defensive registration examples from enrichment.
	const defensiveExamples: BrandAuditRegistrar['defensiveRegistrations']['examples'] = [];
	for (const candidate of enrichResult.candidates) {
		if (candidate.defensive && candidate.defensiveReason) {
			defensiveExamples.push({ apex: candidate.domain, defensiveReason: candidate.defensiveReason });
		}
	}

	// Set enrichment status: 'sparse' when no candidates entered enrichment.
	const finalEnrichmentStatus = enrichInput.length === 0 ? 'sparse' : enrichResult.enrichmentStatus;

	return {
		viewVersion: REGISTRAR_VIEW_VERSION,
		anchor,
		registrarPortfolio: portfolio,
		shadowItHighlights,
		defensiveRegistrations: {
			count: defensiveExamples.length,
			examples: defensiveExamples,
			enrichmentStatus: finalEnrichmentStatus,
		},
		postureSnapshot: {
			stage: 'pending',
			apexesScanned: 0,
			apexesTotal: 0,
			apexes: [],
			medianGrade: null,
			distribution: {},
		},
		deepScan: {
			stage: 'pending',
			apexesScanned: 0,
			apexesTotal: 0,
			danglingDns: [],
			danglingDnsTotal: 0,
			subdomainInventoryByApex: {},
		},
		generatedAt: new Date(now()).toISOString(),
		reportId: makeReportId(now),
	};
}
