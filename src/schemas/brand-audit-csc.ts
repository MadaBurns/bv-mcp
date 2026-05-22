// SPDX-License-Identifier: BUSL-1.1

/**
 * Zod schema for the cscComplement section of a brand-audit report.
 *
 * Producer-side: bv-mcp emits this when `view='csc_complement'`. Consumer-side
 * (bv-web) mirrors this schema in `agentic-csc-complement/product-contract.ts`.
 * Cross-repo drift is caught by the contract test in `test/contracts/`.
 *
 * `viewVersion` is independent of the brand-audit sidecar's v4 version — the
 * CSC view evolves separately. Any breaking change to this schema requires
 * bumping `CSC_VIEW_VERSION` (enforced by audit test).
 */

import { z } from 'zod';

/** Version of the CSC view schema — independent of brand-audit v4. Bump on breaking changes. */
export const CSC_VIEW_VERSION = 1;

const StageEnum = z.enum(['pending', 'running', 'ready']);

/** Registrar identity: family, name, IANA ID. All fields nullable for defensive-unknown entries. */
const RegistrarIdentitySchema = z.object({
	family: z.string().nullable(),
	name: z.string().nullable(),
	ianaId: z.string().nullable(),
});

/** Anchor domain: primary apex, its registrar, and CSC management status. */
const AnchorSchema = z.object({
	apex: z.string().min(1),
	primaryRegistrar: RegistrarIdentitySchema,
	managedByCsc: z.boolean(),
});

/** Family entry in registrar portfolio: counts, percentages, and example apexes. */
const FamilyEntrySchema = z.object({
	family: z.string(),
	count: z.number().int().nonnegative(),
	percent: z.number().min(0).max(100),
	exampleApexes: z.array(z.string()),
	registrarSource: z.string().optional(),
});

/** Portfolio aggregation: total apexes, breakdown by registrar family, off-portfolio counts. */
const RegistrarPortfolioSchema = z.object({
	totalApexes: z.number().int().nonnegative(),
	byFamily: z.array(FamilyEntrySchema),
	offPortfolioCount: z.number().int().nonnegative(),
	offPortfolioApexes: z.array(z.string()),
});

/** Shadow-IT highlight: apex with registrar mismatch evidence. */
const ShadowItHighlightSchema = z.object({
	apex: z.string(),
	registrar: z.string().nullable(),
	combinedConfidence: z.number().nullable(),
	reasons: z.array(z.string()),
	evidence: z.string().optional(),
});

/** Single defensive registration example with reason classification. */
const DefensiveExampleSchema = z.object({
	apex: z.string(),
	defensiveReason: z.enum(['redirect-to-target', 'no-mx', 'parked-ns']),
});

/** Defensive registrations summary: count, examples, and data-enrichment status. */
const DefensiveRegistrationsSchema = z.object({
	count: z.number().int().nonnegative(),
	examples: z.array(DefensiveExampleSchema),
	enrichmentStatus: z.enum(['ready', 'partial', 'sparse']),
});

/** Single apex posture snapshot: grade, score, and individual protocol statuses. */
const PostureApexSchema = z.object({
	apex: z.string(),
	grade: z.string(),
	score: z.number().int(),
	dmarc: z.string().nullable(),
	spf: z.string().nullable(),
	dnssec: z.boolean().nullable(),
	dkim: z.string().nullable(),
	mtaSts: z.string().nullable(),
	scannedAt: z.string(),
});

/** Posture snapshot: stage, counts, apex details, and grade distribution. */
const PostureSnapshotSchema = z.object({
	stage: StageEnum,
	apexesScanned: z.number().int().nonnegative(),
	apexesTotal: z.number().int().nonnegative(),
	apexes: z.array(PostureApexSchema),
	medianGrade: z.string().nullable(),
	distribution: z.record(z.string(), z.number().int().nonnegative()),
});

/** Single dangling DNS finding: subdomain, target, and takeover risk. */
const DanglingFindingSchema = z.object({
	subdomain: z.string(),
	apex: z.string(),
	recordType: z.string(),
	target: z.string().nullable(),
	takeoverProvider: z.string().nullable(),
	severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
	evidence: z.string().optional(),
});

/** Subdomain inventory entry: source is always certificate-transparency. */
const SubdomainInventoryEntrySchema = z.object({
	total: z.number().int().nonnegative(),
	dangling: z.number().int().nonnegative(),
	source: z.literal('certificate_transparency'),
	sample: z.array(z.string()),
	partial: z.boolean(),
});

/** Deep scan: stage, apex counts, dangling findings, and subdomain inventory by apex. */
const DeepScanSchema = z.object({
	stage: StageEnum,
	apexesScanned: z.number().int().nonnegative(),
	apexesTotal: z.number().int().nonnegative(),
	danglingDns: z.array(DanglingFindingSchema),
	danglingDnsTotal: z.number().int().nonnegative(),
	subdomainInventoryByApex: z.record(z.string(), SubdomainInventoryEntrySchema),
});

/** Complete CSC complement view: all sections of the brand-audit report for CSC-managed domains. */
export const BrandAuditCscSchema = z.object({
	viewVersion: z.literal(CSC_VIEW_VERSION),
	anchor: AnchorSchema,
	registrarPortfolio: RegistrarPortfolioSchema,
	shadowItHighlights: z.array(ShadowItHighlightSchema),
	defensiveRegistrations: DefensiveRegistrationsSchema,
	postureSnapshot: PostureSnapshotSchema,
	deepScan: DeepScanSchema,
	generatedAt: z.string(),
	reportId: z.string().regex(/^csc_rpt_[a-zA-Z0-9]+$/),
});

/** TypeScript type derived from the schema — use for inline type annotations. */
export type BrandAuditCsc = z.infer<typeof BrandAuditCscSchema>;
