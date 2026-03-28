// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';

/** All valid check categories. */
export const CheckCategorySchema = z.enum([
	'spf', 'dmarc', 'dkim', 'dnssec', 'ssl', 'mta_sts', 'ns', 'caa',
	'subdomain_takeover', 'mx', 'bimi', 'tlsrpt', 'lookalikes', 'shadow_domains',
	'txt_hygiene', 'http_security', 'dane', 'mx_reputation', 'srv', 'zone_hygiene',
	'dane_https', 'svcb_https',
]);

/** Severity levels. */
export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);

/** Finding confidence. */
export const FindingConfidenceSchema = z.enum(['deterministic', 'heuristic', 'verified']);

/** Category tier. */
export const CategoryTierSchema = z.enum(['core', 'protective', 'hardening']);

/** A single finding from a check. */
export const FindingSchema = z.object({
	category: CheckCategorySchema,
	title: z.string(),
	severity: SeveritySchema,
	detail: z.string(),
	metadata: z.record(z.string(), z.unknown()).optional(),
});

/** Result of a single DNS check. */
export const CheckResultSchema = z.object({
	category: CheckCategorySchema,
	passed: z.boolean(),
	score: z.number(),
	findings: z.array(FindingSchema),
});

/** Scan score result. */
export const ScanScoreSchema = z.object({
	overall: z.number(),
	grade: z.string(),
	categoryScores: z.record(z.string(), z.number()),
	findings: z.array(FindingSchema),
	summary: z.string(),
});
