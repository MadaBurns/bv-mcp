// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';

export const FindingSchema = z
	.object({
		category: z.string(),
		title: z.string(),
		severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
		detail: z.string(),
	})
	.passthrough();

export const EvidenceCoverageSchema = z
	.object({
		attempted: z.number().int().nonnegative(),
		completed: z.number().int().nonnegative(),
		ratio: z.number().min(0).max(1),
	})
	.passthrough();

/** Tolerant client projection of scan_domain structuredContent. */
export const ScanResultSchema = z
	.object({
		domain: z.string().min(1),
		score: z.number().min(0).max(100).nullable(),
		grade: z.string().min(1).nullable(),
		passed: z.boolean().nullable(),
		measured: z.boolean(),
		categoryScores: z.record(z.string(), z.number().nullable()),
		findings: z.array(FindingSchema),
		checkStatuses: z.record(z.string(), z.enum(['completed', 'timeout', 'error'])),
		notApplicableCategories: z.array(z.string()),
		inconclusiveCategories: z.array(z.string()),
		evidence: EvidenceCoverageSchema,
		evidenceInsufficient: z.boolean(),
		timestamp: z.string().datetime(),
		scoringModelVersion: z.string().min(1),
		dnsChecksPackageVersion: z.string().min(1),
		scoringConfigHash: z.string().min(1),
		error: z.string().optional(),
	})
	.passthrough();

export const CheckResultSchema = z
	.object({
		category: z.string().min(1),
		passed: z.boolean(),
		score: z.number().min(0).max(100),
		findings: z.array(FindingSchema),
		checkStatus: z.enum(['completed', 'timeout', 'error']).optional(),
		partial: z.boolean().optional(),
	})
	.passthrough();

export const BatchResultSchema = z
	.object({
		results: z.array(ScanResultSchema).min(1).max(10),
	})
	.passthrough();

export const PolicyResultSchema = z
	.object({
		domain: z.string().min(1),
		passed: z.boolean().nullable(),
		violations: z.array(z.unknown()),
		inconclusiveRules: z.array(z.string()),
		checkedRules: z.number().int().nonnegative(),
		timestamp: z.string().datetime(),
	})
	.passthrough();

export const DriftResultSchema = z
	.object({
		domain: z.string().min(1),
		classification: z.enum(['improving', 'stable', 'regressing', 'mixed', 'inconclusive']),
		scoreDelta: z.number().nullable(),
		gradeChange: z.object({ from: z.string().nullable(), to: z.string().nullable() }).passthrough(),
		timestamp: z.string().datetime(),
	})
	.passthrough();

export type ScanResult = z.infer<typeof ScanResultSchema>;
