// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import {
	FindingSchema,
	CheckResultSchema,
	ScanScoreSchema,
	CheckCategorySchema,
	SeveritySchema,
	FindingConfidenceSchema,
	CategoryTierSchema,
} from '../schemas/scoring';

describe('CheckCategorySchema', () => {
	it('accepts all valid categories', () => {
		const categories = [
			'spf', 'dmarc', 'dkim', 'dnssec', 'ssl', 'mta_sts', 'ns', 'caa',
			'subdomain_takeover', 'mx', 'bimi', 'tlsrpt', 'lookalikes', 'shadow_domains',
			'txt_hygiene', 'http_security', 'dane', 'mx_reputation', 'srv', 'zone_hygiene',
			'dane_https', 'svcb_https',
		];
		for (const cat of categories) {
			const result = CheckCategorySchema.safeParse(cat);
			expect(result.success, `expected '${cat}' to be valid`).toBe(true);
		}
	});

	it('rejects unknown categories', () => {
		const result = CheckCategorySchema.safeParse('unknown_category');
		expect(result.success).toBe(false);
	});
});

describe('SeveritySchema', () => {
	it('accepts all severity levels', () => {
		for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
			expect(SeveritySchema.safeParse(sev).success).toBe(true);
		}
	});

	it('rejects invalid severity', () => {
		expect(SeveritySchema.safeParse('warning').success).toBe(false);
	});
});

describe('FindingConfidenceSchema', () => {
	it('accepts all confidence levels', () => {
		for (const conf of ['deterministic', 'heuristic', 'verified']) {
			expect(FindingConfidenceSchema.safeParse(conf).success).toBe(true);
		}
	});

	it('rejects invalid confidence', () => {
		expect(FindingConfidenceSchema.safeParse('uncertain').success).toBe(false);
	});
});

describe('CategoryTierSchema', () => {
	it('accepts all tiers', () => {
		for (const tier of ['core', 'protective', 'hardening']) {
			expect(CategoryTierSchema.safeParse(tier).success).toBe(true);
		}
	});

	it('rejects invalid tier', () => {
		expect(CategoryTierSchema.safeParse('bonus').success).toBe(false);
	});
});

describe('FindingSchema', () => {
	const validFinding = {
		category: 'spf',
		title: 'SPF record configured',
		severity: 'info',
		detail: 'SPF record found and valid',
	};

	it('accepts a valid finding without metadata', () => {
		const result = FindingSchema.safeParse(validFinding);
		expect(result.success).toBe(true);
	});

	it('accepts a valid finding with metadata', () => {
		const result = FindingSchema.safeParse({
			...validFinding,
			metadata: { record: 'v=spf1 include:_spf.google.com ~all', confidence: 'deterministic' },
		});
		expect(result.success).toBe(true);
	});

	it('accepts a finding with empty metadata object', () => {
		const result = FindingSchema.safeParse({ ...validFinding, metadata: {} });
		expect(result.success).toBe(true);
	});

	it('rejects when category is missing', () => {
		const { category: _, ...partial } = validFinding;
		const result = FindingSchema.safeParse(partial);
		expect(result.success).toBe(false);
	});

	it('rejects when title is missing', () => {
		const { title: _, ...partial } = validFinding;
		const result = FindingSchema.safeParse(partial);
		expect(result.success).toBe(false);
	});

	it('rejects when severity is missing', () => {
		const { severity: _, ...partial } = validFinding;
		const result = FindingSchema.safeParse(partial);
		expect(result.success).toBe(false);
	});

	it('rejects when detail is missing', () => {
		const { detail: _, ...partial } = validFinding;
		const result = FindingSchema.safeParse(partial);
		expect(result.success).toBe(false);
	});

	it('rejects invalid severity value', () => {
		const result = FindingSchema.safeParse({ ...validFinding, severity: 'warning' });
		expect(result.success).toBe(false);
	});

	it('rejects invalid category value', () => {
		const result = FindingSchema.safeParse({ ...validFinding, category: 'nonexistent' });
		expect(result.success).toBe(false);
	});
});

describe('CheckResultSchema', () => {
	const validResult = {
		category: 'dmarc',
		passed: true,
		score: 85,
		findings: [
			{
				category: 'dmarc',
				title: 'DMARC policy configured',
				severity: 'info',
				detail: 'DMARC record found with p=reject',
			},
		],
	};

	it('accepts a valid check result', () => {
		const result = CheckResultSchema.safeParse(validResult);
		expect(result.success).toBe(true);
	});

	it('accepts a result with empty findings array', () => {
		const result = CheckResultSchema.safeParse({ ...validResult, findings: [] });
		expect(result.success).toBe(true);
	});

	it('accepts a result with multiple findings', () => {
		const result = CheckResultSchema.safeParse({
			...validResult,
			findings: [
				{ category: 'dmarc', title: 'Finding A', severity: 'medium', detail: 'Detail A' },
				{ category: 'dmarc', title: 'Finding B', severity: 'low', detail: 'Detail B' },
				{ category: 'dmarc', title: 'Finding C', severity: 'info', detail: 'Detail C' },
			],
		});
		expect(result.success).toBe(true);
	});

	it('rejects when passed is not a boolean', () => {
		const result = CheckResultSchema.safeParse({ ...validResult, passed: 'yes' });
		expect(result.success).toBe(false);
	});

	it('rejects when score is not a number', () => {
		const result = CheckResultSchema.safeParse({ ...validResult, score: 'high' });
		expect(result.success).toBe(false);
	});

	it('rejects when findings is missing', () => {
		const { findings: _, ...partial } = validResult;
		const result = CheckResultSchema.safeParse(partial);
		expect(result.success).toBe(false);
	});

	it('rejects when a nested finding is invalid', () => {
		const result = CheckResultSchema.safeParse({
			...validResult,
			findings: [{ category: 'dmarc', title: 'Incomplete' }],
		});
		expect(result.success).toBe(false);
	});

	it('accepts boundary score of 0', () => {
		const result = CheckResultSchema.safeParse({ ...validResult, score: 0 });
		expect(result.success).toBe(true);
	});

	it('accepts boundary score of 100', () => {
		const result = CheckResultSchema.safeParse({ ...validResult, score: 100 });
		expect(result.success).toBe(true);
	});

	it('accepts passed=false', () => {
		const result = CheckResultSchema.safeParse({ ...validResult, passed: false, score: 35 });
		expect(result.success).toBe(true);
	});
});

describe('ScanScoreSchema', () => {
	const validScanScore = {
		overall: 78,
		grade: 'B',
		categoryScores: {
			spf: 100,
			dmarc: 85,
			dkim: 60,
			dnssec: 0,
			ssl: 100,
		},
		findings: [
			{
				category: 'dkim',
				title: 'DKIM not found',
				severity: 'high',
				detail: 'No DKIM record found for common selectors',
			},
		],
		summary: 'Good configuration with some gaps in email authentication.',
	};

	it('accepts a valid scan score', () => {
		const result = ScanScoreSchema.safeParse(validScanScore);
		expect(result.success).toBe(true);
	});

	it('accepts a scan score with empty categoryScores', () => {
		const result = ScanScoreSchema.safeParse({
			...validScanScore,
			categoryScores: {},
		});
		expect(result.success).toBe(true);
	});

	it('accepts a scan score with empty findings array', () => {
		const result = ScanScoreSchema.safeParse({
			...validScanScore,
			findings: [],
		});
		expect(result.success).toBe(true);
	});

	it('rejects when overall is missing', () => {
		const { overall: _, ...partial } = validScanScore;
		const result = ScanScoreSchema.safeParse(partial);
		expect(result.success).toBe(false);
	});

	it('rejects when grade is missing', () => {
		const { grade: _, ...partial } = validScanScore;
		const result = ScanScoreSchema.safeParse(partial);
		expect(result.success).toBe(false);
	});

	it('rejects when categoryScores is missing', () => {
		const { categoryScores: _, ...partial } = validScanScore;
		const result = ScanScoreSchema.safeParse(partial);
		expect(result.success).toBe(false);
	});

	it('rejects when summary is missing', () => {
		const { summary: _, ...partial } = validScanScore;
		const result = ScanScoreSchema.safeParse(partial);
		expect(result.success).toBe(false);
	});

	it('rejects non-numeric values in categoryScores', () => {
		const result = ScanScoreSchema.safeParse({
			...validScanScore,
			categoryScores: { spf: 'excellent' },
		});
		expect(result.success).toBe(false);
	});

	it('accepts boundary overall score of 0', () => {
		const result = ScanScoreSchema.safeParse({ ...validScanScore, overall: 0 });
		expect(result.success).toBe(true);
	});

	it('accepts boundary overall score of 100', () => {
		const result = ScanScoreSchema.safeParse({ ...validScanScore, overall: 100 });
		expect(result.success).toBe(true);
	});

	it('validates nested findings within scan score', () => {
		const result = ScanScoreSchema.safeParse({
			...validScanScore,
			findings: [{ category: 'spf', title: 'Incomplete' }],
		});
		expect(result.success).toBe(false);
	});

	it('accepts all valid grade strings', () => {
		for (const grade of ['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'F']) {
			const result = ScanScoreSchema.safeParse({ ...validScanScore, grade });
			expect(result.success, `expected grade '${grade}' to be valid`).toBe(true);
		}
	});
});
