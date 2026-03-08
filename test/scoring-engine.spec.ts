import { describe, expect, it } from 'vitest';
import { scoreToGrade, computeScanScore } from '../src/lib/scoring-engine';
import { buildCheckResult, createFinding } from '../src/lib/scoring-model';

describe('scoring-engine', () => {
	it('maps numeric scores to expected grade bands', () => {
		expect(scoreToGrade(90)).toBe('A+');
		expect(scoreToGrade(75)).toBe('B');
		expect(scoreToGrade(49)).toBe('F');
	});

	it('returns excellent summary when no check results are present', () => {
		const scan = computeScanScore([]);
		expect(scan.overall).toBe(100);
		expect(scan.summary).toContain('Excellent');
	});

	it('applies verified critical penalty during aggregate scoring', () => {
		const scan = computeScanScore([
			buildCheckResult('subdomain_takeover', [
				createFinding('subdomain_takeover', 'Verified takeover', 'critical', 'Fingerprint confirmed', {
					verificationStatus: 'verified',
				}),
			]),
		]);

		expect(scan.overall).toBe(84);
	});
});