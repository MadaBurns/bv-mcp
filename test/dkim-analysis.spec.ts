import { describe, expect, it } from 'vitest';

import { analyzeKeyStrength, consolidateSelectorProbeKeyStrengthFindings, getDkimTagValue } from '../src/tools/dkim-analysis';
import { createFinding } from '../src/lib/scoring';

describe('dkim-analysis', () => {
	it('extracts DKIM tag values', () => {
		expect(getDkimTagValue('v=DKIM1; k=rsa; p=abc123', 'k')).toBe('rsa');
		expect(getDkimTagValue('v=DKIM1; k=rsa; p=abc123', 'p')).toBe('abc123');
		expect(getDkimTagValue('v=DKIM1; k=rsa; p=abc123', 't')).toBeUndefined();
	});

	it('treats ed25519 as strong by design', () => {
		expect(analyzeKeyStrength('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=', 'ed25519')).toEqual({
			bits: 256,
			strength: 'info',
			keyType: 'ed25519',
		});
	});

	it('flags short keys without k= as ambiguous', () => {
		expect(analyzeKeyStrength('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIa', 'rsa-default')).toEqual({
			bits: null,
			strength: 'medium',
			keyType: 'unknown',
		});
	});

	it('estimates RSA strength from key length', () => {
		expect(analyzeKeyStrength('x'.repeat(100), 'rsa')).toMatchObject({ bits: 512, strength: 'critical', keyType: 'rsa' });
		expect(analyzeKeyStrength('x'.repeat(200), 'rsa')).toMatchObject({ bits: 1024, strength: 'high', keyType: 'rsa' });
		expect(analyzeKeyStrength('x'.repeat(300), 'rsa')).toMatchObject({ bits: 2048, strength: 'medium', keyType: 'rsa' });
		expect(analyzeKeyStrength('x'.repeat(600), 'rsa')).toMatchObject({ bits: 4096, strength: 'info', keyType: 'rsa' });
	});

	it('consolidates duplicate selector-probe key findings', () => {
		const findings = [
			createFinding('dkim', 'Legacy RSA key: google', 'high', 'legacy', { estimatedBits: 1024, keyType: 'rsa' }),
			createFinding('dkim', 'Legacy RSA key: selector1', 'high', 'legacy', { estimatedBits: 1024, keyType: 'rsa' }),
			createFinding('dkim', 'DKIM configured', 'info', 'configured'),
		];

		consolidateSelectorProbeKeyStrengthFindings(findings);

		expect(findings.filter((finding) => /Legacy RSA key/i.test(finding.title))).toHaveLength(1);
		expect(findings.find((finding) => /consolidated/i.test(finding.title))?.severity).toBe('info');
	});
});