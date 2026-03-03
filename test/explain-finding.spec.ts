import { describe, it, expect } from 'vitest';

describe('explainFinding', () => {
	async function getModule() {
		return import('../src/tools/explain-finding');
	}

	it('returns correct explanation for known checkType + status', async () => {
		const { explainFinding } = await getModule();
		const result = explainFinding('SPF', 'pass');
		expect(result.checkType).toBe('SPF');
		expect(result.status).toBe('pass');
		expect(result.title).toBe('SPF Validated');
		expect(result.severity).toBe('pass');
		expect(result.explanation).toContain('SPF');
		expect(result.recommendation).toBeTruthy();
		expect(result.references.length).toBeGreaterThan(0);
	});

	it('falls back to DEFAULT_EXPLANATION for unknown checkType', async () => {
		const { explainFinding } = await getModule();
		const result = explainFinding('UNKNOWN_CHECK', 'fail');
		expect(result.checkType).toBe('UNKNOWN_CHECK');
		expect(result.title).toBe('Security Check Complete');
		expect(result.severity).toBe('info');
		expect(result.recommendation).toContain('documentation');
	});

	it('falls back to DEFAULT_EXPLANATION for unknown status', async () => {
		const { explainFinding } = await getModule();
		const result = explainFinding('SPF', 'unknown_status');
		expect(result.title).toBe('Security Check Complete');
		expect(result.severity).toBe('info');
	});

	it('includes details when provided', async () => {
		const { explainFinding } = await getModule();
		const result = explainFinding('SPF', 'fail', 'Record uses +all');
		expect(result.details).toBe('Record uses +all');
	});

	it('details is undefined when not provided', async () => {
		const { explainFinding } = await getModule();
		const result = explainFinding('SPF', 'fail');
		expect(result.details).toBeUndefined();
	});

	it('normalizes checkType via toUpperCase (case insensitive)', async () => {
		const { explainFinding } = await getModule();
		const result = explainFinding('spf', 'pass');
		expect(result.checkType).toBe('SPF');
		expect(result.title).toBe('SPF Validated');
	});

	it('handles MTA_STS checkType', async () => {
		const { explainFinding } = await getModule();
		const result = explainFinding('MTA_STS', 'pass');
		expect(result.checkType).toBe('MTA_STS');
		expect(result.title).toBe('MTA-STS Enabled');
	});

	it('handles SUBDOMAIN_TAKEOVER checkType with critical status', async () => {
		const { explainFinding } = await getModule();
		// SUBDOMAIN_TAKEOVER is already uppercase, so toUpperCase() keeps it as-is
		const result = explainFinding('SUBDOMAIN_TAKEOVER', 'critical');
		expect(result.title).toBe('Dangling CNAME — Subdomain Takeover Risk');
		expect(result.severity).toBe('critical');
	});
});

describe('formatExplanation', () => {
	async function getModule() {
		return import('../src/tools/explain-finding');
	}

	it('formats result without details', async () => {
		const { explainFinding, formatExplanation } = await getModule();
		const result = explainFinding('SPF', 'fail');
		const text = formatExplanation(result);
		expect(text).toContain('## SPF Validation Failed');
		expect(text).toContain('**Check Type:** SPF');
		expect(text).toContain('**Status:** fail');
		expect(text).toContain('### What this means');
		expect(text).toContain('### Recommendation');
		expect(text).toContain('### References');
		expect(text).not.toContain('**Details:**');
	});

	it('includes details when present in result', async () => {
		const { explainFinding, formatExplanation } = await getModule();
		const result = explainFinding('SPF', 'fail', 'SPF record uses +all');
		const text = formatExplanation(result);
		expect(text).toContain('**Details:** SPF record uses +all');
	});

	it('includes references as markdown links', async () => {
		const { explainFinding, formatExplanation } = await getModule();
		const result = explainFinding('DMARC', 'pass');
		const text = formatExplanation(result);
		expect(text).toContain('- https://');
	});
});
