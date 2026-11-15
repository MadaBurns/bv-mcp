import { describe, expect, it } from 'vitest';
import {
	extractAndValidateDomain,
	extractDkimSelector,
	extractExplainFindingArgs,
	extractFormat,
	normalizeToolName,
	resolveToolAlias,
	validateToolArgs,
} from '../src/handlers/tool-args';

describe('tool-args helpers', () => {
	it('normalizes tool aliases', () => {
		expect(normalizeToolName(' scan ')).toBe('scan_domain');
		expect(normalizeToolName('CHECK_SPF')).toBe('check_spf');
		// deprecated generate_* names resolve (name-only) to the merged tool
		expect(normalizeToolName('generate_spf_record')).toBe('generate');
		expect(normalizeToolName('generate_rollout_plan')).toBe('generate');
	});

	it('resolveToolAlias injects the artifact for deprecated generate_* names', () => {
		expect(resolveToolAlias('generate_spf_record', { domain: 'example.com' })).toEqual({
			name: 'generate',
			args: { domain: 'example.com', artifact: 'spf_record' },
		});
		// injected artifact is forced — it wins over a conflicting caller value
		expect(resolveToolAlias('generate_dkim_config', { domain: 'example.com', artifact: 'dmarc_record' })).toEqual({
			name: 'generate',
			args: { domain: 'example.com', artifact: 'dkim_config' },
		});
		// 1:1 alias (no injection) passes args through untouched
		expect(resolveToolAlias('scan', { domain: 'example.com' })).toEqual({ name: 'scan_domain', args: { domain: 'example.com' } });
		// non-alias names pass through normalized
		expect(resolveToolAlias('check_spf', { domain: 'example.com' })).toEqual({ name: 'check_spf', args: { domain: 'example.com' } });
	});

	it('extractAndValidateDomain sanitizes valid domains and rejects missing ones', () => {
		expect(extractAndValidateDomain({ domain: 'Example.COM.' })).toBe('example.com');
		expect(() => extractAndValidateDomain({})).toThrow('Missing required parameter: domain');
	});

	it('extractDkimSelector normalizes valid selectors', () => {
		expect(extractDkimSelector({ selector: ' Selector-1 ' })).toBe('selector-1');
		expect(extractDkimSelector({})).toBeUndefined();
		// Selector validation is now handled by Zod in validateToolArgs, not this function
		expect(extractDkimSelector({ selector: 'bad@selector' })).toBe('bad@selector');
	});

	it('extractExplainFindingArgs reads args without throwing', () => {
		expect(extractExplainFindingArgs({ checkType: 'SPF', status: 'fail', details: 'detail' })).toEqual({
			checkType: 'SPF',
			status: 'fail',
			details: 'detail',
		});
		// Missing fields are now caught by validateToolArgs, not this function
		expect(extractExplainFindingArgs({ checkType: 'SPF' })).toEqual({ checkType: 'SPF', status: undefined, details: undefined });
	});

	it('extractFormat returns the format value as-is (normalization handled by Zod)', () => {
		expect(extractFormat({ format: 'full' })).toBe('full');
		expect(extractFormat({ format: 'compact' })).toBe('compact');
		expect(extractFormat({})).toBeUndefined();
		expect(extractFormat({ format: null })).toBeUndefined();
		// Normalization and validation are handled by Zod in validateToolArgs
	});

	it('validateToolArgs enforces Zod schemas for known tools', () => {
		// Missing domain
		expect(() => validateToolArgs('check_spf', {})).toThrow('Missing required parameter: domain');
		// Invalid selector
		expect(() => validateToolArgs('check_dkim', { domain: 'example.com', selector: 'bad@selector' })).toThrow('Invalid DKIM selector');
		// Invalid format
		expect(() => validateToolArgs('check_spf', { domain: 'example.com', format: 'verbose' })).toThrow('Invalid format');
		// explain_finding: missing checkType
		expect(() => validateToolArgs('explain_finding', { status: 'pass' })).toThrow('Missing required parameters');
		// explain_finding: missing status (enum)
		expect(() => validateToolArgs('explain_finding', { checkType: 'SPF' })).toThrow('Missing required parameters');
	});

	it('validateToolArgs passes through unknown tool names', () => {
		const args = { foo: 'bar' };
		expect(validateToolArgs('unknown_tool', args)).toBe(args);
	});

	it('validates validate_fix args', () => {
		const result = validateToolArgs('validate_fix', { domain: 'example.com', check: 'dmarc' });
		expect(result).toHaveProperty('domain');
		expect(result).toHaveProperty('check', 'dmarc');
		expect(() => validateToolArgs('validate_fix', { domain: 'example.com' })).toThrow('Missing required parameters');
		expect(() => validateToolArgs('validate_fix', { domain: 'example.com', check: '' })).toThrow();
	});

	it('validates map_supply_chain args', () => {
		const result = validateToolArgs('map_supply_chain', { domain: 'example.com' });
		expect(result).toHaveProperty('domain');
		expect(() => validateToolArgs('map_supply_chain', {})).toThrow('Missing required parameter: domain');
	});

	it('validates analyze_drift args', () => {
		const result = validateToolArgs('analyze_drift', { domain: 'example.com', baseline: 'cached' });
		expect(result).toHaveProperty('domain');
		expect(result).toHaveProperty('baseline', 'cached');
	});

	it('analyze_drift baseline defaults to "cached" when omitted (arg-forgiveness)', () => {
		// A blind first call (domain only) no longer throws a missing-arg error —
		// it resolves against the last cached scan. Cuts the tool's dominant
		// first-call failure; with no cache the tool returns a clean actionable
		// non-error downstream, not a validation throw.
		const result = validateToolArgs('analyze_drift', { domain: 'example.com' });
		expect(result).toHaveProperty('baseline', 'cached');
	});

	it('validates generate(artifact=rollout_plan) args', () => {
		const result = validateToolArgs('generate', { artifact: 'rollout_plan', domain: 'example.com' });
		expect(result).toHaveProperty('domain');
		const full = validateToolArgs('generate', {
			artifact: 'rollout_plan',
			domain: 'example.com',
			target_policy: 'quarantine',
			timeline: 'aggressive',
		});
		expect(full).toHaveProperty('target_policy', 'quarantine');
		expect(full).toHaveProperty('timeline', 'aggressive');
		expect(() => validateToolArgs('generate', {
			artifact: 'rollout_plan',
			domain: 'example.com',
			timeline: 'invalid',
		})).toThrow('Invalid');
	});
});

describe('candidate_domains entries are validated like a domain argument', () => {
	const tools = ['discover_brand_domains', 'discover_brand_domains_start', 'brand_audit_single'] as const;
	const reserved = ['localhost', '127.0.0.1', '169.254.169.254', 'example.com/../etc', 'a..b.com'];

	it.each(tools)('%s refuses a reserved or malformed entry and names its position', (tool) => {
		for (const bad of reserved) {
			expect(() => validateToolArgs(tool, { domain: 'example.com', candidate_domains: ['example.org', bad] })).toThrow(
				'Invalid candidate_domains.1: each entry must be a public domain name',
			);
		}
	});

	it('brand_audit_batch_start refuses the same entries', () => {
		expect(() => validateToolArgs('brand_audit_batch_start', { domains: ['example.com'], candidate_domains: ['localhost'] })).toThrow(
			'Invalid candidate_domains.0: each entry must be a public domain name',
		);
	});

	it.each(tools)('%s still accepts ordinary, uppercase and trailing-dot candidates', (tool) => {
		const candidates = ['example.org', 'EXAMPLE.NET', 'sub.example.co.nz', 'example.com.'];
		expect(validateToolArgs(tool, { domain: 'example.com', candidate_domains: candidates }).candidate_domains).toEqual(candidates);
		expect(validateToolArgs(tool, { domain: 'example.com', candidate_domains: [] }).candidate_domains).toEqual([]);
		expect(validateToolArgs(tool, { domain: 'example.com' }).candidate_domains).toBeUndefined();
	});
});
