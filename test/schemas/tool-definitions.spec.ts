import { describe, it, expect } from 'vitest';
import { TOOLS } from '../../src/schemas/tool-definitions';

describe('TOOLS', () => {
	it('has 39 tools', () => {
		expect(TOOLS).toHaveLength(47);
	});

	it('every tool has required fields', () => {
		for (const tool of TOOLS) {
			expect(tool.name).toBeTruthy();
			expect(tool.description).toBeTruthy();
			expect(tool.inputSchema).toBeDefined();
			expect(tool.inputSchema.type).toBe('object');
			expect(tool.inputSchema.properties).toBeDefined();
			expect(tool.group).toBeTruthy();
			expect(typeof tool.scanIncluded).toBe('boolean');
		}
	});

	it('scan_domain has profile, force_refresh, format properties', () => {
		const scan = TOOLS.find((t) => t.name === 'scan_domain')!;
		expect(scan.inputSchema.properties).toHaveProperty('domain');
		expect(scan.inputSchema.properties).toHaveProperty('profile');
		expect(scan.inputSchema.properties).toHaveProperty('force_refresh');
		expect(scan.inputSchema.properties).toHaveProperty('format');
	});

	it('check_dkim has selector property', () => {
		const dkim = TOOLS.find((t) => t.name === 'check_dkim')!;
		expect(dkim.inputSchema.properties).toHaveProperty('selector');
	});

	it('explain_finding has checkType and status required', () => {
		const explain = TOOLS.find((t) => t.name === 'explain_finding')!;
		expect(explain.inputSchema.required).toContain('checkType');
		expect(explain.inputSchema.required).toContain('status');
	});

	it('compare_baseline requires domain and baseline', () => {
		const baseline = TOOLS.find((t) => t.name === 'compare_baseline')!;
		expect(baseline.inputSchema.required).toContain('domain');
		expect(baseline.inputSchema.required).toContain('baseline');
	});

	it('get_benchmark has no required fields', () => {
		const bench = TOOLS.find((t) => t.name === 'get_benchmark')!;
		expect(bench.inputSchema.required ?? []).toHaveLength(0);
	});

	it('domain-only tools have domain as only required field', () => {
		const tool = TOOLS.find((t) => t.name === 'check_spf')!;
		expect(tool.inputSchema.required).toEqual(['domain']);
	});

	it('no tool has additionalProperties: false', () => {
		for (const tool of TOOLS) {
			expect((tool.inputSchema as Record<string, unknown>).additionalProperties).not.toBe(false);
		}
	});

	it('properties include descriptions from .describe()', () => {
		const spf = TOOLS.find((t) => t.name === 'check_spf')!;
		const domainProp = spf.inputSchema.properties.domain as Record<string, unknown>;
		expect(domainProp.description).toBeTruthy();
	});
});
