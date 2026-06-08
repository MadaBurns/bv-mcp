import { describe, it, expect } from 'vitest';
import { TOOLS } from '../../src/schemas/tool-definitions';

describe('TOOLS', () => {
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

	// force_refresh is declared in inputSchema for CACHED tools (so clients can discover
	// the cache-bypass), and intentionally ABSENT from stateless tools (generators,
	// explain_finding, pure pollers/queries) where it would be a misleading no-op.
	it('cached tools expose force_refresh; stateless tools do not', () => {
		const hasForceRefresh = (name: string) =>
			Boolean(TOOLS.find((t) => t.name === name)?.inputSchema.properties?.force_refresh);

		const cachedTools = [
			'scan_domain',
			'batch_scan',
			'check_spf',
			'check_lookalikes',
			'check_dkim',
			'check_fast_flux',
			'check_subdomain_takeover',
			'compare_domains',
			'compare_baseline',
			'analyze_drift',
			'generate_fix_plan',
			'map_compliance',
			'discover_brand_domains',
			'brand_audit_single',
		];
		for (const name of cachedTools) {
			expect(hasForceRefresh(name), `${name} should expose force_refresh`).toBe(true);
		}

		const statelessTools = [
			'generate_spf_record',
			'generate_dmarc_record',
			'generate_dkim_config',
			'generate_mta_sts_policy',
			'generate_rollout_plan',
			'explain_finding',
			'get_benchmark',
			'check_resolver_consistency',
			'check_root_server_set',
			'query_signins',
			'osint_investigate_domain_start',
			'brand_audit_status',
		];
		for (const name of statelessTools) {
			expect(hasForceRefresh(name), `${name} should NOT expose force_refresh`).toBe(false);
		}
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

	// F6: the published inputSchema must be HONEST about extra-prop handling.
	// Tools whose runtime args schema is `.strict()` hard-reject unknown props,
	// so their published schema MUST advertise additionalProperties:false (else
	// the surface lies — "extra params allowed" while the runtime rejects them).
	// Every other tool uses `.passthrough()` and must NOT carry the strict marker.
	const STRICT_RUNTIME_TOOLS = new Set([
		'scan_buckets_start',
		'scan_buckets_status',
		'scan_buckets_findings',
		'osint_investigate_domain_start',
		'osint_investigate_infrastructure_start',
		'osint_investigate_supply_chain_start',
		'osint_investigate_username_start',
		'osint_investigate_email_start',
		'osint_investigation_status',
		'osint_investigation_report',
	]);

	it('strict-runtime tools publish additionalProperties:false (schema matches runtime)', () => {
		for (const name of STRICT_RUNTIME_TOOLS) {
			const tool = TOOLS.find((t) => t.name === name)!;
			expect(tool, `${name} not found in TOOLS`).toBeDefined();
			expect((tool.inputSchema as Record<string, unknown>).additionalProperties, `${name} should advertise additionalProperties:false`).toBe(
				false,
			);
		}
	});

	it('non-strict tools never publish additionalProperties: false', () => {
		for (const tool of TOOLS) {
			if (STRICT_RUNTIME_TOOLS.has(tool.name)) continue;
			expect(
				(tool.inputSchema as Record<string, unknown>).additionalProperties,
				`${tool.name} unexpectedly carries additionalProperties:false`,
			).not.toBe(false);
		}
	});

	it('properties include descriptions from .describe()', () => {
		const spf = TOOLS.find((t) => t.name === 'check_spf')!;
		const domainProp = spf.inputSchema.properties.domain as Record<string, unknown>;
		expect(domainProp.description).toBeTruthy();
	});
});
