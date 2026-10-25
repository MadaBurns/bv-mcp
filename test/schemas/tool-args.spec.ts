import { describe, it, expect } from 'vitest';
import {
	BaseDomainArgs,
	ScanDomainArgs,
	CheckDkimArgs,
	GenerateArgs,
	ExplainFindingArgs,
	CompareBaselineArgs,
	GetBenchmarkArgs,
	GetProviderInsightsArgs,
	QuerySigninsArgs,
	QueryUalArgs,
	GetCaPoliciesArgs,
	AssessCoverageArgs,
	TOOL_SCHEMA_MAP,
} from '../../src/schemas/tool-args';
import { TOOLS } from '../../src/schemas/tool-definitions';

describe('BaseDomainArgs', () => {
	it('accepts domain only', () => {
		const result = BaseDomainArgs.parse({ domain: 'example.com' });
		expect(result.domain).toBe('example.com');
	});
	it('accepts domain + format', () => {
		const result = BaseDomainArgs.parse({ domain: 'example.com', format: 'compact' });
		expect(result.format).toBe('compact');
	});
	it('rejects missing domain', () => {
		expect(() => BaseDomainArgs.parse({})).toThrow();
	});
	it('rejects unknown properties (strict schema)', () => {
		const result = BaseDomainArgs.safeParse({ domain: 'example.com', extra: true });
		expect(result.success).toBe(false);
		expect(result.error?.issues[0]).toMatchObject({ code: 'unrecognized_keys', keys: ['extra'], path: [] });
	});
});

describe('validateToolArgs — unknown-argument error', () => {
	it('names every unknown top-level key under the allowlisted "Invalid" prefix', async () => {
		const { validateToolArgs } = await import('../../src/handlers/tool-args');
		expect(() => validateToolArgs('check_spf', { domain: 'example.com', extra: true, other: 1 })).toThrow(
			'Invalid request: unknown argument(s): extra, other',
		);
	});

	it('path-qualifies an unknown key inside the nested compare_baseline policy object', async () => {
		const { validateToolArgs } = await import('../../src/handlers/tool-args');
		expect(() => validateToolArgs('compare_baseline', { domain: 'example.com', baseline: { require_spf: true, bogus: 1 } })).toThrow(
			'Invalid request: unknown argument(s): baseline.bogus',
		);
	});

	it('reaches the client verbatim through sanitizeErrorMessage (not the generic fallback)', async () => {
		const { validateToolArgs } = await import('../../src/handlers/tool-args');
		const { sanitizeErrorMessage } = await import('../../src/lib/json-rpc');
		let caught: unknown;
		try {
			validateToolArgs('scan_domain', { domain: 'example.com', domian: 'typo.example' });
		} catch (err) {
			caught = err;
		}
		expect(sanitizeErrorMessage(caught, 'FALLBACK')).toBe('Invalid request: unknown argument(s): domian');
	});

	it('accepts format on tools that previously relied on passthrough for it', async () => {
		const { validateToolArgs } = await import('../../src/handlers/tool-args');
		const cases: Array<[string, Record<string, unknown>]> = [
			['discover_brand_domains_status', { operationId: 'op_1' }],
			['discover_brand_domains_findings', { operationId: 'op_1' }],
			['brand_audit_status', { auditId: 'audit_1' }],
			['brand_audit_get_report', { auditId: 'audit_1' }],
			['list_brand_audit_watches', {}],
			['register_brand_audit_watch', { domain: 'example.com', interval: 'daily' }],
			['delete_brand_audit_watch', { watchId: 'watch_1' }],
			['query_signins', { ms_tenant_id: 'tenant' }],
			['query_ual', { ms_tenant_id: 'tenant' }],
			['get_ca_policies', { ms_tenant_id: 'tenant' }],
			['assess_coverage', { ms_tenant_id: 'tenant' }],
		];
		for (const [tool, args] of cases) {
			expect(validateToolArgs(tool, { ...args, format: 'compact' }).format, tool).toBe('compact');
		}
	});
});

describe('ScanDomainArgs', () => {
	it('accepts all params', () => {
		const result = ScanDomainArgs.parse({
			domain: 'example.com',
			profile: 'enterprise_mail',
			force_refresh: true,
			format: 'full',
		});
		expect(result.profile).toBe('enterprise_mail');
		expect(result.force_refresh).toBe(true);
	});
	it('rejects invalid profile', () => {
		expect(() => ScanDomainArgs.parse({ domain: 'example.com', profile: 'bad' })).toThrow();
	});
	it('rejects non-boolean force_refresh', () => {
		expect(() => ScanDomainArgs.parse({ domain: 'example.com', force_refresh: 'yes' })).toThrow();
	});
});

describe('CheckDkimArgs', () => {
	it('accepts domain + selector', () => {
		const result = CheckDkimArgs.parse({ domain: 'example.com', selector: 'google' });
		expect(result.selector).toBe('google');
	});
	it('accepts without selector', () => {
		const result = CheckDkimArgs.parse({ domain: 'example.com' });
		expect(result.selector).toBeUndefined();
	});
});

describe('GenerateArgs (artifact=spf_record)', () => {
	it('accepts include_providers array', () => {
		const result = GenerateArgs.parse({ artifact: 'spf_record', domain: 'example.com', include_providers: ['google', 'sendgrid'] });
		expect(result.include_providers).toEqual(['google', 'sendgrid']);
	});
	it('rejects > 15 providers', () => {
		const providers = Array.from({ length: 16 }, (_, i) => `p${i}`);
		expect(() => GenerateArgs.parse({ artifact: 'spf_record', domain: 'example.com', include_providers: providers })).toThrow();
	});
});

describe('GenerateArgs (artifact=mta_sts_policy)', () => {
	it('rejects mx_hosts with whitespace', () => {
		expect(() => GenerateArgs.parse({ artifact: 'mta_sts_policy', domain: 'example.com', mx_hosts: ['host with space'] })).toThrow();
	});
	it('rejects > 20 hosts', () => {
		const hosts = Array.from({ length: 21 }, (_, i) => `mx${i}.example.com`);
		expect(() => GenerateArgs.parse({ artifact: 'mta_sts_policy', domain: 'example.com', mx_hosts: hosts })).toThrow();
	});
});

describe('ExplainFindingArgs', () => {
	it('accepts required fields', () => {
		const result = ExplainFindingArgs.parse({ checkType: 'SPF', status: 'fail' });
		expect(result.checkType).toBe('SPF');
	});
	it('accepts optional details', () => {
		const result = ExplainFindingArgs.parse({ checkType: 'SPF', status: 'fail', details: 'some detail' });
		expect(result.details).toBe('some detail');
	});
	it('rejects missing checkType', () => {
		expect(() => ExplainFindingArgs.parse({ status: 'fail' })).toThrow();
	});
	it('rejects checkType over 100 chars', () => {
		expect(() => ExplainFindingArgs.parse({ checkType: 'a'.repeat(101), status: 'fail' })).toThrow();
	});
});

describe('CompareBaselineArgs', () => {
	it('accepts baseline with grade', () => {
		const result = CompareBaselineArgs.parse({
			domain: 'example.com',
			baseline: { grade: 'B+', require_spf: true },
		});
		expect(result.baseline.grade).toBe('B+');
		expect(result.baseline.require_spf).toBe(true);
	});
	it('rejects score > 100', () => {
		expect(() => CompareBaselineArgs.parse({
			domain: 'example.com',
			baseline: { score: 101 },
		})).toThrow();
	});
	it('rejects non-integer max_critical_findings', () => {
		expect(() => CompareBaselineArgs.parse({
			domain: 'example.com',
			baseline: { max_critical_findings: 1.5 },
		})).toThrow();
	});
});

describe('GetBenchmarkArgs', () => {
	it('accepts empty (all optional)', () => {
		const result = GetBenchmarkArgs.parse({});
		expect(result).toBeDefined();
	});
	it('accepts profile without auto', () => {
		const result = GetBenchmarkArgs.parse({ profile: 'mail_enabled' });
		expect(result.profile).toBe('mail_enabled');
	});
	it('rejects auto profile', () => {
		expect(() => GetBenchmarkArgs.parse({ profile: 'auto' })).toThrow();
	});
});

describe('GetProviderInsightsArgs', () => {
	it('requires provider', () => {
		expect(() => GetProviderInsightsArgs.parse({})).toThrow();
	});
	it('accepts provider + profile', () => {
		const result = GetProviderInsightsArgs.parse({ provider: 'google workspace', profile: 'enterprise_mail' });
		expect(result.provider).toBe('google workspace');
	});
	// M2: cap unbounded provider field at 200 chars to match generate_dkim_config
	// and avoid feeding near-10KB strings to downstream regex/string ops.
	it('rejects provider > 200 chars', () => {
		expect(() => GetProviderInsightsArgs.parse({ provider: 'x'.repeat(201) })).toThrow();
	});
	it('accepts provider exactly 200 chars', () => {
		expect(() => GetProviderInsightsArgs.parse({ provider: 'x'.repeat(200) })).not.toThrow();
	});
});

describe('QuerySigninsArgs', () => {
	it('accepts valid ms_tenant_id', () => {
		const result = QuerySigninsArgs.parse({ ms_tenant_id: 'abc123.onmicrosoft.com' });
		expect(result.ms_tenant_id).toBe('abc123.onmicrosoft.com');
	});
	it('accepts all optional fields', () => {
		const result = QuerySigninsArgs.parse({
			ms_tenant_id: 'abc123',
			user_principal_name: 'user@corp.com',
			failures_only: true,
			since_hours: 48,
		});
		expect(result.failures_only).toBe(true);
		expect(result.since_hours).toBe(48);
	});
	it('rejects missing ms_tenant_id', () => {
		expect(() => QuerySigninsArgs.parse({})).toThrow();
	});
	it('rejects since_hours out of range', () => {
		expect(() => QuerySigninsArgs.parse({ ms_tenant_id: 'x', since_hours: 721 })).toThrow();
	});
});

describe('QueryUalArgs', () => {
	it('accepts valid ms_tenant_id', () => {
		const result = QueryUalArgs.parse({ ms_tenant_id: 'abc123' });
		expect(result.ms_tenant_id).toBe('abc123');
	});
	it('accepts all optional fields', () => {
		const result = QueryUalArgs.parse({
			ms_tenant_id: 'abc123',
			operation: 'MailItemsAccessed',
			user_principal_name: 'user@corp.com',
			since_hours: 6,
		});
		expect(result.operation).toBe('MailItemsAccessed');
	});
	it('rejects missing ms_tenant_id', () => {
		expect(() => QueryUalArgs.parse({})).toThrow();
	});
});

describe('GetCaPoliciesArgs', () => {
	it('accepts valid ms_tenant_id', () => {
		const result = GetCaPoliciesArgs.parse({ ms_tenant_id: 'tenant-guid-here' });
		expect(result.ms_tenant_id).toBe('tenant-guid-here');
	});
	it('rejects missing ms_tenant_id', () => {
		expect(() => GetCaPoliciesArgs.parse({})).toThrow();
	});
});

describe('AssessCoverageArgs', () => {
	it('accepts valid ms_tenant_id', () => {
		const result = AssessCoverageArgs.parse({ ms_tenant_id: 'tenant-guid-here' });
		expect(result.ms_tenant_id).toBe('tenant-guid-here');
	});
	it('rejects missing ms_tenant_id', () => {
		expect(() => AssessCoverageArgs.parse({})).toThrow();
	});
});

describe('TOOL_SCHEMA_MAP', () => {
	it('has exactly one schema per registered tool', () => {
		// Derived from the tool registry — catches a tool added without a schema
		// (or an orphan schema) rather than asserting a hardcoded count.
		expect(Object.keys(TOOL_SCHEMA_MAP).sort()).toEqual(TOOLS.map((t) => t.name).sort());
	});
	it('all values are Zod schemas', () => {
		for (const schema of Object.values(TOOL_SCHEMA_MAP)) {
			expect(typeof schema.parse).toBe('function');
			expect(typeof schema.safeParse).toBe('function');
		}
	});
});
