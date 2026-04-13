import { describe, it, expect } from 'vitest';
import {
	BaseDomainArgs,
	ScanDomainArgs,
	CheckDkimArgs,
	GenerateSpfArgs,
	GenerateMtaStsArgs,
	ExplainFindingArgs,
	CompareBaselineArgs,
	GetBenchmarkArgs,
	GetProviderInsightsArgs,
	TOOL_SCHEMA_MAP,
} from '../../src/schemas/tool-args';

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
	it('passes through unknown properties', () => {
		const result = BaseDomainArgs.parse({ domain: 'example.com', extra: true });
		expect((result as Record<string, unknown>).extra).toBe(true);
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

describe('GenerateSpfArgs', () => {
	it('accepts include_providers array', () => {
		const result = GenerateSpfArgs.parse({ domain: 'example.com', include_providers: ['google', 'sendgrid'] });
		expect(result.include_providers).toEqual(['google', 'sendgrid']);
	});
	it('rejects > 15 providers', () => {
		const providers = Array.from({ length: 16 }, (_, i) => `p${i}`);
		expect(() => GenerateSpfArgs.parse({ domain: 'example.com', include_providers: providers })).toThrow();
	});
});

describe('GenerateMtaStsArgs', () => {
	it('rejects mx_hosts with whitespace', () => {
		expect(() => GenerateMtaStsArgs.parse({ domain: 'example.com', mx_hosts: ['host with space'] })).toThrow();
	});
	it('rejects > 20 hosts', () => {
		const hosts = Array.from({ length: 21 }, (_, i) => `mx${i}.example.com`);
		expect(() => GenerateMtaStsArgs.parse({ domain: 'example.com', mx_hosts: hosts })).toThrow();
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
});

describe('TOOL_SCHEMA_MAP', () => {
	it('has 38 tools', () => {
		expect(Object.keys(TOOL_SCHEMA_MAP)).toHaveLength(51);
	});
	it('all values are Zod schemas', () => {
		for (const schema of Object.values(TOOL_SCHEMA_MAP)) {
			expect(typeof schema.parse).toBe('function');
			expect(typeof schema.safeParse).toBe('function');
		}
	});
});
