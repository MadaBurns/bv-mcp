import { describe, it, expect } from 'vitest';
import {
	DomainSchema,
	SessionIdSchema,
	DkimSelectorSchema,
	ToolNameSchema,
	SafeLabelSchema,
	ProfileSchema,
	BenchmarkProfileSchema,
	FormatSchema,
	RecordTypeSchema,
	GradeSchema,
	TierSchema,
	DmarcPolicySchema,
	ExplainStatusSchema,
} from '../../src/schemas/primitives';

describe('DomainSchema', () => {
	it('accepts valid domain', () => {
		expect(DomainSchema.parse('example.com')).toBe('example.com');
	});
	it('rejects empty string', () => {
		expect(() => DomainSchema.parse('')).toThrow();
	});
	it('rejects string over 253 chars', () => {
		expect(() => DomainSchema.parse('a'.repeat(254))).toThrow();
	});
});

describe('SessionIdSchema', () => {
	it('accepts 64 hex chars', () => {
		const id = 'a'.repeat(64);
		expect(SessionIdSchema.parse(id)).toBe(id);
	});
	it('rejects 63 chars', () => {
		expect(() => SessionIdSchema.parse('a'.repeat(63))).toThrow();
	});
	it('rejects uppercase hex', () => {
		expect(() => SessionIdSchema.parse('A'.repeat(64))).toThrow();
	});
});

describe('DkimSelectorSchema', () => {
	it('accepts valid selector', () => {
		expect(DkimSelectorSchema.parse('google')).toBe('google');
	});
	it('accepts selector with hyphens', () => {
		expect(DkimSelectorSchema.parse('s1-2024')).toBe('s1-2024');
	});
	it('rejects selector starting with hyphen', () => {
		expect(() => DkimSelectorSchema.parse('-invalid')).toThrow();
	});
	it('rejects selector over 63 chars', () => {
		expect(() => DkimSelectorSchema.parse('a'.repeat(64))).toThrow();
	});
});

describe('ToolNameSchema', () => {
	it('accepts valid tool name', () => {
		expect(ToolNameSchema.parse('check_spf')).toBe('check_spf');
	});
	it('rejects names with uppercase', () => {
		expect(() => ToolNameSchema.parse('Check_SPF')).toThrow();
	});
	it('rejects names over 30 chars', () => {
		expect(() => ToolNameSchema.parse('a'.repeat(31))).toThrow();
	});
});

describe('ProfileSchema', () => {
	it('accepts all valid profiles including auto', () => {
		for (const p of ['auto', 'mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal']) {
			expect(ProfileSchema.parse(p)).toBe(p);
		}
	});
	it('rejects invalid profile', () => {
		expect(() => ProfileSchema.parse('invalid')).toThrow();
	});
});

describe('BenchmarkProfileSchema', () => {
	it('rejects auto', () => {
		expect(() => BenchmarkProfileSchema.parse('auto')).toThrow();
	});
	it('accepts mail_enabled', () => {
		expect(BenchmarkProfileSchema.parse('mail_enabled')).toBe('mail_enabled');
	});
});

describe('FormatSchema', () => {
	it('accepts full and compact', () => {
		expect(FormatSchema.parse('full')).toBe('full');
		expect(FormatSchema.parse('compact')).toBe('compact');
	});
	it('rejects other strings', () => {
		expect(() => FormatSchema.parse('verbose')).toThrow();
	});
});

describe('GradeSchema', () => {
	it('accepts A+', () => {
		expect(GradeSchema.parse('A+')).toBe('A+');
	});
	it('accepts F', () => {
		expect(GradeSchema.parse('F')).toBe('F');
	});
});

describe('TierSchema', () => {
	it('accepts all tiers', () => {
		for (const t of ['free', 'agent', 'developer', 'enterprise', 'partner']) {
			expect(TierSchema.parse(t)).toBe(t);
		}
	});
});
