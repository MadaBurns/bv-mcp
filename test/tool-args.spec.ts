import { afterEach, describe, expect, it, vi } from 'vitest';
import {
	extractAndValidateDomain,
	extractDkimSelector,
	extractExplainFindingArgs,
	extractFormat,
	normalizeToolName,
	validateToolArgs,
} from '../src/handlers/tool-args';

describe('tool-args helpers', () => {
	it('normalizes tool aliases', () => {
		expect(normalizeToolName(' scan ')).toBe('scan_domain');
		expect(normalizeToolName('CHECK_SPF')).toBe('check_spf');
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

	describe('explain_finding rejection telemetry', () => {
		let logSpy: ReturnType<typeof vi.spyOn>;

		afterEach(() => {
			logSpy?.mockRestore();
		});

		it('emits a structured log event when explain_finding is rejected by Zod', () => {
			logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);

			expect(() =>
				validateToolArgs('explain_finding', { checkType: 'SPF', status: 'unexpected_value_xyz' }),
			).toThrow();

			const telemetryCall = logSpy.mock.calls.find((args) => {
				const msg = args[0];
				return typeof msg === 'string' && msg.includes('explain_finding_rejected');
			});
			expect(telemetryCall).toBeDefined();
			const payload = JSON.parse(telemetryCall![0] as string);
			expect(payload.result).toBe('explain_finding_rejected');
			expect(payload.tool).toBe('explain_finding');
			expect(payload.details.rejectedField).toBe('status');
			expect(payload.details.rejectedValue).toContain('unexpected_value_xyz');
			expect((payload.details.rejectedValue as string).length).toBeLessThanOrEqual(64);
		});

		it('truncates long or unusual rejected values', () => {
			logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);

			const longValue = 'x'.repeat(500);
			expect(() => validateToolArgs('explain_finding', { checkType: 'SPF', status: longValue })).toThrow();

			const telemetryCall = logSpy.mock.calls.find((args) => {
				const msg = args[0];
				return typeof msg === 'string' && msg.includes('explain_finding_rejected');
			});
			expect(telemetryCall).toBeDefined();
			const payload = JSON.parse(telemetryCall![0] as string);
			expect((payload.details.rejectedValue as string).length).toBeLessThanOrEqual(64);
		});

		it('does not emit telemetry for other tools when Zod rejects', () => {
			logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);

			expect(() => validateToolArgs('check_spf', {})).toThrow();

			const telemetryCall = logSpy.mock.calls.find((args) => {
				const msg = args[0];
				return typeof msg === 'string' && msg.includes('explain_finding_rejected');
			});
			expect(telemetryCall).toBeUndefined();
		});
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
		expect(() => validateToolArgs('analyze_drift', { domain: 'example.com' })).toThrow('Missing required parameters');
	});

	it('validates generate_rollout_plan args', () => {
		const result = validateToolArgs('generate_rollout_plan', { domain: 'example.com' });
		expect(result).toHaveProperty('domain');
		const full = validateToolArgs('generate_rollout_plan', {
			domain: 'example.com',
			target_policy: 'quarantine',
			timeline: 'aggressive',
		});
		expect(full).toHaveProperty('target_policy', 'quarantine');
		expect(full).toHaveProperty('timeline', 'aggressive');
		expect(() => validateToolArgs('generate_rollout_plan', {
			domain: 'example.com',
			timeline: 'invalid',
		})).toThrow('Invalid');
	});
});
