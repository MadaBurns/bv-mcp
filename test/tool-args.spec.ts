import { describe, expect, it } from 'vitest';
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

	it('validateToolArgs passes through unknown tool names', () => {
		const args = { foo: 'bar' };
		expect(validateToolArgs('unknown_tool', args)).toBe(args);
	});
});
