import { describe, expect, it } from 'vitest';
import {
	extractAndValidateDomain,
	extractDkimSelector,
	extractExplainFindingArgs,
	extractFormat,
	normalizeToolName,
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

	it('extractDkimSelector normalizes valid selectors and rejects invalid ones', () => {
		expect(extractDkimSelector({ selector: ' Selector-1 ' })).toBe('selector-1');
		expect(extractDkimSelector({})).toBeUndefined();
		expect(() => extractDkimSelector({ selector: 'bad@selector' })).toThrow('Invalid DKIM selector');
	});

	it('extractExplainFindingArgs requires checkType and status', () => {
		expect(extractExplainFindingArgs({ checkType: 'SPF', status: 'fail', details: 'detail' })).toEqual({
			checkType: 'SPF',
			status: 'fail',
			details: 'detail',
		});
		expect(() => extractExplainFindingArgs({ checkType: 'SPF' })).toThrow('Missing required parameters: checkType and status');
	});

	it('extractFormat returns valid formats and rejects invalid ones', () => {
		expect(extractFormat({ format: 'full' })).toBe('full');
		expect(extractFormat({ format: 'compact' })).toBe('compact');
		expect(extractFormat({ format: 'COMPACT' })).toBe('compact');
		expect(extractFormat({ format: ' Full ' })).toBe('full');
		expect(extractFormat({})).toBeUndefined();
		expect(extractFormat({ format: null })).toBeUndefined();
		expect(() => extractFormat({ format: 'verbose' })).toThrow('Invalid format');
		expect(() => extractFormat({ format: 42 })).toThrow('Invalid format: must be a string');
	});
});