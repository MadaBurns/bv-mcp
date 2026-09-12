import { describe, it, expect } from 'vitest';
import { classifyRegistrarFamily } from '../src/lib/registrar-identity';

describe('classifyRegistrarFamily', () => {
	it('returns the canonical family for a known registrar', () => {
		expect(classifyRegistrarFamily('MarkMonitor Inc.')).toBe('markmonitor');
		expect(classifyRegistrarFamily('GoDaddy.com, LLC')).toBe('godaddy');
		expect(classifyRegistrarFamily('CSC Corporate Domains, Inc.')).toBe('corporate domains registrar');
		expect(classifyRegistrarFamily('CSC Global')).toBe('corporate domains registrar');
		expect(classifyRegistrarFamily('Corporation Service Company (Aust) Pty Ltd')).toBe('corporate domains registrar');
	});

	it('returns null for an unknown registrar', () => {
		expect(classifyRegistrarFamily('Some Tiny Registrar LLC')).toBeNull();
	});

	it('returns null for redacted / unknown strings', () => {
		expect(classifyRegistrarFamily('REDACTED FOR PRIVACY')).toBeNull();
		expect(classifyRegistrarFamily('')).toBeNull();
		expect(classifyRegistrarFamily(null)).toBeNull();
		expect(classifyRegistrarFamily(undefined)).toBeNull();
	});

	it('matches the registrar bare website host via raw pattern', () => {
		expect(classifyRegistrarFamily('cscglobal.com')).toBe('corporate domains registrar');
	});
});
