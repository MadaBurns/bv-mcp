// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { analyzeTlsaRecords, classifyDanePresence } from '../src/tools/dane-analysis';

describe('analyzeTlsaRecords', () => {
	it('should return info finding for valid DANE-EE record with DNSSEC', () => {
		const records = ['3 1 1 aabbccdd'];
		const findings = analyzeTlsaRecords(records, '_25._tcp.mx.example.com', true);
		const infoFinding = findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.title).toContain('DANE TLSA configured');
		expect(infoFinding!.title).toContain('_25._tcp.mx.example.com');
	});

	it('should return high finding for DANE-EE without DNSSEC', () => {
		const records = ['3 1 1 aabbccdd'];
		const findings = analyzeTlsaRecords(records, '_25._tcp.mx.example.com', false);
		const highFinding = findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.title).toBe('DANE without DNSSEC');
		expect(highFinding!.detail).toContain('DNSSEC is not validated');
	});

	it('should return high finding for DANE-TA without DNSSEC', () => {
		const records = ['2 0 1 aabbccdd'];
		const findings = analyzeTlsaRecords(records, '_443._tcp.example.com', false);
		const highFinding = findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.title).toBe('DANE without DNSSEC');
	});

	it('should not flag PKIX-TA (usage 0) without DNSSEC as high', () => {
		const records = ['0 1 1 aabbccdd'];
		const findings = analyzeTlsaRecords(records, '_25._tcp.mx.example.com', false);
		const highFinding = findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeUndefined();
		const infoFinding = findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
	});

	it('should return medium finding for invalid usage value', () => {
		const records = ['5 1 1 aabbccdd'];
		const findings = analyzeTlsaRecords(records, '_25._tcp.mx.example.com', true);
		const mediumFinding = findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toBe('Invalid TLSA usage');
		expect(mediumFinding!.detail).toContain('usage value 5');
	});

	it('should return medium finding for invalid selector value', () => {
		const records = ['3 5 1 aabbccdd'];
		const findings = analyzeTlsaRecords(records, '_25._tcp.mx.example.com', true);
		const mediumFinding = findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toBe('Invalid TLSA selector');
		expect(mediumFinding!.detail).toContain('selector value 5');
	});

	it('should return medium finding for invalid matching type', () => {
		const records = ['3 1 5 aabbccdd'];
		const findings = analyzeTlsaRecords(records, '_25._tcp.mx.example.com', true);
		const mediumFinding = findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toBe('Invalid TLSA matching type');
		expect(mediumFinding!.detail).toContain('matching type 5');
	});

	it('should return low finding for full certificate matching (type 0)', () => {
		const records = ['3 1 0 aabbccdd'];
		const findings = analyzeTlsaRecords(records, '_25._tcp.mx.example.com', true);
		const lowFinding = findings.find((f) => f.severity === 'low');
		expect(lowFinding).toBeDefined();
		expect(lowFinding!.title).toBe('TLSA uses full certificate matching');
		expect(lowFinding!.detail).toContain('SHA-256');
	});

	it('should return medium finding for malformed TLSA record', () => {
		const records = ['garbage'];
		const findings = analyzeTlsaRecords(records, '_25._tcp.mx.example.com', true);
		const mediumFinding = findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toBe('Malformed TLSA record');
	});

	it('should handle multiple records with mixed validity', () => {
		const records = ['3 1 1 aabbccdd', '5 0 0 invalid'];
		const findings = analyzeTlsaRecords(records, '_25._tcp.mx.example.com', true);
		expect(findings.length).toBeGreaterThanOrEqual(2);
		// First record produces info finding
		const infoFinding = findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
		// Second record produces medium finding for invalid usage
		const mediumFinding = findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
	});

	it('should handle hex wire format TLSA records', () => {
		// Hex wire format: usage=3 selector=1 matchingType=1 + cert data
		const records = ['\\# 35 03 01 01 aa bb cc dd'];
		const findings = analyzeTlsaRecords(records, '_25._tcp.mx.example.com', true);
		const infoFinding = findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.title).toContain('DANE TLSA configured');
	});
});

describe('classifyDanePresence', () => {
	it('should return medium finding when no MX TLSA', () => {
		const findings = classifyDanePresence(false, true);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('medium');
		expect(findings[0].title).toContain('No DANE TLSA for MX');
	});

	it('should return low finding when no HTTPS TLSA', () => {
		const findings = classifyDanePresence(true, false);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('low');
		expect(findings[0].title).toContain('No DANE TLSA for HTTPS');
	});

	it('should return both findings when neither MX nor HTTPS TLSA', () => {
		const findings = classifyDanePresence(false, false);
		expect(findings).toHaveLength(2);
		const severities = findings.map((f) => f.severity);
		expect(severities).toContain('medium');
		expect(severities).toContain('low');
	});

	it('should return empty when both have TLSA', () => {
		const findings = classifyDanePresence(true, true);
		expect(findings).toHaveLength(0);
	});
});
