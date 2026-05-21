// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';

import {
	normalizeRegistrarIdentity,
	sameRegistrarFamily,
	type RegistrarIdentity,
} from '../src/lib/registrar-identity';

describe('registrar identity matching', () => {
	it('matches the same IANA registrar ID even when registrar names differ', () => {
		const left: RegistrarIdentity = { name: 'CSC Corporate Domains, Inc.', ianaId: '299' };
		const right: RegistrarIdentity = { name: 'Corporation Service Company', ianaId: '299' };

		expect(sameRegistrarFamily(left, right)).toBe(true);
	});

	it('does not match unrelated registrars by weak suffix or token overlap', () => {
		expect(
			sameRegistrarFamily(
				{ name: 'GoDaddy Corporate Domains, LLC', ianaId: '146' },
				{ name: 'CSC Corporate Domains, Inc.', ianaId: '299' },
			),
		).toBe(false);

		expect(
			sameRegistrarFamily(
				{ name: 'Example Consumer Domains LLC' },
				{ name: 'Example Corporate Domains Inc.' },
			),
		).toBe(false);
	});

	it('does not match known registrar names as substrings inside unrelated names', () => {
		expect(sameRegistrarFamily({ name: 'Ugandi Registrar LLC' }, { name: 'Gandi SAS' })).toBe(false);
		expect(sameRegistrarFamily({ name: 'Not Cloudflare Domains LLC' }, { name: 'Cloudflare Registrar LLC' })).toBe(false);
	});

	it('strips corporate suffixes without deleting meaningful tokens', () => {
		expect(normalizeRegistrarIdentity('CSC Corporate Domains, Inc.')).toBe('csc corporate domains');
	});

	it('matches CSC regional WHOIS display variants as the same registrar family', () => {
		const target: RegistrarIdentity = { name: 'CSC Corporate Domains, Inc.' };
		for (const variant of [
			'CSC Corporate Domains, Inc. ( https://nic.at/registrar/533 )',
			'Name: CSC CORPORATE DOMAINS INC.',
			'Name:\tCSC Corporate Domains, Inc.',
			'CSC Corporate Domains (Canada) Company',
			'CSC Digital Brand Service, Inc',
			'CSC Digital Brand Services Malaysia Sdn Bhd',
			'CSC Corp Domains',
			'Corporation Service Company',
		]) {
			expect(sameRegistrarFamily({ name: variant }, target), variant).toBe(true);
		}
		expect(sameRegistrarFamily({ name: 'REG-IPMIRROR' }, target)).toBe(false);
	});

	// Regression: 2026-05 CSC registrar-family fixture verification surfaced false-positive
	// shadowIt findings on regional-alpha.example.com, regional-beta.example.com, regional-gamma.example.com because
	// the registrar display string contained "Corporation Service Company (Aust) Pty Ltd"
	// — CSC's Australian arm — and the family detector did not collapse it to CSC.
	it('matches CSC global regional subsidiary registrar strings (Aust Pty Ltd, Digital Brand Services, CSC Global)', () => {
		const target: RegistrarIdentity = { name: 'CSC Corporate Domains, Inc.' };
		for (const variant of [
			'Corporation Service Company (Aust) Pty Ltd',
			'Corporation Service Company, LLC',
			'CSC Digital Brand Services Malaysia Sdn Bhd',
			'CSC Digital Brand Services, Inc.',
			'CSC Global',
			'cscglobal.com',
			'https://cscglobal.com',
		]) {
			expect(sameRegistrarFamily({ name: variant }, target), variant).toBe(true);
		}
	});

	it('groups two CSC-subsidiary candidates into the same registrar family (consolidated, not shadowIt)', () => {
		// Two regional CSC subsidiaries observed verbatim in production WHOIS
		// for regional-alpha.example.com, regional-beta.example.com, regional-gamma.example.com, etc.
		const fordAu: RegistrarIdentity = { name: 'Corporation Service Company (Aust) Pty Ltd' };
		const cscMalaysia: RegistrarIdentity = { name: 'CSC Digital Brand Services Malaysia Sdn Bhd' };
		const cscUs: RegistrarIdentity = { name: 'CSC Corporate Domains, Inc.' };
		// All pairwise comparisons must be same-family — this is the
		// user-visible bug: any pair returning false drives an off-primary-registrar
		// inference and a shadowIt finding in the brand-audit report.
		expect(sameRegistrarFamily(fordAu, cscMalaysia)).toBe(true);
		expect(sameRegistrarFamily(fordAu, cscUs)).toBe(true);
		expect(sameRegistrarFamily(cscMalaysia, cscUs)).toBe(true);
	});

	it('falls back to registrar-family names when registry-specific registrar IDs differ', () => {
		expect(
			sameRegistrarFamily(
				{ name: 'CSC Corporate Domains, Inc.', ianaId: '9999' },
				{ name: 'CSC Corporate Domains, Inc.', ianaId: '299' },
			),
		).toBe(true);

		expect(
			sameRegistrarFamily(
				{ name: 'REG-IPMIRROR', ianaId: '9999' },
				{ name: 'CSC Corporate Domains, Inc.', ianaId: '299' },
			),
		).toBe(false);
	});

	it('does not treat unavailable registrar labels as registrar families', () => {
		for (const label of [
			'Registrar lookup failed',
			'Registrar unavailable',
			'Registrar redacted by registry',
			'Registrar not found in registry',
		]) {
			expect(normalizeRegistrarIdentity(label)).toBeNull();
			expect(sameRegistrarFamily({ name: label }, { name: label })).toBe(false);
		}
	});
});
