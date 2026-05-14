// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for the pure WHOIS response parser.
 * Layer: Unit. Node env, real fs access for fixtures.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

import { parseWhoisResponse, parseIanaReferral } from '../whois';

const FIXTURE_DIR = join(import.meta.dirname, 'fixtures/whois');
const fixture = (name: string) => readFileSync(join(FIXTURE_DIR, name), 'utf8');

describe('parseWhoisResponse', () => {
	it('extracts registrar from Verisign thin .com response (leading whitespace)', () => {
		const result = parseWhoisResponse(fixture('registry-google.com.txt'));
		expect(result.registrar).toBe('MarkMonitor Inc.');
	});

	it('extracts registrar from .me ICANN-template response', () => {
		const result = parseWhoisResponse(fixture('registry-google.me.txt'));
		expect(result.registrar).toBe('MarkMonitor Inc.');
	});

	it('extracts registrar from .co response', () => {
		const result = parseWhoisResponse(fixture('registry-google.co.txt'));
		expect(result.registrar).toBe('MarkMonitor, Inc.');
	});

	it('extracts registrar from .io response', () => {
		const result = parseWhoisResponse(fixture('registry-google.io.txt'));
		expect(result.registrar).toBe('MarkMonitor Inc.');
	});

	it('extracts registrar from .sh response', () => {
		const result = parseWhoisResponse(fixture('registry-google.sh.txt'));
		expect(result.registrar).toBe('MarkMonitor Inc.');
	});

	it('extracts registrar from .us response', () => {
		const result = parseWhoisResponse(fixture('registry-google.us.txt'));
		expect(result.registrar).toBe('MarkMonitor, Inc.');
	});

	it('returns redacted=true for DENIC .de privacy-protected response', () => {
		const result = parseWhoisResponse(fixture('registry-google.de.txt'));
		expect(result.registrar).toBeNull();
		expect(result.redacted).toBe(true);
	});

	it('returns notFound=true for "No match" response', () => {
		const result = parseWhoisResponse(fixture('registry-notfound.com.txt'));
		expect(result.registrar).toBeNull();
		expect(result.notFound).toBe(true);
	});

	it('does not match field names embedded in URLs or TOS boilerplate', () => {
		const noise = `
% Terms apply. Registrar must comply with ICANN policies.
% See https://example.com/registrar-info for details.
Domain: example.com
Status: active
`;
		expect(parseWhoisResponse(noise).registrar).toBeNull();
	});

	it('prefers "Registrar:" over "Sponsoring Registrar:" when both present', () => {
		const synthetic = `
Sponsoring Registrar: OldRegistrar Co.
Registrar: NewRegistrar Inc.
`;
		expect(parseWhoisResponse(synthetic).registrar).toBe('NewRegistrar Inc.');
	});

	it('falls back to "Sponsoring Registrar:" when "Registrar:" absent', () => {
		const synthetic = `Domain: example.com\nSponsoring Registrar: SomeReg Ltd.\nStatus: active\n`;
		expect(parseWhoisResponse(synthetic).registrar).toBe('SomeReg Ltd.');
	});

	it('strips trailing whitespace and CR characters from registrar value', () => {
		const synthetic = 'Registrar: TrimmedReg, Inc.   \r\n';
		expect(parseWhoisResponse(synthetic).registrar).toBe('TrimmedReg, Inc.');
	});

	it('handles empty input gracefully', () => {
		const result = parseWhoisResponse('');
		expect(result.registrar).toBeNull();
		expect(result.notFound).toBe(false);
		expect(result.redacted).toBe(false);
	});

	it('truncates parsing at MAX_RESPONSE_BYTES to defend against floods', () => {
		const filler = '#'.repeat(70_000);
		const flood = `${filler}\nRegistrar: ShouldNotBeFound\n`;
		expect(parseWhoisResponse(flood).registrar).toBeNull();
	});
});

describe('parseIanaReferral', () => {
	it('extracts whois server from .me IANA response', () => {
		expect(parseIanaReferral(fixture('iana-me.txt'))).toBe('whois.nic.me');
	});

	it('extracts whois server from .com IANA response', () => {
		expect(parseIanaReferral(fixture('iana-com.txt'))).toBe('whois.verisign-grs.com');
	});

	it('extracts whois server from .de IANA response', () => {
		expect(parseIanaReferral(fixture('iana-de.txt'))).toBe('whois.denic.de');
	});

	it('extracts whois server from .io IANA response', () => {
		expect(parseIanaReferral(fixture('iana-io.txt'))).toBe('whois.nic.io');
	});

	it('extracts whois server from .co IANA response', () => {
		expect(parseIanaReferral(fixture('iana-co.txt'))).toBe('whois.registry.co');
	});

	it('extracts whois server from .sh IANA response', () => {
		expect(parseIanaReferral(fixture('iana-sh.txt'))).toBe('whois.nic.sh');
	});

	it('extracts whois server from .us IANA response', () => {
		expect(parseIanaReferral(fixture('iana-us.txt'))).toBe('whois.nic.us');
	});

	it('returns null for "no data" IANA response', () => {
		expect(parseIanaReferral(fixture('iana-notfound.txt'))).toBeNull();
	});

	it('returns null for empty input', () => {
		expect(parseIanaReferral('')).toBeNull();
	});

	it('returns null if "whois:" key absent', () => {
		expect(parseIanaReferral('domain: TEST\nstatus: ACTIVE\n')).toBeNull();
	});

	it('strips whitespace around hostname', () => {
		expect(parseIanaReferral('whois:   whois.example.com   \n')).toBe('whois.example.com');
	});

	it('does not match lines where "whois" appears mid-sentence', () => {
		const noise = 'See the whois: documentation at example.com for details.\n';
		expect(parseIanaReferral(noise)).toBeNull();
	});
});
