// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for the pure WHOIS response parser.
 * Layer: Unit. Node env, real fs access for fixtures.
 */

import { describe, it, expect } from 'vitest';

import { parseWhoisResponse, parseIanaReferral } from '../whois';
import { WHOIS_FIXTURES } from './fixtures/whois';

// Fixtures live as .txt files for human inspection + are also baked into a TS
// module via packages/dns-checks/scripts/regen-whois-fixtures.mjs so the parser
// tests run pool-agnostic (workers runtime has no fs access to the workspace).
const fixture = (filename: string): string => {
	const key = filename.replace(/[-.]/g, '_') as keyof typeof WHOIS_FIXTURES;
	const value = WHOIS_FIXTURES[key];
	if (!value) throw new Error(`Unknown fixture: ${filename}`);
	return value;
};

describe('parseWhoisResponse', () => {
	it('extracts registrar from Verisign thin .com response (leading whitespace)', () => {
		const result = parseWhoisResponse(fixture('registry-example.com.txt'));
		expect(result.registrar).toBe('Example Registrar Inc.');
	});

	it('extracts registrar from .me ICANN-template response', () => {
		const result = parseWhoisResponse(fixture('registry-example.me.txt'));
		expect(result.registrar).toBe('Example Registrar Inc.');
	});

	it('extracts registrar from .co response', () => {
		const result = parseWhoisResponse(fixture('registry-example.co.txt'));
		expect(result.registrar).toBe('Example Registrar, Inc.');
	});

	it('extracts registrar from .io response', () => {
		const result = parseWhoisResponse(fixture('registry-example.io.txt'));
		expect(result.registrar).toBe('Example Registrar Inc.');
	});

	it('extracts registrar from .sh response', () => {
		const result = parseWhoisResponse(fixture('registry-example.sh.txt'));
		expect(result.registrar).toBe('Example Registrar Inc.');
	});

	it('extracts registrar from .us response', () => {
		const result = parseWhoisResponse(fixture('registry-example.us.txt'));
		expect(result.registrar).toBe('Example Registrar, Inc.');
	});

	it('returns redacted=true for DENIC .de privacy-protected response', () => {
		const result = parseWhoisResponse(fixture('registry-example.de.txt'));
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

	it('extracts "Registrar IANA ID:"', () => {
		const synthetic = `Domain Name: EXAMPLE.TEST\nRegistrar: Example Registrar Inc.\nRegistrar IANA ID: 299\n`;
		expect(parseWhoisResponse(synthetic).registrarIanaId).toBe('299');
	});

	it('extracts registrar from "Registrar Name:"', () => {
		const synthetic = `Domain Name: EXAMPLE.TEST\nRegistrar Name: Registrar Name LLC\n`;
		expect(parseWhoisResponse(synthetic).registrar).toBe('Registrar Name LLC');
	});

	it('extracts registrar from Korean "Authorized Agency:"', () => {
		const synthetic = `Domain Name: example.kr\nAuthorized Agency           : Whois Corp.(http://whois.co.kr)\n`;
		expect(parseWhoisResponse(synthetic).registrar).toBe('Whois Corp.(http://whois.co.kr)');
	});

	it('extracts registrar from Italian Registrar section organization', () => {
		const synthetic = `Domain: example.it\nRegistrar\n  Organization:     Hogan Lovells (Paris) LLP\n  Name:             ANCHOVY-REG\n`;
		expect(parseWhoisResponse(synthetic).registrar).toBe('Hogan Lovells (Paris) LLP');
	});

	it('extracts registrar from Turkish Registrar section organization name', () => {
		const synthetic = `** Domain Name: nike.tr

** Registrar:
NIC Handle		: ogv40
Organization Name	: ODTU GELISTIRME VAKFI BILGI TEKNOLOJILERI SAN. VE TIC. A.S.
Address			: Mustafa Kemal Mahallesi
`;
		expect(parseWhoisResponse(synthetic).registrar).toBe('ODTU GELISTIRME VAKFI BILGI TEKNOLOJILERI SAN. VE TIC. A.S.');
	});

	it('treats registry port-43 access blocks as redacted registrar data', () => {
		for (const synthetic of [
			'Requests of this client are not permitted. Please use https://www.nic.ch/whois/ for queries.',
			'The IP address used to perform the query is not authorised or has exceeded the established limit for queries.',
		]) {
			const parsed = parseWhoisResponse(synthetic);
			expect(parsed.registrar).toBeNull();
			expect(parsed.redacted).toBe(true);
		}
	});

	it('extracts registrar from "Registrar Organization:"', () => {
		const synthetic = `Domain Name: EXAMPLE.TEST\nRegistrar Organization: Registrar Org LLC\n`;
		expect(parseWhoisResponse(synthetic).registrar).toBe('Registrar Org LLC');
	});

	it('does not treat "Registrar URL:" as the registrar name', () => {
		const synthetic = `Domain Name: EXAMPLE.TEST\nRegistrar URL: https://registrar.example\n`;
		expect(parseWhoisResponse(synthetic).registrar).toBeNull();
	});

	it('strips trailing whitespace and CR characters from registrar value', () => {
		const synthetic = 'Registrar: TrimmedReg, Inc.   \r\n';
		expect(parseWhoisResponse(synthetic).registrar).toBe('TrimmedReg, Inc.');
	});

	it('extracts registrar from Nominet .uk indented format (label and value on separate lines)', () => {
		// Nominet returns:  "    Registrar:\n        Example Registrar Ltd. [Tag = EXAMPLE]\n        URL: ..."
		const result = parseWhoisResponse(fixture('registry-example.co.uk.txt'));
		expect(result.registrar).toBe('Example Registrar Ltd.');
	});

	it('strips [Tag = ...] suffix from Nominet registrar value', () => {
		// Nominet appends a registrar tag in square brackets that isn't part of the legal name.
		const synthetic = `
    Registrar:
        Acme Corp. [Tag = ACME]
        URL: https://acme.example
`;
		expect(parseWhoisResponse(synthetic).registrar).toBe('Acme Corp.');
	});

	it('does not falsely match unrelated indented lines as Nominet-format registrar', () => {
		// "Last Registrar" is a different field that happens to have "Registrar" in its label;
		// the bare-label rule (regex: /^Registrar:\s*$/) ensures we don't pick up text after the colon.
		const synthetic = `
    Last Registrar Update:
        Some date
    Whatever:
        nope
`;
		expect(parseWhoisResponse(synthetic).registrar).toBeNull();
	});

	describe('Nominet-style continuation rejects structured sub-field lines (anthropic.eu regression)', () => {
		// Bug: bv-whois shim returned `"Name: NETIM"` as the registrar for
		// `anthropic.eu`. The label-only `Registrar:` branch was grabbing the
		// next non-empty line verbatim, even when that line itself was a
		// structured `Label:` field (e.g. EURid's `Name: NETIM`). Fix: reject
		// continuation lines that look like a structured label-prefixed field
		// and fall through to the registrar-name / sponsoring / organization
		// fallback chain.

		it('prefers a real `Registrar: <value>` elsewhere in the response over a structured continuation', () => {
			// Positive case: a malformed continuation `Name: NETIM` exists but the
			// modern-ICANN `Registrar: NameSilo, LLC` also appears. Resolver should
			// emit the real value, not `Name: NETIM`.
			const synthetic = `
Domain: example.eu
Registrar:
Name: NETIM
Website: https://www.netim.com

Registrar: NameSilo, LLC
`;
			expect(parseWhoisResponse(synthetic).registrar).toBe('NameSilo, LLC');
		});

		it('returns null when the only registrar-ish line is a structured `Name:` continuation', () => {
			// Negative case: nothing in the response identifies a usable registrar.
			// Previously this returned `"Name: NETIM"`. Now it returns null.
			const synthetic = `
Domain: example.eu
Registrar:
Name: NETIM
Website: https://www.netim.com
`;
			expect(parseWhoisResponse(synthetic).registrar).toBeNull();
		});

		it('also rejects `Organization:` / `Org:` style continuation lines', () => {
			const synthetic = `
Domain: example.eu
Registrar:
Organization: SomeRegistrar GmbH
`;
			// The Italian section-block branch (line 95+) handles `Registrar` (no
			// colon) + indented `Organization:` correctly. Here the label has a
			// colon, so the strict label-only branch fires and the structured
			// continuation must be rejected.
			expect(parseWhoisResponse(synthetic).registrar).toBeNull();
		});
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
		expect(parseIanaReferral(fixture('iana-me.txt'))).toBe('whois.me.example');
	});

	it('extracts whois server from .com IANA response', () => {
		expect(parseIanaReferral(fixture('iana-com.txt'))).toBe('whois.com.example');
	});

	it('extracts whois server from .de IANA response', () => {
		expect(parseIanaReferral(fixture('iana-de.txt'))).toBe('whois.de.example');
	});

	it('extracts whois server from .io IANA response', () => {
		expect(parseIanaReferral(fixture('iana-io.txt'))).toBe('whois.io.example');
	});

	it('extracts whois server from .co IANA response', () => {
		expect(parseIanaReferral(fixture('iana-co.txt'))).toBe('whois.co.example');
	});

	it('extracts whois server from .sh IANA response', () => {
		expect(parseIanaReferral(fixture('iana-sh.txt'))).toBe('whois.sh.example');
	});

	it('extracts whois server from .us IANA response', () => {
		expect(parseIanaReferral(fixture('iana-us.txt'))).toBe('whois.us.example');
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
