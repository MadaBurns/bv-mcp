// H2/H3 helper tests. validateOutboundUrl is the boundary check applied to
// attacker-controlled URLs from DNS TXT records (BIMI l=/a= tags) and HTTP
// redirect Location targets. It must reject SSRF payloads that string-prefix
// validation alone would accept.

import { describe, expect, it } from 'vitest';
import { validateOutboundUrl } from '../src/lib/sanitize';

describe('validateOutboundUrl', () => {
	it('accepts well-formed public HTTPS URLs', () => {
		expect(validateOutboundUrl('https://example.com/').valid).toBe(true);
		expect(validateOutboundUrl('https://logo.example.com/file.svg').valid).toBe(true);
		expect(validateOutboundUrl('https://example.com:8443/x').valid).toBe(true);
	});

	it('rejects non-string / empty input', () => {
		expect(validateOutboundUrl('').valid).toBe(false);
		// @ts-expect-error testing runtime guard
		expect(validateOutboundUrl(null).valid).toBe(false);
		// @ts-expect-error testing runtime guard
		expect(validateOutboundUrl(undefined).valid).toBe(false);
	});

	it('rejects malformed URLs', () => {
		expect(validateOutboundUrl('not a url').valid).toBe(false);
		expect(validateOutboundUrl('https:///nohost').valid).toBe(false);
	});

	it('rejects non-https schemes', () => {
		for (const scheme of ['http', 'file', 'ftp', 'data', 'javascript']) {
			const result = validateOutboundUrl(`${scheme}://example.com/`);
			expect(result.valid).toBe(false);
		}
	});

	it('rejects userinfo (https://attacker@target/ confusion)', () => {
		expect(validateOutboundUrl('https://attacker@example.com/').valid).toBe(false);
		expect(validateOutboundUrl('https://attacker:pw@example.com/').valid).toBe(false);
	});

	it('rejects IP literals (RFC1918, loopback, link-local)', () => {
		expect(validateOutboundUrl('https://127.0.0.1/').valid).toBe(false);
		expect(validateOutboundUrl('https://10.0.0.1/').valid).toBe(false);
		expect(validateOutboundUrl('https://192.168.1.1/').valid).toBe(false);
		expect(validateOutboundUrl('https://169.254.169.254/').valid).toBe(false);
	});

	it('rejects reserved TLDs and hostnames', () => {
		expect(validateOutboundUrl('https://something.internal/').valid).toBe(false);
		expect(validateOutboundUrl('https://localhost/').valid).toBe(false);
		expect(validateOutboundUrl('https://anything.local/').valid).toBe(false);
	});

	it('rejects DNS-rebinding services', () => {
		expect(validateOutboundUrl('https://192.0.2.1.nip.io/').valid).toBe(false);
		expect(validateOutboundUrl('https://1-2-3-4.sslip.io/').valid).toBe(false);
	});

	it('rejects encoded-form IPs (decimal/hex/octal)', () => {
		expect(validateOutboundUrl('https://2130706433/').valid).toBe(false);
		expect(validateOutboundUrl('https://0x7f000001/').valid).toBe(false);
	});
});
