// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { analyzeKeyStrength } from '../../checks/dkim-analysis';
import { checkDKIM } from '../../checks/check-dkim';
import type { DNSQueryFunction } from '../../types';

// Real RSA SubjectPublicKeyInfo base64, generated with openssl.
const REAL_512 =
	'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANtwUuPMzIURXcYu/62Q/q8CNmoqMWL+hJeBnDFjurqU28y02wO6fUMQcBs5oHN/32qa9VGDE6BgnABPd0GWDwECAwEAAQ==';
const REAL_2048 =
	'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAscfuKyPiWgOCZZ9swgCi4A96RmZadSQeVBH5UfaRuMs1NNh2Se+wewffsV/2XNNrquxh9eZXW/dVK5wztMX4lFzaSL7XWg5coxxvbe88z2eQT8wkLSFTNSRsc+fFb7xny56IEi2iqfV9BHzL25Eh/prfpqHz8Tm08plQ5UkcNJXNagPXOp2mZBAKyWcdO+0gDVrBRdDZyxjYUxlr6rp0zxGtyotVMCQHWx3JjGxABWkMnkf0+w6oeyWeYyrecZMCR244C/yw1b68POoy5HdaBisbFQwHz8hfBnzkYgjHQiYIRQYxBa3akGFwkwap4dTNfiHj4Q1mWNr7IFFR8iy11wIDAQAB';
// A 2048-bit key truncated in DNS — the real-world failure mode (zerojet.com: single
// truncated RR; aryde.io: key split across 3 separate TXT RRs so only a fragment is read).
// The DER header still declares 2048-bit; only the modulus data is missing.
const TRUNCATED_2048 = REAL_2048.slice(0, 120);

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => records[domain] ?? []);
}

describe('analyzeKeyStrength — malformed/truncated RSA keys', () => {
	it('classifies a truncated 2048-bit-header key as malformed, not a weak ~512-bit key', () => {
		const result = analyzeKeyStrength(TRUNCATED_2048, 'rsa');
		expect(result.keyType).toBe('rsa-malformed');
		expect(result.strength).not.toBe('critical');
		expect(result.bits).toBe(2048); // declared size from the DER header
	});

	it('still flags a genuine complete 512-bit RSA key as critical', () => {
		const result = analyzeKeyStrength(REAL_512, 'rsa');
		expect(result).toMatchObject({ bits: 512, strength: 'critical', keyType: 'rsa' });
	});

	it('still treats a genuine complete 2048-bit RSA key as strong', () => {
		const result = analyzeKeyStrength(REAL_2048, 'rsa');
		expect(result).toMatchObject({ bits: 2048, strength: 'info', keyType: 'rsa' });
	});
});

describe('checkDKIM — truncated key does not produce a false weak-key critical', () => {
	it('reports a malformed/truncated finding instead of "Weak RSA key (~512 bits)"', async () => {
		const queryDNS = createMockDNS({
			'google._domainkey.example.com': [`v=DKIM1; k=rsa; p=${TRUNCATED_2048}`],
		});
		const result = await checkDKIM('example.com', queryDNS);

		const weakCritical = result.findings.find((f) => /weak rsa key/i.test(f.title) && f.severity === 'critical');
		expect(weakCritical).toBeUndefined();

		const malformed = result.findings.find((f) => /malformed/i.test(f.title));
		expect(malformed).toBeDefined();
		expect(malformed?.severity).toBe('medium');
	});
});
