// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Build a DoH DNSKEY response (type 48). DNSKEY rdata format: "flags protocol algorithm <base64key>". */
function dnskeyResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 48 }],
		records.map((data) => ({ name: domain, type: 48, TTL: 300, data })),
	);
}

describe('checkDnskeyStrength', () => {
	async function run(domain = 'example.com') {
		const { checkDnskeyStrength } = await import('../src/tools/check-dnskey-strength');
		return checkDnskeyStrength(domain);
	}

	it('returns the dnskey_strength category', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(dnskeyResponse('example.com', ['257 3 13 mdsswUyr3DPW...']));
		const result = await run();
		expect(result.category).toBe('dnskey_strength');
	});

	it('flags a modern algorithm (ECDSA P-256, alg 13) as info', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(dnskeyResponse('example.com', ['257 3 13 mdsswUyr3DPW...']));
		const result = await run();
		const modern = result.findings.find((f) => f.title.includes('Modern'));
		expect(modern).toBeDefined();
		expect(modern!.severity).toBe('info');
		expect(modern!.detail).toMatch(/ECDSA P-256/);
	});

	it('surfaces the algorithm when Cloudflare DoH emits a mnemonic (ECDSAP256SHA256, alg 13)', async () => {
		// Cloudflare (the PRIMARY prod resolver) returns the IANA mnemonic in the
		// algorithm field, not a number. The record must still resolve to alg 13.
		globalThis.fetch = vi.fn().mockResolvedValue(dnskeyResponse('example.com', ['257 3 ECDSAP256SHA256 mdsswUyr3DPW...']));
		const result = await run();
		const modern = result.findings.find((f) => f.title.includes('Modern'));
		expect(modern).toBeDefined();
		expect(modern!.severity).toBe('info');
		expect(modern!.detail).toMatch(/ECDSA P-256/);
		// Must NOT collapse to the vacuous "No DNSKEY" path.
		expect(result.findings.find((f) => f.title.includes('No DNSKEY'))).toBeUndefined();
	});

	it('flags a deprecated algorithm (RSA/SHA-1, alg 5) as high', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(dnskeyResponse('example.com', ['257 3 5 AwEAAabc...']));
		const result = await run();
		const high = result.findings.find((f) => f.severity === 'high');
		expect(high).toBeDefined();
		expect(high!.title).toMatch(/Deprecated/);
		expect(high!.detail).toMatch(/RSA\/SHA-1|RFC 8624/);
	});

	it('flags a not-recommended algorithm (RSA/SHA-512, alg 10) as low', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(dnskeyResponse('example.com', ['257 3 10 AwEAAdef...']));
		const result = await run();
		const low = result.findings.find((f) => f.severity === 'low');
		expect(low).toBeDefined();
		expect(low!.title).toMatch(/not recommended/i);
	});

	it('deduplicates repeated algorithms (KSK + ZSK on alg 13 → one finding)', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(dnskeyResponse('example.com', ['257 3 13 KSK...', '256 3 13 ZSK...']));
		const result = await run();
		const modern = result.findings.filter((f) => f.title.includes('Modern'));
		expect(modern).toHaveLength(1);
	});

	it('returns an info finding (not a missing control) when no DNSKEY records exist', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(dnskeyResponse('example.com', []));
		const result = await run();
		const info = result.findings.find((f) => f.title.includes('No DNSKEY'));
		expect(info).toBeDefined();
		expect(info!.severity).toBe('info');
		// Hardening bonus-only: absence is not penalised as a missing control.
		expect(info!.metadata?.missingControl).toBeUndefined();
	});

	it('handles a DNS error gracefully (no throw, checkStatus error)', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('DNS timeout'));
		const result = await run();
		expect(result.category).toBe('dnskey_strength');
		const info = result.findings.find((f) => f.severity === 'info');
		expect(info).toBeDefined();
		expect(result.checkStatus).toBe('error');
	});
});
