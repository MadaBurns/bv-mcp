// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a DoH NSEC3PARAM response (type 51). */
function nsec3paramResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 51 }],
		records.map((data) => ({ name: domain, type: 51, TTL: 300, data })),
	);
}

/**
 * Route DoH queries by type-name (the transport sends `type=NSEC3PARAM|DNSKEY|DS`).
 * `signed` controls whether DNSKEY/DS lookups return records, gating the
 * DNSSEC-signed-zone check. NSEC3PARAM always returns empty here (the "missing
 * NSEC3PARAM" path) so the signed/unsigned branch is exercised.
 */
function routeByType(domain: string, opts: { signed: boolean }) {
	return vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? domain;
		const typeName = (u.searchParams.get('type') ?? '').toUpperCase();
		const TYPE_CODE: Record<string, number> = { NSEC3PARAM: 51, DNSKEY: 48, DS: 43 };
		const typeCode = TYPE_CODE[typeName] ?? 0;
		if (opts.signed && (typeName === 'DNSKEY' || typeName === 'DS')) {
			const data = typeName === 'DNSKEY' ? '257 3 13 mdsswUyr3...' : '12345 13 2 ABCDEF...';
			return Promise.resolve(createDohResponse([{ name, type: typeCode }], [{ name, type: typeCode, TTL: 300, data }]));
		}
		return Promise.resolve(createDohResponse([{ name, type: typeCode }], []));
	});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('checkNsecWalkability', () => {
	async function run(domain = 'example.com') {
		const { checkNsecWalkability } = await import('../src/tools/check-nsec-walkability');
		return checkNsecWalkability(domain);
	}

	it('should parse NSEC3PARAM with salt and iterations as info', async () => {
		// "1 0 10 AABBCCDD" → algorithm=1 (SHA-1), flags=0, iterations=10, salt=AABBCCDD
		globalThis.fetch = vi.fn().mockResolvedValue(nsec3paramResponse('example.com', ['1 0 10 AABBCCDD']));

		const result = await run();
		expect(result.category).toBe('nsec_walkability');

		// Standard NSEC3 with salt + iterations → info
		const paramFinding = result.findings.find((f) => f.severity === 'info' && f.detail.includes('NSEC3'));
		expect(paramFinding).toBeDefined();
		expect(paramFinding!.metadata?.algorithm).toBe('SHA-1');
		expect(paramFinding!.metadata?.iterations).toBe(10);
		expect(paramFinding!.metadata?.salt).toBe('AABBCCDD');
	});

	it('should flag 0 iterations with no salt as medium severity', async () => {
		// "1 0 0 -" → RFC 9276 default params: 0 iterations, no salt
		globalThis.fetch = vi.fn().mockResolvedValue(nsec3paramResponse('example.com', ['1 0 0 -']));

		const result = await run();
		expect(result.category).toBe('nsec_walkability');

		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.detail).toMatch(/low enumeration cost|RFC 9276/i);
	});

	it('should flag missing NSEC3PARAM as high severity ONLY when the zone is DNSSEC-signed', async () => {
		// No NSEC3PARAM, but DNSKEY/DS present → signed zone using plain NSEC → walkable HIGH.
		globalThis.fetch = routeByType('example.com', { signed: true });

		const result = await run();
		expect(result.category).toBe('nsec_walkability');

		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.detail).toMatch(/walkable|plain NSEC/i);
		expect(highFinding!.metadata?.walkable).toBe(true);
		expect(highFinding!.metadata?.dnssecSigned).toBe(true);
	});

	it('should NOT flag walkability for an UNSIGNED zone (no NSEC3PARAM, no DNSKEY/DS)', async () => {
		// trademe.co.nz scenario: no NSEC3PARAM AND no DNSSEC → no NSEC chain to walk.
		globalThis.fetch = routeByType('example.com', { signed: false });

		const result = await run();
		expect(result.category).toBe('nsec_walkability');

		// Must be an info "N/A" finding, NOT a high walkability false positive.
		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeUndefined();
		const infoFinding = result.findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.detail).toMatch(/not DNSSEC-signed|N\/A|no NSEC chain|not signed/i);
		expect(infoFinding!.metadata?.walkable).toBe(false);
		expect(infoFinding!.metadata?.dnssecSigned).toBe(false);
	});

	it('should report opt-out flag when set', async () => {
		// "1 1 5 AABB" → flags=1 (opt-out bit set)
		globalThis.fetch = vi.fn().mockResolvedValue(nsec3paramResponse('example.com', ['1 1 5 AABB']));

		const result = await run();
		expect(result.category).toBe('nsec_walkability');

		const optOutFinding = result.findings.find((f) => f.detail.includes('opt-out') || f.detail.includes('Opt-out'));
		expect(optOutFinding).toBeDefined();
		expect(optOutFinding!.severity).toBe('low');
	});

	it('should map algorithm ID 1 to SHA-1', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(nsec3paramResponse('example.com', ['1 0 10 AABBCCDD']));

		const result = await run();
		const finding = result.findings.find((f) => f.metadata?.algorithm);
		expect(finding).toBeDefined();
		expect(finding!.metadata!.algorithm).toBe('SHA-1');
	});

	it('should handle DNS error gracefully', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('DNS timeout'));

		const result = await run();
		expect(result.category).toBe('nsec_walkability');

		// Should not throw — return info finding about the error
		const infoFinding = result.findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
	});
});
