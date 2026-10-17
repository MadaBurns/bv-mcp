// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract test: handler responses run through bv-mcp's consumer shapes and acceptance checks.
 *
 * bv-mcp's parser types are module-private (not exported) and live outside this package, so the shapes and the
 * checks are COPIED here with their source lines (bv-mcp @ origin/main fa86d6c9, per SQ-338). If bv-mcp changes
 * them, this copy is what to update; the checks mirror what makes bv-mcp treat an answer as healthy.
 */

import { describe, expect, it } from 'vitest';
import { handleApiRequest } from '../api/handler';
import { nameKey, siblingKey } from '../codec';
import type { IndexReader, NameObservation } from '../types';

/** src/tools/discover-subdomains.ts:645-653 */
interface CertstreamEnumerateResponse {
	domain: string;
	subdomains: string[];
	certificateCount: number;
	timedOut: boolean;
	cached: boolean;
	cacheAgeMinutes?: number;
	error?: string;
}

/** src/tools/discover-subdomains.ts:656-665 (san-correlator.ts:151 reads the same fields minus `truncated`) */
interface CertstreamSansResponse {
	domain: string;
	names: string[];
	certificateCount: number;
	timedOut: boolean;
	truncated: boolean;
	cached: boolean;
	cacheAgeMinutes?: number;
	error?: string;
}

/** src/tools/discover-subdomains.ts:1639 (/enumerate) and :1674 (/sans): a healthy answer. */
const enumerateHealthy = (data: CertstreamEnumerateResponse | null) => Boolean(data) && !data?.error && Array.isArray(data?.subdomains);
const sansHealthy = (data: CertstreamSansResponse | null) => Boolean(data) && !data?.error && Array.isArray(data?.names);

/** src/tools/scan/post-processing.ts:224-227 (fetchCertIssuerFromCertstream): the issuer, or null. */
function parseCertMeta(data: unknown): string | null {
	if (data === null || typeof data !== 'object' || Array.isArray(data)) return null;
	if (!('issuer' in data) || typeof data.issuer !== 'string' || data.issuer.trim().length === 0) return null;
	if ('error' in data && data.error) return null;
	return data.issuer;
}

/** src/tools/discover-subdomains.ts:1839-1862 (buildCertstreamResult): which names count as subdomains of `domain`. */
function subdomainsOf(domain: string, names: string[]): string[] {
	const domainLower = domain.toLowerCase();
	const domainSuffix = `.${domainLower}`;
	const kept = new Set<string>();
	for (const name of names) {
		const lower = name.trim().toLowerCase().replace(/\.$/, '');
		if (!lower) continue;
		const isWildcard = lower.startsWith('*.');
		const comparable = isWildcard ? lower.slice(2) : lower;
		if (!isWildcard && comparable === domainLower) continue;
		if (comparable !== domainLower && !comparable.endsWith(domainSuffix)) continue;
		kept.add(lower);
	}
	return [...kept];
}

/** src/tenants/discovery/san-correlator.ts:281-308: a /sans answer is accepted (even with zero siblings) unless it errs or timed out empty. */
function sansAccepted(data: CertstreamSansResponse): boolean {
	return !data.error && Array.isArray(data.names) && !data.timedOut;
}

function name(host: string, overrides: Partial<NameObservation> = {}): NameObservation {
	const k = nameKey(host);
	return {
		key: k.key,
		name: k.name,
		apex: 'example.com',
		firstSeen: 1_790_000_000,
		notAfter: 1_800_000_000,
		issuer: "Let's Encrypt R11",
		wildcard: k.wildcard,
		...overrides,
	};
}

const reader: IndexReader = {
	async scan() {
		return {
			names: [name('example.com'), name('api.example.com'), name('dev.example.com', { wildcard: true })],
			truncated: true,
			cursor: 'abc',
		};
	},
	async siblings() {
		return {
			siblings: [{ key: siblingKey('example.com', 'example.org'), apex: 'example.com', sibling: 'example.org', firstSeen: 1, notAfter: 2 }],
			truncated: false,
		};
	},
	async meta() {
		return { indexStartedAt: '2026-10-17T00:00:00.000Z', freshThrough: '2026-10-17T05:00:00.000Z', generation: 1 };
	},
};

async function get<T>(path: string): Promise<T> {
	const response = await handleApiRequest(
		new Request(`https://certstream${path}`, { headers: { authorization: 'Bearer k' } }),
		{ CT_INDEX_ADMIN_KEY: 'k' },
		{ reader },
	);
	expect(response.status).toBe(200);
	return (await response.json()) as T;
}

describe('bv-mcp consumer contract', () => {
	it('/enumerate is a healthy CertstreamEnumerateResponse whose names bv-mcp keeps as subdomains', async () => {
		const data = await get<CertstreamEnumerateResponse>('/enumerate?domain=example.com');
		expect(enumerateHealthy(data)).toBe(true);
		expect(data.timedOut).toBe(false);
		expect(typeof data.certificateCount).toBe('number');
		// The apex itself is dropped by bv-mcp; the wildcard row arrives as both dev.example.com and *.dev.example.com.
		expect(subdomainsOf('example.com', data.subdomains)).toEqual(['api.example.com', 'dev.example.com', '*.dev.example.com']);
	});

	it('/sans is a healthy CertstreamSansResponse that carries `truncated` and is accepted even with no siblings', async () => {
		const data = await get<CertstreamSansResponse>('/sans?domain=www.example.com');
		expect(sansHealthy(data)).toBe(true);
		expect(data.names).toEqual(['example.org']);
		expect(data.truncated).toBe(false);
		expect(sansAccepted(data)).toBe(true);
	});

	it("/cert-meta yields a non-empty string issuer through bv-mcp's parser", async () => {
		const data = await get<unknown>('/cert-meta?domain=example.com');
		expect(parseCertMeta(data)).toBe("Let's Encrypt R11");
	});

	it('an error body is never mistaken for a healthy answer by the same parsers', async () => {
		const failing: IndexReader = { ...reader, scan: () => Promise.reject(new Error('d1 down')) };
		const response = await handleApiRequest(
			new Request('https://certstream/enumerate?domain=example.com', { headers: { authorization: 'Bearer k' } }),
			{ CT_INDEX_ADMIN_KEY: 'k' },
			{ reader: failing },
		);
		expect(response.ok).toBe(false); // bv-mcp: `if (!response.ok) return { data: null, outcome: ... }` (:1773)
		const body = (await response.json()) as CertstreamEnumerateResponse;
		expect(enumerateHealthy(body)).toBe(false);
		expect(parseCertMeta(body)).toBeNull();
	});
});
