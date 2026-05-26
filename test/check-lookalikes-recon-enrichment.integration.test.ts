// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// DNS mock helpers — produce at least one registered lookalike with MX so the
// tool reaches checkLookalikesCore's main return (not an early-exit guard).
// Mirrors the "high finding for lookalike with MX records" mock in check-lookalikes.spec.ts.
// ---------------------------------------------------------------------------

function buildLookalikeFetchMock() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const parsed = new URL(url);
		const name = parsed.searchParams.get('name') ?? '';
		const type = parsed.searchParams.get('type') ?? '';

		// One lookalike (tst.com) has NS + MX + A records → reaches main return
		if (name === 'tst.com' || name === 'tes.com') {
			if (type === 'NS' || type === '2') {
				return Promise.resolve(
					createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]),
				);
			}
			if (type === 'MX' || type === '15') {
				return Promise.resolve(
					createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.example.com.' }]),
				);
			}
			if (type === 'A' || type === '1') {
				return Promise.resolve(
					createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]),
				);
			}
		}
		return Promise.resolve(createDohResponse([], []));
	});
}

// ---------------------------------------------------------------------------
// Recon binding mock helper
// ---------------------------------------------------------------------------

function makeReconHitBinding(detail: string) {
	return {
		fetch: vi.fn(async () => new Response(JSON.stringify({ checkType: 'CT_LOOKALIKE', status: 'warning', details: detail }), { status: 200, headers: { 'Content-Type': 'application/json' } })),
	};
}

function makeReconBenignBinding() {
	return {
		fetch: vi.fn(async () => new Response(JSON.stringify({ checkType: 'CT_LOOKALIKE', status: 'info', details: 'nothing serious' }), { status: 200, headers: { 'Content-Type': 'application/json' } })),
	};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('checkLookalikes recon enrichment', () => {
	it('fail-soft guard: no reconEnriched finding when binding is absent', async () => {
		buildLookalikeFetchMock();

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com');

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(0);
	});

	it('enriched: adds corroboration finding when recon returns a hit status', async () => {
		buildLookalikeFetchMock();

		const reconBinding = makeReconHitBinding('Certificate transparency logs show lookalike activity for test.com');

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com', { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(1);
		expect(enriched[0].severity).toBe('medium');
		expect(enriched[0].title).toBe('CT-observed lookalike corroboration');
		expect(enriched[0].detail).toContain('Certificate transparency logs show lookalike activity');
	});

	it('enriched: no corroboration finding when recon returns a benign status', async () => {
		buildLookalikeFetchMock();

		const reconBinding = makeReconBenignBinding();

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com', { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(0);
	});

	it('enriched: no corroboration finding when recon binding fetch fails (fail-soft)', async () => {
		buildLookalikeFetchMock();

		const reconBinding = { fetch: vi.fn(async () => { throw new Error('network error'); }) };

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com', { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(0);
	});
});
