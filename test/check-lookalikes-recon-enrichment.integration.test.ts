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
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]));
			}
			if (type === 'MX' || type === '15') {
				return Promise.resolve(createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.example.com.' }]));
			}
			if (type === 'A' || type === '1') {
				return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]));
			}
		}
		return Promise.resolve(createDohResponse([], []));
	});
}

// ---------------------------------------------------------------------------
// Recon binding mock helper
// ---------------------------------------------------------------------------

function makeReconHitBinding(detail: string, matchedDomain?: string) {
	return {
		fetch: vi.fn(
			async () =>
				new Response(
					JSON.stringify({
						checkType: 'CT_LOOKALIKE',
						status: 'warning',
						details: detail,
						...(matchedDomain !== undefined ? { metadata: { matchedDomain } } : {}),
					}),
					{ status: 200, headers: { 'Content-Type': 'application/json' } },
				),
		),
	};
}

function makeReconBenignBinding() {
	return {
		fetch: vi.fn(
			async () =>
				new Response(JSON.stringify({ checkType: 'CT_LOOKALIKE', status: 'info', details: 'nothing serious' }), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				}),
		),
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

	// FIX ROUND 1, F1 (2026-07-27, post-review): bv-recon's CT_LOOKALIKE check
	// is scoped to the SEED domain's CT-log neighbourhood and does not always
	// name a specific confusable domain. When it doesn't (this test's stub —
	// no `metadata.matchedDomain`), the old behaviour was a live violation of
	// the ownership-severity-gate invariant: a `medium` `threat_observation`
	// with NO `ownershipVerdict` and `domain: <the seed>` metadata (not any
	// candidate). The fix demotes an unnamed-candidate hit to `info` +
	// `scan_status` instead of fabricating a candidate name or verdict —
	// this is the CORRECTED expectation, not a relaxation: the underlying
	// signal is still surfaced (DEMOTE, NEVER DELETE), just never claims a
	// severity-bearing statement about an unnamed target.
	it('enriched, no specific candidate named: demotes to an info scan_status notice, never a nameless threat_observation', async () => {
		buildLookalikeFetchMock();

		const reconBinding = makeReconHitBinding('Certificate transparency logs show lookalike activity for test.com');

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com', { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(1);
		expect(enriched[0].severity).toBe('info');
		expect(enriched[0].metadata?.findingAxis).toBe('scan_status');
		expect(enriched[0].title).toBe('CT-observed lookalike corroboration (no specific candidate identified)');
		expect(enriched[0].detail).toContain('Certificate transparency logs show lookalike activity');
		// Never fabricates an ownershipVerdict for an unnamed target.
		expect(enriched[0].metadata?.ownershipVerdict).toBeUndefined();
	});

	// The corrected, named-candidate path: bv-recon's metadata.matchedDomain
	// resolves to a permutation this scan ALSO generated/probed locally
	// (`tst.com`, registered on `ns1.registrar.com.` — no seed NS overlap,
	// so `third_party`). The corroboration finding must reuse that SAME
	// ownership assessment rather than omitting it.
	it('enriched, named candidate resolves via ownershipByDomain: carries the real ownershipVerdict and names the candidate, not the seed', async () => {
		buildLookalikeFetchMock();

		const reconBinding = makeReconHitBinding('Certificate transparency logs show lookalike activity for tst.com', 'tst.com');

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com', { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(1);
		expect(enriched[0].severity).toBe('medium');
		expect(enriched[0].metadata?.findingAxis).toBe('threat_observation');
		expect(enriched[0].title).toBe('CT-observed lookalike corroboration');
		expect(enriched[0].metadata?.lookalikeDomain).toBe('tst.com');
		expect(enriched[0].metadata?.domain).toBeUndefined();
		expect(enriched[0].metadata?.ownershipVerdict).toBe('third_party');
	});

	// F4 hardening: a recon response that merely echoes the SEED as
	// `matchedDomain` must be treated identically to "no candidate named" —
	// never let a self-referential match masquerade as a real one.
	it('enriched, matchedDomain equal to the seed itself: treated as no candidate named (F4)', async () => {
		buildLookalikeFetchMock();

		const reconBinding = makeReconHitBinding('echoes the seed', 'test.com');

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com', { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(1);
		expect(enriched[0].severity).toBe('info');
		expect(enriched[0].metadata?.findingAxis).toBe('scan_status');
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

		const reconBinding = {
			fetch: vi.fn(async () => {
				throw new Error('network error');
			}),
		};

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes('test.com', { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(0);
	});
});
