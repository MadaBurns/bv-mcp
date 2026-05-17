// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the second-order SAN expansion (`correlateSansRecursive`).
 *
 * Cross-cert mutual SAN inclusion (seed is in candidate's crt.sh SAN list)
 * is near-deterministic ownership: a third party cannot publish a cert that
 * includes another operator's apex. The recursive pass promotes single-signal
 * first-order SAN hits (0.10 conf, gate-dropped) into corroborated
 * candidates at 0.85.
 *
 * `.spec.ts` here = Vitest unit (per repo CLAUDE.md), not E2E. Tests inject
 * `fetchFn` so no live crt.sh traffic.
 */

import { describe, it, expect, vi } from 'vitest';
import { correlateSansRecursive } from '../src/tenants/discovery/san-correlator';

interface CrtShFixtureEntry {
	id?: number;
	name_value: string;
}

function jsonResponse(body: unknown): Response {
	const text = JSON.stringify(body);
	const encoder = new TextEncoder();
	const uint8 = encoder.encode(text);
	return new Response(uint8, {
		status: 200,
		headers: { 'content-type': 'application/json', 'content-length': String(uint8.length) },
	});
}

/** Map `q=<domain>` query param to fixture entries; unknown → empty list. */
function mockFetchByQuery(byDomain: Record<string, CrtShFixtureEntry[]>): typeof fetch {
	return vi.fn().mockImplementation(async (url: string) => {
		const q = (new URL(String(url)).searchParams.get('q') ?? '').toLowerCase();
		return jsonResponse(byDomain[q] ?? []);
	}) as unknown as typeof fetch;
}

describe('correlateSansRecursive', () => {
	it('cross-confirms when a first-order sibling lists the seed in its own SANs', async () => {
		const fetchFn = mockFetchByQuery({
			'githubusercontent.com': [
				{ id: 101, name_value: 'github.com\ngithubusercontent.com\ngithubassets.com' },
			],
		});

		const result = await correlateSansRecursive(
			'github.com',
			['githubusercontent.com'],
			{ fetchFn, maxRetries: 0 },
		);

		expect(result).toMatchObject({
			queryStatus: 'ok',
			probed: ['githubusercontent.com'],
			crossConfirmed: [{ candidate: 'githubusercontent.com' }],
		});
	});

	it('emits no candidates when sibling SANs do NOT mention the seed', async () => {
		const fetchFn = mockFetchByQuery({
			'unrelated-sibling.com': [
				{ id: 201, name_value: 'unrelated-sibling.com\nfoo.com\nbar.com' },
			],
		});

		const result = await correlateSansRecursive(
			'github.com',
			['unrelated-sibling.com'],
			{ fetchFn, maxRetries: 0 },
		);

		expect(result.crossConfirmed).toEqual([]);
	});

	it('caps second-order probes to top 20 candidates (shortest apex first)', async () => {
		// 25 first-order candidates of varied length; default maxCandidates=20.
		const firstOrder: string[] = [];
		for (let i = 0; i < 25; i++) {
			const segLen = i < 10 ? 3 : i < 20 ? 4 : 5;
			const tag = String(i).padStart(2, '0');
			const left = 'a'.repeat(Math.max(1, segLen - tag.length)) + tag;
			firstOrder.push(`${left}.com`);
		}

		const fetchFn = vi.fn().mockImplementation(async (url: string) => {
			const q = (new URL(String(url)).searchParams.get('q') ?? '').toLowerCase();
			return jsonResponse([{ id: 1, name_value: `seed.com\n${q}` }]);
		}) as unknown as typeof fetch;

		const result = await correlateSansRecursive('seed.com', firstOrder, {
			fetchFn,
			maxRetries: 0,
		});

		// Only 20 shortest probed; no length-9 entries leak through.
		expect(result.probed.length).toBe(20);
		expect(result.probed.every((p) => p.length <= 8)).toBe(true);
		expect((fetchFn as ReturnType<typeof vi.fn>).mock.calls.length).toBe(20);
	});
});
