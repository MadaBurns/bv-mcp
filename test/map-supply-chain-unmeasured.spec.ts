// SPDX-License-Identifier: BUSL-1.1

// SQ-291 item 1 (map_supply_chain half) — a lookup that never concluded is not
// "no third-party dependencies".

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

function typeOf(url: string | URL): string {
	return new URL(typeof url === 'string' ? url : url.toString()).searchParams.get('type') ?? '';
}

describe('SQ-291 mapSupplyChain — unmeasured lookups are surfaced, never an empty clean map', () => {
	it('every lookup rejecting → unmeasured lists every source and the formatter does not claim "no dependencies"', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('network down'));
		const { mapSupplyChain, formatSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = await mapSupplyChain('rejected-291.example');
		expect(result.dependencies).toEqual([]);
		const sources = (result.unmeasured ?? []).map((u) => u.source);
		for (const s of ['txt', 'ns', 'caa', 'mx', 'a', 'srv']) expect(sources).toContain(s);
		for (const format of ['full', 'compact'] as const) {
			const text = formatSupplyChain(result, format);
			expect(text).not.toContain('No third-party dependencies detected');
			expect(text).toMatch(/not (be )?measured|Not assessed|unmeasured/i);
		}
	});

	it('SERVFAIL on TXT and NS → those sources are unmeasured (inconclusive); others are not', async () => {
		globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
			const type = typeOf(url);
			if (type === 'TXT' || type === 'NS') return Promise.resolve(createDohResponse([], [], { status: 2 }));
			return Promise.resolve(createDohResponse([], []));
		});
		const { mapSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = await mapSupplyChain('servfail-291.example');
		const bySource = Object.fromEntries((result.unmeasured ?? []).map((u) => [u.source, u.reason]));
		expect(bySource).toEqual({ txt: 'inconclusive', ns: 'inconclusive' });
	});

	it('control: every lookup measured empty → no unmeasured field and the clean wording stays', async () => {
		globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createDohResponse([], [])));
		const { mapSupplyChain, formatSupplyChain } = await import('../src/tools/map-supply-chain');
		const result = await mapSupplyChain('clean-291.example');
		expect(result.unmeasured).toBeUndefined();
		expect(formatSupplyChain(result, 'full')).toContain('No third-party dependencies detected');
	});
});
