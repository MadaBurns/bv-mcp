// SPDX-License-Identifier: BUSL-1.1

/**
 * The takeover sweep's fingerprint probes share the check's fetch budget. A probe that throws
 * after the budget is spent is recorded as "cut short" (not read as clean); a probe that throws
 * with budget left is not.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	vi.restoreAllMocks();
	restore();
});

const CUT_SHORT_REASON = 'at least one takeover fingerprint probe was cut short by the time budget';
const LLMS_TXT = ['# Example', '', '> Docs for agents.', '', '- [Source](https://linked.example.net/repo)'].join('\n');

/**
 * Routes: llms.txt on the scanned domain, DoH where `linked.example.net` has only an A record
 * (so the sweep runs its A/AAAA fingerprint vector), and `probe(url)` for every other egress.
 */
function mockWeb(probe: (u: URL) => Response | never) {
	globalThis.fetch = vi.fn().mockImplementation(async (input: string | URL | Request) => {
		const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const u = new URL(href);
		const name = u.searchParams.get('name');
		if (name !== null) {
			const type = Number(u.searchParams.get('type') === 'A' ? 1 : (u.searchParams.get('type') ?? 1));
			const q = [{ name, type }];
			if (type === 1 && name === 'linked.example.net') {
				return createDohResponse(q, [{ name, type: 1, TTL: 300, data: '203.0.113.9' }]);
			}
			return createDohResponse(q, []);
		}
		if (u.hostname === 'example.com') {
			return u.pathname === '/llms.txt' ? new Response(LLMS_TXT, { status: 200, headers: { 'content-type': 'text/plain' } }) : new Response('nf', { status: 404 });
		}
		return probe(u);
	});
}

async function notAssessedReasons(): Promise<string[]> {
	const { checkLlmsTxt } = await import('../src/tools/check-llms-txt');
	const result = await checkLlmsTxt('example.com');
	return result.notAssessed.map((n) => n.reason);
}

describe('checkLlmsTxt takeover probe budget accounting', () => {
	it('records a probe that throws after the fetch budget is spent as cut short', async () => {
		const realNow = Date.now.bind(Date);
		let skewMs = 0;
		vi.spyOn(Date, 'now').mockImplementation(() => realNow() + skewMs);
		mockWeb((u) => {
			if (u.pathname.endsWith('/robots.txt')) return new Response('', { status: 404 });
			// The fingerprint probe: burn the whole 18s budget, then fail.
			skewMs += 20_000;
			throw new Error('connection reset');
		});

		const reasons = await notAssessedReasons();
		expect(reasons).toContain(CUT_SHORT_REASON);
	});

	it('does not flag a probe that throws while budget remains', async () => {
		mockWeb((u) => {
			if (u.pathname.endsWith('/robots.txt')) return new Response('', { status: 404 });
			throw new Error('connection reset');
		});

		const reasons = await notAssessedReasons();
		expect(reasons).not.toContain(CUT_SHORT_REASON);
	});
});
