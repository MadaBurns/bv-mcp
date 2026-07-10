// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import {
	SCANNER_USER_AGENT,
	RobotsDisallowedError,
	withRobotsGate,
	parseRobotsGroups,
	isPathDisallowed,
} from '../robots-gate';

function textResponse(body: string, ok = true): Response {
	return new Response(body, { status: ok ? 200 : 404 });
}

describe('parseRobotsGroups', () => {
	it('parses a single wildcard group', () => {
		const groups = parseRobotsGroups('User-agent: *\nDisallow: /private\n');
		expect(groups).toEqual([{ agents: ['*'], rules: [{ path: '/private', allow: false }] }]);
	});

	it('parses a named group separately from the wildcard group', () => {
		const groups = parseRobotsGroups(
			'User-agent: BlackVeil-Security-Scanner\nDisallow: /\n\nUser-agent: *\nDisallow: /admin\n'
		);
		expect(groups).toEqual([
			{ agents: ['blackveil-security-scanner'], rules: [{ path: '/', allow: false }] },
			{ agents: ['*'], rules: [{ path: '/admin', allow: false }] },
		]);
	});

	it('ignores comments and blank lines', () => {
		const groups = parseRobotsGroups(
			'# comment\n\nUser-agent: *\n# another comment\nDisallow: /x\n'
		);
		expect(groups).toEqual([{ agents: ['*'], rules: [{ path: '/x', allow: false }] }]);
	});

	it('groups consecutive User-agent lines into one group', () => {
		const groups = parseRobotsGroups('User-agent: a\nUser-agent: b\nDisallow: /x\n');
		expect(groups).toEqual([{ agents: ['a', 'b'], rules: [{ path: '/x', allow: false }] }]);
	});
});

describe('isPathDisallowed', () => {
	it('returns false for a null group (no matching group at all)', () => {
		expect(isPathDisallowed(null, '/anything')).toBe(false);
	});

	it('disallows an exact-prefix match', () => {
		const group = { agents: ['*'], rules: [{ path: '/private', allow: false }] };
		expect(isPathDisallowed(group, '/private/x')).toBe(true);
		expect(isPathDisallowed(group, '/public')).toBe(false);
	});

	it('an empty Disallow value means allow everything', () => {
		const group = { agents: ['*'], rules: [{ path: '', allow: false }] };
		expect(isPathDisallowed(group, '/anything')).toBe(false);
	});

	it('longest match wins', () => {
		const group = {
			agents: ['*'],
			rules: [
				{ path: '/', allow: false },
				{ path: '/public', allow: true },
			],
		};
		expect(isPathDisallowed(group, '/public/page')).toBe(false);
		expect(isPathDisallowed(group, '/private')).toBe(true);
	});

	it('ties favor Allow regardless of encounter order', () => {
		const allowFirst = {
			agents: ['*'],
			rules: [
				{ path: '/x', allow: true },
				{ path: '/x', allow: false },
			],
		};
		const disallowFirst = {
			agents: ['*'],
			rules: [
				{ path: '/x', allow: false },
				{ path: '/x', allow: true },
			],
		};
		expect(isPathDisallowed(allowFirst, '/x')).toBe(false);
		expect(isPathDisallowed(disallowFirst, '/x')).toBe(false);
	});

	it('supports * wildcard and $ end-anchor', () => {
		const group = { agents: ['*'], rules: [{ path: '/*.pdf$', allow: false }] };
		expect(isPathDisallowed(group, '/docs/report.pdf')).toBe(true);
		expect(isPathDisallowed(group, '/docs/report.pdf.html')).toBe(false);
	});
});

describe('withRobotsGate', () => {
	it('stamps the User-Agent header when the caller did not set one', async () => {
		const inner = vi.fn(async () => textResponse('', false));
		const gated = withRobotsGate(inner);
		await gated('https://example.com/robots.txt');
		expect(inner).toHaveBeenCalledWith(
			'https://example.com/robots.txt',
			expect.objectContaining({
				headers: expect.any(Headers),
			})
		);
		const sentHeaders = inner.mock.calls[0]![1]!.headers as Headers;
		expect(sentHeaders.get('User-Agent')).toBe(SCANNER_USER_AGENT);
	});

	it('does not overwrite a caller-supplied User-Agent', async () => {
		const inner = vi.fn(async () => textResponse('', false));
		const gated = withRobotsGate(inner);
		await gated('https://example.com/robots.txt', { headers: { 'User-Agent': 'Custom/1.0' } });
		const sentHeaders = inner.mock.calls[0]![1]!.headers as Headers;
		expect(sentHeaders.get('User-Agent')).toBe('Custom/1.0');
	});

	it('allows a path with no robots.txt (fetch failure = fail-open)', async () => {
		const inner = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) throw new Error('network error');
			return textResponse('ok');
		});
		const gated = withRobotsGate(inner);
		const res = await gated('https://example.com/');
		expect(await res.text()).toBe('ok');
	});

	it('allows a path when robots.txt has no matching Disallow', async () => {
		const inner = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) return textResponse('User-agent: *\nDisallow: /private\n');
			return textResponse('ok');
		});
		const gated = withRobotsGate(inner);
		const res = await gated('https://example.com/');
		expect(await res.text()).toBe('ok');
	});

	it('rejects with RobotsDisallowedError for a disallowed path', async () => {
		const inner = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) return textResponse('User-agent: *\nDisallow: /\n');
			return textResponse('should not be reached');
		});
		const gated = withRobotsGate(inner);
		await expect(gated('https://example.com/')).rejects.toBeInstanceOf(RobotsDisallowedError);
	});

	it('fetches robots.txt at most once per hostname across repeated calls', async () => {
		const robotsFetches = vi.fn();
		const inner = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) {
				robotsFetches();
				return textResponse('User-agent: *\nDisallow: /private\n');
			}
			return textResponse('ok');
		});
		const gated = withRobotsGate(inner);
		await gated('https://example.com/a');
		await gated('https://example.com/b');
		await gated('https://example.com/c');
		expect(robotsFetches).toHaveBeenCalledTimes(1);
	});

	it('never routes a /robots.txt request itself through the gate', async () => {
		const inner = vi.fn(async () => textResponse('User-agent: *\nDisallow: /\n'));
		const gated = withRobotsGate(inner);
		// Would throw RobotsDisallowedError if the gate applied to itself (Disallow: /).
		await expect(gated('https://example.com/robots.txt')).resolves.toBeInstanceOf(Response);
	});

	it('selects the named UA group over the wildcard group', async () => {
		const inner = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) {
				return textResponse(
					'User-agent: *\nDisallow: /\n\nUser-agent: BlackVeil-Security-Scanner\nAllow: /\n'
				);
			}
			return textResponse('ok');
		});
		const gated = withRobotsGate(inner);
		const res = await gated('https://example.com/');
		expect(await res.text()).toBe('ok');
	});
});
