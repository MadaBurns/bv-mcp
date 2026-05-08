// safeFetch is the boundary used by tool wrappers (BIMI logo fetch, HTTP
// redirect follower, MTA-STS policy fetch, ...) to gate outbound requests to
// attacker-controllable URLs. H2/H3 fix from 2026-05-08 security audit.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { safeFetch } from '../src/lib/safe-fetch';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('safeFetch', () => {
	it('throws TypeError for blocked internal hostnames', async () => {
		const fetchSpy = vi.spyOn(globalThis, 'fetch');
		await expect(safeFetch('https://something.internal/path')).rejects.toThrow(TypeError);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('throws for non-https schemes', async () => {
		const fetchSpy = vi.spyOn(globalThis, 'fetch');
		await expect(safeFetch('http://example.com/')).rejects.toThrow(/blocked/i);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('throws for userinfo-spoofed URLs', async () => {
		const fetchSpy = vi.spyOn(globalThis, 'fetch');
		await expect(safeFetch('https://attacker@example.com/')).rejects.toThrow(/blocked/i);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('throws for IP literals', async () => {
		const fetchSpy = vi.spyOn(globalThis, 'fetch');
		await expect(safeFetch('https://169.254.169.254/latest/meta-data')).rejects.toThrow(/blocked/i);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('delegates to fetch for valid public HTTPS URLs', async () => {
		const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
			new Response('ok', { status: 200 }),
		);
		const res = await safeFetch('https://example.com/');
		expect(res.status).toBe(200);
		expect(fetchSpy).toHaveBeenCalledOnce();
	});
});
