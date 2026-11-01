// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { checkSSL } from '../../checks/check-ssl';
import { withRobotsGate, type RobotsResolutionRecord } from '../../robots-gate';
import type { FetchFunction } from '../../types';

function waitForAbort(signal: AbortSignal | null | undefined): Promise<Response> {
	return new Promise((_resolve, reject) => {
		if (!signal) return reject(new Error('Missing composed signal'));
		if (signal.aborted) return reject(signal.reason);
		signal.addEventListener('abort', () => reject(signal.reason), { once: true });
	});
}

describe('HTTPS redirects through the robots gate', () => {
	it('cancels a slow cross-host robots lookup at the chain deadline and withholds HSTS', async () => {
		const records: RobotsResolutionRecord[] = [];
		let targetRequested = false;
		let robotsAborted = false;
		const transport: FetchFunction = async (url, init) => {
			if (url === 'https://example.test/robots.txt') return new Response('', { status: 200 });
			if (url === 'https://redirect.example.test/robots.txt') {
				try { return await waitForAbort(init?.signal); }
				finally { robotsAborted = true; }
			}
			if (url === 'https://example.test') return new Response(null, { status: 307, headers: { location: 'https://redirect.example.test/' } });
			targetRequested = true;
			return new Response('', { status: 200 });
		};
		const result = await checkSSL('example.test', withRobotsGate(transport, { onRobotsResolution: (record) => records.push(record) }), { timeout: 500 });
		expect(robotsAborted).toBe(true);
		expect(targetRequested).toBe(false);
		expect(result).toMatchObject({ checkStatus: 'timeout', partial: true, passed: false });
		expect(result.findings.some((finding) => finding.metadata?.missingControl)).toBe(false);
		expect(records).toContainEqual(expect.objectContaining({ host: 'redirect.example.test', resolution: 'timeout', elapsedMs: expect.any(Number) }));
		expect(result.metadata?.httpsOperations).toEqual([
			expect.objectContaining({ host: 'example.test', method: 'HEAD', outcome: 'response', status: 307 }),
			expect.objectContaining({ host: 'redirect.example.test', method: 'HEAD', outcome: 'timeout', elapsedMs: expect.any(Number), remainingMs: expect.any(Number) }),
		]);
	});

	it('cancels a memo wait without cancelling another caller or issuing its target request', async () => {
		let release!: (response: Response) => void;
		let robotsCalls = 0;
		let targetCalls = 0;
		const transport: FetchFunction = async (url) => {
			if (url.endsWith('/robots.txt')) {
				robotsCalls++;
				return new Promise<Response>((resolve) => { release = resolve; });
			}
			targetCalls++;
			return new Response('ok');
		};
		const gate = withRobotsGate(transport);
		const first = gate('https://example.test/');
		const controller = new AbortController();
		const second = gate('https://example.test/', { signal: controller.signal });
		const rejected = expect(second).rejects.toMatchObject({ name: 'AbortError' });
		controller.abort();
		await rejected;
		expect(targetCalls).toBe(0);
		release(new Response('User-agent: *\nAllow: /'));
		await first;
		expect(robotsCalls).toBe(1);
		expect(targetCalls).toBe(1);
	});

	it('does not turn a robots denial or SSRF rejection into a timeout', async () => {
		for (const blockedBy of ['robots', 'ssrf']) {
			const transport: FetchFunction = async (url) => {
				if (url === 'https://example.test/robots.txt') return new Response('');
				if (url === 'https://redirect.example.test/robots.txt') {
					if (blockedBy === 'ssrf') throw new TypeError('Outbound fetch blocked: timeout.localhost');
					return new Response('User-agent: *\nDisallow: /');
				}
				if (url === 'https://example.test') return new Response(null, { status: 307, headers: { location: 'https://redirect.example.test/' } });
				if (blockedBy === 'ssrf') throw new TypeError('Outbound fetch blocked: timeout.localhost');
				throw new Error('Unexpected target fetch');
			};
			const result = await checkSSL('example.test', withRobotsGate(transport));
			expect(result.checkStatus).toBe('error');
			expect(result.metadata?.httpsOperations).toContainEqual(expect.objectContaining({ outcome: blockedBy === 'robots' ? 'robots_disallowed' : 'ssrf_rejected' }));
		}
	});
});
