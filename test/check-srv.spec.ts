// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, srvResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Build an empty DoH response (no answers). */
function emptyResponse(name: string, type: number) {
	return createDohResponse([{ name, type }], []);
}

describe('checkSrv', () => {
	async function run(domain = 'example.com') {
		const { checkSrv } = await import('../src/tools/check-srv');
		return checkSrv(domain);
	}

	it('should return info finding when no SRV records found', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=SRV') || url.includes('type=33')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 33));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('srv');
		expect(result.passed).toBe(true);
		expect(result.findings.some((f) => f.title === 'No SRV service records found')).toBe(true);
	});

	it('should return info findings when SRV records are discovered', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('_imaps._tcp') && (url.includes('type=SRV') || url.includes('type=33'))) {
				return Promise.resolve(srvResponse('_imaps._tcp.example.com', [{ priority: 10, weight: 0, port: 993, target: 'mail.example.com' }]));
			}
			if (url.includes('type=SRV') || url.includes('type=33')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 33));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('srv');
		expect(result.passed).toBe(true);
		const discovered = result.findings.filter((f) => f.title.startsWith('SRV service discovered'));
		expect(discovered.length).toBeGreaterThanOrEqual(1);
	});

	it('should flag insecure IMAP protocol exposure', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			// Return IMAP plain-text but no IMAPS
			if (url.includes('_imap._tcp') && !url.includes('_imaps') && (url.includes('type=SRV') || url.includes('type=33'))) {
				return Promise.resolve(srvResponse('_imap._tcp.example.com', [{ priority: 10, weight: 0, port: 143, target: 'mail.example.com' }]));
			}
			if (url.includes('type=SRV') || url.includes('type=33')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 33));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('srv');
		const medium = result.findings.filter((f) => f.severity === 'medium');
		expect(medium.length).toBeGreaterThanOrEqual(1);
		expect(medium.some((f) => f.title.includes('Plain-text IMAP'))).toBe(true);
	});

	it('should flag autodiscover exposure', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('_autodiscover._tcp') && (url.includes('type=SRV') || url.includes('type=33'))) {
				return Promise.resolve(
					srvResponse('_autodiscover._tcp.example.com', [{ priority: 10, weight: 0, port: 443, target: 'autodiscover.example.com' }]),
				);
			}
			if (url.includes('type=SRV') || url.includes('type=33')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 33));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('srv');
		const low = result.findings.filter((f) => f.severity === 'low');
		expect(low.some((f) => f.title.includes('Autodiscover'))).toBe(true);
	});

	it('should handle DNS query failure for all probes gracefully', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('DNS failure'));

		const result = await run();
		expect(result.category).toBe('srv');
		expect(result.findings.length).toBeGreaterThan(0);
		const errorFinding = result.findings.find((f) => f.title === 'SRV DNS queries failed');
		expect(errorFinding).toBeDefined();
		expect(errorFinding!.severity).toBe('medium');
	});

	it('should include summary finding with service count', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('_imaps._tcp') && (url.includes('type=SRV') || url.includes('type=33'))) {
				return Promise.resolve(srvResponse('_imaps._tcp.example.com', [{ priority: 10, weight: 0, port: 993, target: 'mail.example.com' }]));
			}
			if (url.includes('_https._tcp') && (url.includes('type=SRV') || url.includes('type=33'))) {
				return Promise.resolve(srvResponse('_https._tcp.example.com', [{ priority: 10, weight: 0, port: 443, target: 'www.example.com' }]));
			}
			if (url.includes('type=SRV') || url.includes('type=33')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 33));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('srv');
		const summary = result.findings.find((f) => f.title.includes('Service footprint'));
		expect(summary).toBeDefined();
		expect(summary!.title).toContain('2 services');
	});

	it('should note partial failures when some probes fail', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=SRV') || url.includes('type=33')) {
				// Fail specifically the _imap._tcp and _pop3._tcp probes
				if (url.includes('_imap._tcp') || url.includes('_pop3._tcp')) {
					return Promise.reject(new Error('DNS timeout'));
				}
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 33));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('srv');
		// Should have a partial failures note
		const partialNote = result.findings.find((f) => f.title === 'Some SRV queries failed');
		expect(partialNote).toBeDefined();
		expect(partialNote!.severity).toBe('info');
	});
});
