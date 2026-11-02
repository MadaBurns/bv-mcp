// SPDX-License-Identifier: BUSL-1.1
//
// Characterization of the direct-dispatch `switch` arms of handleToolsCall (the tools that are
// not in TOOL_REGISTRY). Written against the code BEFORE the switch moved to
// src/handlers/direct-dispatch.ts, so it pins what each arm returns and what it records in the
// access log (the `logEvent` JSON line on console.log) and in the tool_call analytics event.
// A change here means the extraction changed behaviour, not that the test needs updating.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, createDohResponse, httpResponse } from './helpers/dns-mock';
import type { ScanDomainResult } from '../src/tools/scan-domain';

const { restore } = setupFetchMock();

function mockAllChecks() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
				if (url.includes('_domainkey.')) return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}
			if (url.includes('type=NS') || url.includes('type=2'))
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			if (url.includes('type=CAA') || url.includes('type=257'))
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('example.com', true));
			return Promise.resolve(createDohResponse([], []));
		}
		return Promise.resolve(httpResponse('OK'));
	});
}

/** The JSON access-log lines (logEvent → console.log) recorded for one tool. */
function accessLogs(spy: { mock: { calls: unknown[][] } }, tool: string): Record<string, unknown>[] {
	const logs: Record<string, unknown>[] = [];
	for (const call of spy.mock.calls) {
		if (typeof call[0] !== 'string') continue;
		try {
			const log = JSON.parse(call[0]) as Record<string, unknown>;
			if (log.tool === tool) logs.push(log);
		} catch {
			// not a JSON log line
		}
	}
	return logs;
}

function analyticsCapture(): { analytics: import('../src/lib/analytics').AnalyticsClient; events: Record<string, unknown>[] } {
	const events: Record<string, unknown>[] = [];
	const analytics = {
		emitToolEvent: (event: Record<string, unknown>) => events.push(event),
	} as unknown as import('../src/lib/analytics').AnalyticsClient;
	return { analytics, events };
}

beforeEach(async () => {
	// Imported per test: the throw-path test resets the module graph.
	const { IN_MEMORY_CACHE } = await import('../src/lib/cache');
	IN_MEMORY_CACHE.clear();
});

afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

describe('direct-dispatch characterization: scan_domain', () => {
	it('returns the scan report and logs the grade with a summary of the scan', async () => {
		mockAllChecks();
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		const { analytics, events } = analyticsCapture();
		let captured: ScanDomainResult | undefined;
		const { handleToolsCall } = await import('../src/handlers/tools');

		const result = await handleToolsCall({ name: 'scan_domain', arguments: { domain: 'example.com' } }, undefined, {
			analytics,
			scanResultCapture: (scan) => {
				captured = scan;
			},
		});

		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text.startsWith('DNS Security Scan: example.com\n')).toBe(true);
		expect(result.content[1].text).toContain('STRUCTURED_RESULT');

		expect(captured).toBeDefined();
		const scan = captured!;
		const logs = accessLogs(consoleSpy, 'scan_domain');
		expect(logs).toHaveLength(1);
		expect(logs[0].severity).toBe('info');
		expect(logs[0].domain).toBe('example.com');
		expect(logs[0].result).toBe(scan.score.grade ?? 'ungraded');
		expect(logs[0].result).not.toBe('unknown');
		expect(logs[0].details).toEqual({
			grade: scan.score.grade,
			overall: scan.score.overall,
			cached: false,
			categoryCount: scan.checks.length,
			findingCount: scan.checks.reduce((n, c) => n + c.findings.length, 0),
		});

		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			toolName: 'scan_domain',
			isError: false,
			status: scan.score.overall === null ? 'inconclusive' : scan.score.overall >= 50 ? 'pass' : 'fail',
			cacheStatus: 'miss',
			outcomeReason: 'completed',
			unitsAttempted: scan.checks.length,
			unitsCompleted: scan.checks.filter((check) => !check.checkStatus || check.checkStatus === 'completed').length,
		});
	});
});

describe('direct-dispatch characterization: compare_domains', () => {
	it('returns the comparison and logs the compared count with the winner', async () => {
		mockAllChecks();
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		const { analytics, events } = analyticsCapture();
		const { handleToolsCall } = await import('../src/handlers/tools');

		const result = await handleToolsCall({ name: 'compare_domains', arguments: { domains: ['example.com', 'example.org'] } }, undefined, {
			analytics,
		});

		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text.startsWith('Domain Security Comparison\n')).toBe(true);

		const logs = accessLogs(consoleSpy, 'compare_domains');
		expect(logs).toHaveLength(1);
		expect(logs[0].severity).toBe('info');
		expect(logs[0].result).toBe('2/2 domains compared');
		// Both domains get identical mocked answers, so the comparison is a tie.
		expect(logs[0].details).toEqual({ totalDomains: 2, winner: null });

		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({ toolName: 'compare_domains', isError: false, status: 'pass', outcomeReason: 'completed' });
	});
});

describe('direct-dispatch characterization: get_benchmark', () => {
	it('returns the unavailable benchmark and logs the result status with the full result', async () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		const { analytics, events } = analyticsCapture();
		const { handleToolsCall } = await import('../src/handlers/tools');

		// No profileAccumulator binding: the benchmark abstains as not configured.
		const result = await handleToolsCall({ name: 'get_benchmark', arguments: {} }, undefined, { analytics });

		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text.startsWith('# Benchmark: mail_enabled\n')).toBe(true);

		const logs = accessLogs(consoleSpy, 'get_benchmark');
		expect(logs).toHaveLength(1);
		expect(logs[0].severity).toBe('info');
		expect(logs[0].result).toBe('unavailable');
		expect(logs[0].details).toEqual({ status: 'unavailable', profile: 'mail_enabled', reason: 'not_configured', retryable: false });

		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({ toolName: 'get_benchmark', isError: false, status: 'pass', outcomeReason: 'completed' });
	});
});

describe('direct-dispatch characterization: a throwing arm', () => {
	it('scan_domain rejecting returns the generic error and logs an error line with no result key', async () => {
		vi.resetModules();
		vi.doMock('../src/tools/scan-domain', async (importOriginal) => {
			const orig = await importOriginal<typeof import('../src/tools/scan-domain')>();
			return { ...orig, scanDomain: vi.fn().mockRejectedValue(new Error('characterization: scan exploded')) };
		});
		try {
			const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
			const { analytics, events } = analyticsCapture();
			const { handleToolsCall } = await import('../src/handlers/tools');

			const result = await handleToolsCall({ name: 'scan_domain', arguments: { domain: 'example.com' } }, undefined, { analytics });

			expect(result).toEqual({
				content: [
					{
						type: 'text',
						text: 'Error: An unexpected error occurred while running scan_domain. Retry the request — transient DNS failures are common.',
					},
				],
				isError: true,
			});

			const logs = accessLogs(consoleSpy, 'scan_domain');
			expect(logs).toHaveLength(1);
			const { timestamp, ...log } = logs[0];
			expect(typeof timestamp).toBe('string');
			expect(log).toEqual({
				severity: 'error',
				error: 'characterization: scan exploded',
				tool: 'scan_domain',
				domain: 'example.com',
				details: { argumentCount: 1, argumentKeys: ['domain'] },
			});
			expect('result' in logs[0]).toBe(false);

			expect(events).toHaveLength(1);
			expect(events[0]).toMatchObject({ toolName: 'scan_domain', isError: true, status: 'error', outcomeReason: 'internal_error' });
		} finally {
			vi.doUnmock('../src/tools/scan-domain');
			vi.resetModules();
		}
	});
});
