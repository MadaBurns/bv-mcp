/**
 * Dedicated test for the DnsQueryError defense-in-depth catch in checkDnssec.
 * Uses hoisted vi.mock to replace @blackveil/dns-checks before any imports,
 * which is required because the Workers pool caches module namespaces.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { DnsQueryError } from '../src/lib/dns';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

const mockCheckDNSSEC = vi.fn();

vi.mock('@blackveil/dns-checks', async (importOriginal) => {
	const orig = await importOriginal<typeof import('@blackveil/dns-checks')>();
	return {
		...orig,
		checkDNSSEC: (...args: unknown[]) => mockCheckDNSSEC(...args),
	};
});

afterEach(() => {
	restore();
	mockCheckDNSSEC.mockReset();
});

describe('checkDnssec — DnsQueryError catch', () => {
	it('returns info finding when DnsQueryError escapes checkDNSSEC', async () => {
		mockCheckDNSSEC.mockRejectedValue(new DnsQueryError('connection refused', 'example.com', 'A'));

		const { checkDnssec } = await import('../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');

		expect(result.category).toBe('dnssec');
		const infoFinding = result.findings.find((f) => f.title === 'DNSSEC check could not complete');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.severity).toBe('info');
		expect(infoFinding!.detail).toContain('DNS query failed');
		expect(infoFinding!.metadata?.checkStatus).toBe('error');
	});

	it('re-throws non-DnsQueryError errors', async () => {
		mockCheckDNSSEC.mockRejectedValue(new TypeError('unexpected'));

		const { checkDnssec } = await import('../src/tools/check-dnssec');
		await expect(checkDnssec('example.com')).rejects.toThrow(TypeError);
	});
});
