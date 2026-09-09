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
	it('returns the retryable, non-cacheable dns_error abstention when DnsQueryError escapes checkDNSSEC', async () => {
		mockCheckDNSSEC.mockRejectedValue(new DnsQueryError('connection refused', 'example.com', 'A'));

		const { checkDnssec } = await import('../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');

		expect(result.category).toBe('dnssec');
		// Same shape as buildDnsErrorResult / safeCheck: scan_domain's transient-zero retry keys on
		// checkStatus 'error' && score 0, and `partial` keeps it out of the 5-minute cache. The
		// previous info-only score-100 shape satisfied neither (#900).
		expect(result).toMatchObject({ checkStatus: 'error', score: 0, passed: false, partial: true });
		const errorFinding = result.findings.find((f) => f.title === 'DNSSEC check error');
		expect(errorFinding).toBeDefined();
		expect(errorFinding!.metadata?.errorKind).toBe('dns_error');
	});

	it('re-throws non-DnsQueryError errors', async () => {
		mockCheckDNSSEC.mockRejectedValue(new TypeError('unexpected'));

		const { checkDnssec } = await import('../src/tools/check-dnssec');
		await expect(checkDnssec('example.com')).rejects.toThrow(TypeError);
	});
});
