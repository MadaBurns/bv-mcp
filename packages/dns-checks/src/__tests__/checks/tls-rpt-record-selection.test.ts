// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-556 item 2 — `checkTLSRPT` selects TLS-RPT records individually (RFC 8460 §3).
 *
 * Each element of the TXT answer is already one complete RR (the DNS layer joins a
 * multi-string RR). The check used to `join('')` every TXT RR at `_smtp._tls` and read the
 * TLS-RPT record as "v=TLSRPTv1 to end of string", so an unrelated TXT record became part
 * of the reporting URI, and two TLS-RPT records fused into one "configured" record.
 */

import { describe, expect, it, vi } from 'vitest';
import { checkTLSRPT } from '../../checks/check-tlsrpt';
import type { DNSQueryFunction } from '../../types';

function txtDNS(records: string[]): DNSQueryFunction {
	return vi.fn(async (domain: string) => (domain === '_smtp._tls.example.com' ? records : []));
}

describe('checkTLSRPT — per-record selection', () => {
	it('ignores an unrelated TXT record at _smtp._tls: configured, rua exact, no invalid-URI finding', async () => {
		const result = await checkTLSRPT('example.com', txtDNS(['v=TLSRPTv1; rua=mailto:a@example.com', 'unrelated=value with space']));

		const configured = result.findings.find((f) => f.title === 'TLS-RPT record configured');
		expect(configured).toBeDefined();
		expect(configured!.detail.endsWith(': v=TLSRPTv1; rua=mailto:a@example.com')).toBe(true);
		expect(result.findings.some((f) => /invalid reporting URI/i.test(f.title))).toBe(false);
		expect(result.findings.some((f) => /Multiple TLS-RPT records/i.test(f.title))).toBe(false);
	});

	it('reports two TLS-RPT records as multiple, and not also as configured with a fused rua', async () => {
		const result = await checkTLSRPT(
			'example.com',
			txtDNS(['v=TLSRPTv1; rua=mailto:a@example.com', 'v=TLSRPTv1; rua=mailto:b@example.com']),
		);

		const multiple = result.findings.find((f) => /Multiple TLS-RPT records/i.test(f.title));
		expect(multiple).toBeDefined();
		expect(multiple!.severity).toBe('low');
		expect(result.findings.some((f) => f.title === 'TLS-RPT record configured')).toBe(false);
		expect(result.findings.some((f) => /invalid reporting URI/i.test(f.title))).toBe(false);
		// A record is still PUBLISHED; RFC 8460 just applies none of them.
		expect(result.recordPresent).toBe(true);
	});
});
