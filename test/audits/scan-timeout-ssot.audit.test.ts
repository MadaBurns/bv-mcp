import { describe, expect, it } from 'vitest';
import scanDomainSource from '../../src/tools/scan-domain.ts?raw';
import { PER_CHECK_TIMEOUT_MS, SCAN_TIMEOUT_MS } from '../../src/lib/config';
import { resolveScanTimeoutBudget } from '../../src/tools/scan/timeouts';

describe('scan timeout SSOT audit', () => {
	it('keeps scan-domain from redeclaring timeout constants', () => {
		expect(scanDomainSource).not.toMatch(/const\s+SCAN_TIMEOUT_MS\s*=/);
		expect(scanDomainSource).not.toMatch(/const\s+PER_CHECK_TIMEOUT_MS\s*=/);
		expect(scanDomainSource).toContain("from './scan/timeouts'");
	});

	it('keeps runtime timeout defaults tied to config constants', () => {
		const budget = resolveScanTimeoutBudget();

		expect(budget.scanTimeoutMs).toBe(SCAN_TIMEOUT_MS);
		expect(budget.perCheckTimeoutMs).toBe(PER_CHECK_TIMEOUT_MS);
	});
});
