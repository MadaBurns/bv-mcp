// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it } from 'vitest';
import type { CtSourceAttempt } from '../src/lib/ct-coverage';
import type { SubdomainDiscoveryResult } from '../src/tools/discover-subdomains';

async function render(domain: string, attempts: CtSourceAttempt[]): Promise<string> {
	const { buildCtCoverage } = await import('../src/lib/ct-coverage');
	const { formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
	const result: SubdomainDiscoveryResult = {
		domain,
		totalSubdomains: 0,
		totalCertificates: 0,
		subdomains: [],
		wildcardCerts: 0,
		expiredCerts: 0,
		uniqueIssuers: [],
		issues: [],
		sourceUnavailable: true,
		coverage: buildCtCoverage(attempts),
	};
	return formatSubdomainDiscovery(result, 'full');
}

describe('#1147 failure guidance follows the source budget and observed refusal', () => {
	it('reports the public-suffix crt.sh budget, with the ordinary budget as a control', async () => {
		const { CT_SOURCE_TIMEOUT_MS, CT_SOURCE_TIMEOUT_MS_PSL_APEX } = await import('../src/tools/discover-subdomains');
		const attempts: CtSourceAttempt[] = [{ source: 'crtsh', outcome: 'timeout', contributed: false }];
		expect(await render('co.nz', attempts)).toContain(`${CT_SOURCE_TIMEOUT_MS_PSL_APEX / 1000}s per-source CT budget`);
		expect(await render('example.test', attempts)).toContain(`${CT_SOURCE_TIMEOUT_MS / 1000}s per-source CT budget`);
	});

	it('keeps the certstream budget independent from the public-suffix crt.sh budget', async () => {
		const { CT_SOURCE_TIMEOUT_MS, CT_SOURCE_TIMEOUT_MS_PSL_APEX } = await import('../src/tools/discover-subdomains');
		const output = await render('co.nz', [
			{ source: 'certstream', outcome: 'timeout', contributed: false },
			{ source: 'crtsh', outcome: 'timeout', contributed: false },
		]);
		expect(output).toContain(`certstream did not answer inside this tool's ${CT_SOURCE_TIMEOUT_MS / 1000}s`);
		expect(output).toContain(`crtsh did not answer inside this tool's ${CT_SOURCE_TIMEOUT_MS_PSL_APEX / 1000}s`);
	});

	it('does not infer the credential tier or exhausted quota from a 429', async () => {
		const output = await render('example.test', [{ source: 'certspotter', outcome: 'rate_limited', contributed: false }]);
		expect(output).toContain('rate-limited this caller (HTTP 429)');
		expect(output).toContain('Back off');
		expect(output).not.toMatch(/unauthenticated|quota is spent|retry shortly|retry is worthwhile/i);
	});

	it('names the independent Certspotter budget without asserting an upstream status or repeatability', async () => {
		const { CERTSPOTTER_TIMEOUT_MS } = await import('../src/tools/discover-subdomains');
		const output = await render('example.test', [{ source: 'certspotter', outcome: 'timeout', contributed: false }]);
		expect(output).toContain(`${CERTSPOTTER_TIMEOUT_MS / 1000}s per-source CT budget (CERTSPOTTER_TIMEOUT_MS)`);
		expect(output).not.toMatch(/HTTP 504|deterministic|identical retry will time out/i);
		expect(output).not.toContain('8s per-source CT budget');
	});
});
