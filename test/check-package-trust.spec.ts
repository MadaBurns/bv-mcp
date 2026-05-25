// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => vi.restoreAllMocks());

function reconBinding(body: unknown, status = 200) {
	return {
		fetch: vi.fn(async () =>
			new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
		),
	};
}

describe('checkPackageTrust', () => {
	it('returns an unprovisioned info result when binding is absent', async () => {
		const { checkPackageTrust } = await import('../src/tools/check-package-trust');
		const r = await checkPackageTrust({ registry: 'npm', package: 'left-pad' }, {});
		expect(r.findings.some(f => f.metadata?.unprovisioned === true)).toBe(true);
		expect(r.passed).toBe(true);
	});

	it('maps a MALICIOUS verdict to a critical finding', async () => {
		const { checkPackageTrust } = await import('../src/tools/check-package-trust');
		const binding = reconBinding({ verdict: 'MALICIOUS', confidence: 'HIGH', signals: [{ severity: 'critical', detail: 'postinstall exfil' }] });
		const r = await checkPackageTrust({ registry: 'npm', package: 'evil-pkg', version: '9.9.9' }, { reconBinding: binding, reconAuthToken: 'tok' });
		expect(r.findings.some(f => f.severity === 'critical')).toBe(true);
		expect(r.passed).toBe(false);
	});

	it('maps a SAFE verdict to a passing result', async () => {
		const { checkPackageTrust } = await import('../src/tools/check-package-trust');
		const binding = reconBinding({ verdict: 'SAFE', confidence: 'HIGH', signals: [] });
		const r = await checkPackageTrust({ registry: 'npm', package: 'react' }, { reconBinding: binding, reconAuthToken: 'tok' });
		expect(r.passed).toBe(true);
	});
});
