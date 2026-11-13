// SPDX-License-Identifier: BUSL-1.1

// Regression coverage for the "stale-after-deploy" cache bug: scan/check results
// were keyed by domain only, so a deploy kept serving pre-deploy results until the
// TTL expired. The fix threads BOTH the server version AND the dns-checks (scoring)
// version into every cache key — a bump to EITHER auto-invalidates the cache. The
// dns-checks version is essential: a scoring-only recalibration deploy does not move
// SERVER_VERSION, yet must still cold-start the cache (2026-06-01 parity finding).

import { describe, it, expect } from 'vitest';
import { buildCheckCacheKey, buildScanCacheKey, buildScanCheckInflightKey, TLS_PROBE_KEY_SEGMENT } from '../src/lib/cache';
import { resolveScanCacheKey } from '../src/tools/scan-domain';
import { SERVER_VERSION } from '../src/lib/server-version';
import { PARITY_CORPUS_VERSION } from '@blackveil/dns-checks';

describe('buildCheckCacheKey', () => {
	it('includes the server version and the dns-checks version', () => {
		const key = buildCheckCacheKey('example.com', 'mx');
		expect(key).toContain(`v${SERVER_VERSION}`);
		expect(key).toContain(`dc${PARITY_CORPUS_VERSION}`);
	});

	it('produces the canonical cache:v<server>-dc<dnsChecks>:<domain>:check:<name> shape', () => {
		expect(buildCheckCacheKey('example.com', 'mx')).toBe(
			`cache:v${SERVER_VERSION}-dc${PARITY_CORPUS_VERSION}:example.com:check:mx`
		);
	});

	it('changes when the server version changes', () => {
		const a = buildCheckCacheKey('example.com', 'mx', '1.0.0');
		const b = buildCheckCacheKey('example.com', 'mx', '1.0.1');
		expect(a).not.toBe(b);
	});

	it('changes when ONLY the dns-checks (scoring) version changes (server version fixed)', () => {
		const a = buildCheckCacheKey('example.com', 'mx', '3.5.0', '1.3.11');
		const b = buildCheckCacheKey('example.com', 'mx', '3.5.0', '1.3.12');
		expect(a).not.toBe(b);
		expect(a).toContain('dc1.3.11');
		expect(b).toContain('dc1.3.12');
	});
});

describe('buildScanCacheKey', () => {
	it('includes the server version and the dns-checks version', () => {
		const key = buildScanCacheKey('example.com');
		expect(key).toContain(`v${SERVER_VERSION}`);
		expect(key).toContain(`dc${PARITY_CORPUS_VERSION}`);
	});

	it('produces the canonical cache:v<server>-dc<dnsChecks>:<domain> shape for the default profile', () => {
		expect(buildScanCacheKey('example.com')).toBe(
			`cache:v${SERVER_VERSION}-dc${PARITY_CORPUS_VERSION}:example.com`
		);
	});

	it('appends an explicit profile when provided', () => {
		expect(buildScanCacheKey('example.com', 'api_heavy')).toBe(
			`cache:v${SERVER_VERSION}-dc${PARITY_CORPUS_VERSION}:example.com:profile:api_heavy`
		);
	});

	it('changes when the server version changes', () => {
		const a = buildScanCacheKey('example.com', undefined, '1.0.0');
		const b = buildScanCacheKey('example.com', undefined, '1.0.1');
		expect(a).not.toBe(b);
	});

	it('changes when ONLY the dns-checks (scoring) version changes', () => {
		const a = buildScanCacheKey('example.com', undefined, '3.5.0', '1.3.11');
		const b = buildScanCacheKey('example.com', undefined, '3.5.0', '1.3.12');
		expect(a).not.toBe(b);
	});
});

// SQ-567: the scan-level key (and the per-check in-flight key) is partitioned by TLS-probe CAPABILITY —
// a probe-eligible tier AND a bound probe binding — never by the raw tier name.
describe('resolveScanCacheKey TLS-probe partition (SQ-567)', () => {
	const binding = { fetch: (async () => new Response('{}')) as typeof fetch };
	const base = buildScanCacheKey('example.com');

	it('gives eligible and ineligible callers distinct keys when the probe binding is bound', () => {
		const anon = resolveScanCacheKey('example.com', { authTier: 'anon', tlsProbeBinding: binding });
		const owner = resolveScanCacheKey('example.com', { authTier: 'owner', tlsProbeBinding: binding });
		expect(anon).toBe(base);
		expect(owner).toBe(`${base}:${TLS_PROBE_KEY_SEGMENT}`);
		expect(owner).not.toBe(anon);
	});

	it('partitions every probe-eligible tier identically and no ineligible tier', () => {
		for (const tier of ['developer', 'enterprise', 'partner', 'owner']) {
			expect(resolveScanCacheKey('example.com', { authTier: tier, tlsProbeBinding: binding })).toBe(`${base}:tls-probe`);
		}
		for (const tier of ['anon', 'free', 'agent', undefined]) {
			expect(resolveScanCacheKey('example.com', { authTier: tier, tlsProbeBinding: binding })).toBe(base);
		}
	});

	it('keeps one shared key for every caller when the probe binding is NOT bound', () => {
		const keys = ['anon', 'free', 'agent', 'developer', 'enterprise', 'partner', 'owner'].map((authTier) =>
			resolveScanCacheKey('example.com', { authTier }),
		);
		expect(new Set(keys)).toEqual(new Set([base]));
		expect(resolveScanCacheKey('example.com')).toBe(base);
		expect(resolveScanCacheKey('example.com', { authTier: 'owner', tlsProbeBinding: undefined })).toBe(base);
	});

	it('composes with an explicit profile and treats profile "auto" as the default key', () => {
		expect(resolveScanCacheKey('example.com', { profile: 'mail_enabled', authTier: 'owner', tlsProbeBinding: binding })).toBe(
			`${buildScanCacheKey('example.com', 'mail_enabled')}:tls-probe`,
		);
		expect(resolveScanCacheKey('example.com', { profile: 'mail_enabled', authTier: 'anon', tlsProbeBinding: binding })).toBe(
			buildScanCacheKey('example.com', 'mail_enabled'),
		);
		expect(resolveScanCacheKey('example.com', { profile: 'auto', authTier: 'owner', tlsProbeBinding: binding })).toBe(`${base}:tls-probe`);
	});

	it('leaves the authoritative_dns_infra key on its ":active" gate suffix alone (that profile runs neither ssl nor dane_https)', () => {
		const infra = buildScanCacheKey('example.com', 'authoritative_dns_infra');
		expect(resolveScanCacheKey('example.com', { profile: 'authoritative_dns_infra', authTier: 'owner', tlsProbeBinding: binding })).toBe(
			`${infra}:active`,
		);
		expect(resolveScanCacheKey('example.com', { profile: 'authoritative_dns_infra', authTier: 'anon', tlsProbeBinding: binding })).toBe(infra);
	});

	it('partitions the per-check in-flight key only when a variant is passed', () => {
		const plain = buildScanCheckInflightKey('example.com', 'ssl');
		expect(buildScanCheckInflightKey('example.com', 'ssl', TLS_PROBE_KEY_SEGMENT)).toBe(`${plain}:tls-probe`);
		expect(buildScanCheckInflightKey('example.com', 'ssl', undefined)).toBe(plain);
	});
});
