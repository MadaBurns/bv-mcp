// SPDX-License-Identifier: BUSL-1.1

/**
 * `check_dane_https` wrapper — TLSA pin verification over the operator-only
 * BV_TLS_PROBE binding (#841), KILL-SWITCHED since 3.75.1 (`DANE_PIN_VERIFICATION_ENABLED`).
 *
 * The package ladder (verified 100 > absent / unverified 95 > mismatch 75; a probe with
 * no certificate = the unverified low, partial only when transient) is pinned in
 * packages/dns-checks/src/__tests__/checks/dane-pin-verification.test.ts and stays
 * reachable there through an injected certificate. THIS file pins the wrapper's contract
 * while the switch is off: with the binding present the probe is NEVER called for DANE
 * and the pin reports the permanent `probe_vantage_intercepted` sub-state at 95 — never
 * a verdict in either direction — because the probe's Browser Rendering vantage is
 * TLS-intercepted (Mockttp re-signs every non-Cloudflare origin), which made 3.75.0
 * score a correct pin (fedoraproject.org) as a `high` mismatch.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, dnssecResponse, tlsaResponse } from './helpers/dns-mock';
import { LEAF_SPKI_SHA256, STALE_SHA256, servedCertificate } from '../packages/dns-checks/src/__tests__/checks/served-certificate.fixture';

const { restore } = setupFetchMock();
const TLS_PROBE_AUTH_TOKEN = 'tls-probe-dane-spec-key-32-bytes-minimum';

afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

/** DoH mock: DNSSEC on, and the given TLSA RRset at _443._tcp.example.com. */
function mockDns(tlsa: Array<{ usage: number; selector: number; matchingType: number; certData: string }>) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (url.includes('_443._tcp.example.com') && (url.includes('type=TLSA') || url.includes('type=52'))) {
			return Promise.resolve(
				tlsa.length > 0
					? tlsaResponse('_443._tcp.example.com', tlsa)
					: createDohResponse([{ name: '_443._tcp.example.com', type: 52 }], []),
			);
		}
		if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
			return Promise.resolve(dnssecResponse('example.com', true));
		}
		return Promise.resolve(createDohResponse([], []));
	});
}

function probeBinding(body: unknown, status = 200) {
	return {
		fetch: vi.fn(
			async (_input: RequestInfo | URL, _init?: RequestInit) =>
				new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
		),
	};
}

const PIN_CURRENT = { usage: 3, selector: 1, matchingType: 1, certData: LEAF_SPKI_SHA256 };
const PIN_STALE = { usage: 3, selector: 1, matchingType: 1, certData: STALE_SHA256 };
/** What a Mockttp-fronted probe returns: a capture whose SPKI matches nothing the zone pins. */
const PROBE_WITH_CERT = { reachable: true, minVersion: 'TLS1.2', maxVersion: 'TLS1.3', certificate: servedCertificate('example.com') };

async function run(binding?: ReturnType<typeof probeBinding>, extra: Record<string, unknown> = {}) {
	const { checkDaneHttps } = await import('../src/tools/check-dane-https');
	return checkDaneHttps('example.com', undefined, { tlsProbeBinding: binding, tlsProbeAuthToken: TLS_PROBE_AUTH_TOKEN, ...extra });
}

function interceptedLow(result: Awaited<ReturnType<typeof run>>) {
	const low = result.findings.find((f) => f.title.startsWith('DANE TLSA configured'))!;
	expect(low.severity).toBe('low');
	expect(low.metadata?.certificateMatchVerified).toBe(false);
	expect(low.metadata?.certificateProbe).toBe('failed');
	expect(low.metadata?.notAssessedReason).toBe('probe_vantage_intercepted');
	expect(low.metadata?.inconclusive).toBeUndefined();
	return low;
}

describe('checkDaneHttps — pin verification over BV_TLS_PROBE is kill-switched (3.75.1)', () => {
	it('the switch is OFF: flipping it needs a capture source that is not TLS-intercepted', async () => {
		const { DANE_PIN_VERIFICATION_ENABLED } = await import('../src/lib/tls-probe-binding');
		expect(DANE_PIN_VERIFICATION_ENABLED).toBe(false);
	});

	it('a pin the probe capture WOULD match → still 95 unverified, and the probe is never called', async () => {
		mockDns([PIN_CURRENT]);
		const binding = probeBinding(PROBE_WITH_CERT);
		const result = await run(binding);
		expect(binding.fetch).not.toHaveBeenCalled();
		expect(result.score).toBe(95);
		expect(result.passed).toBe(true);
		expect(result.partial).toBeUndefined();
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.some((f) => f.metadata?.certificateMatchVerified === true)).toBe(false);
		interceptedLow(result);
	});

	it('a pin the probe capture would NOT match → 95 unverified, never the 3.75.0 high mismatch', async () => {
		mockDns([PIN_STALE]);
		const binding = probeBinding(PROBE_WITH_CERT);
		const result = await run(binding);
		expect(binding.fetch).not.toHaveBeenCalled();
		expect(result.score).toBe(95);
		expect(result.partial).toBeUndefined();
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
		const low = interceptedLow(result);
		expect(low.metadata?.servedLeafSpkiSha256).toBeUndefined();
		expect(low.metadata?.pinned).toBeUndefined();
	});

	it('the intercepted-vantage reason is PERMANENT: not partial, so the result caches normally', async () => {
		mockDns([PIN_STALE]);
		const result = await run(probeBinding(PROBE_WITH_CERT));
		expect(result.partial).toBeUndefined();
		const { isTransientDanePinReason } = await import('@blackveil/dns-checks');
		expect(isTransientDanePinReason('probe_vantage_intercepted')).toBe(false);
	});

	it('a failing (503) or throwing binding is indistinguishable — no call is made either way', async () => {
		mockDns([PIN_STALE]);
		const failing = probeBinding({ error: 'server error' }, 503);
		const a = await run(failing);
		expect(failing.fetch).not.toHaveBeenCalled();
		mockDns([PIN_STALE]);
		const throwing = { fetch: vi.fn(async () => Promise.reject(new Error('binding exploded'))) };
		const b = await run(throwing);
		expect(throwing.fetch).not.toHaveBeenCalled();
		for (const result of [a, b]) {
			expect(result.score).toBe(95);
			expect(result.partial).toBeUndefined();
			interceptedLow(result);
		}
	});

	it('is LAZY: no TLSA record → the probe is never called, 95 unchanged, no sub-state metadata', async () => {
		mockDns([]);
		const binding = probeBinding(PROBE_WITH_CERT);
		const result = await run(binding);
		expect(binding.fetch).not.toHaveBeenCalled();
		expect(result.score).toBe(95);
		expect(result.partial).toBeUndefined();
		expect(result.findings[0].title).toBe('No DANE TLSA for HTTPS');
	});

	it('binding absent → identical to the two-argument call (self-host posture, 95 low, not partial, no probe metadata)', async () => {
		mockDns([PIN_STALE]);
		const { checkDaneHttps } = await import('../src/tools/check-dane-https');
		const plain = await checkDaneHttps('example.com');
		mockDns([PIN_STALE]);
		const emptyOpts = await run(undefined);
		expect(emptyOpts).toEqual(plain);
		expect(plain.score).toBe(95);
		expect(plain.partial).toBeUndefined();
		const low = plain.findings.find((f) => f.title.startsWith('DANE TLSA configured'))!;
		expect(low.severity).toBe('low');
		expect(low.metadata?.certificateMatchVerified).toBe(false);
		expect(low.metadata?.certificateProbe).toBeUndefined();
		expect(low.metadata?.notAssessedReason).toBeUndefined();
	});

	it('a budget never reaches the binding while the switch is off (nothing to meter)', async () => {
		mockDns([PIN_CURRENT]);
		const binding = probeBinding(PROBE_WITH_CERT);
		const result = await run(binding, { budgetMs: 1 });
		expect(binding.fetch).not.toHaveBeenCalled();
		expect(result.score).toBe(95);
		expect(result.partial).toBeUndefined();
		interceptedLow(result);
	});

	it('the projection stays correct for a future trustworthy capture (the switch, not the projection, is the guard)', async () => {
		const { servedCertificateFromProbe } = await import('../src/lib/tls-probe-binding');
		const projected = servedCertificateFromProbe(PROBE_WITH_CERT as never, 'example.com');
		expect(projected.servedCertificate?.leafSpkiSha256).toBe(LEAF_SPKI_SHA256);
	});
});
