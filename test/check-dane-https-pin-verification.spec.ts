// SPDX-License-Identifier: BUSL-1.1

/**
 * `check_dane_https` wrapper — TLSA pin verification over the operator-only
 * BV_TLS_PROBE binding (#841). The package ladder (verified 100 > absent / unverified 95 >
 * mismatch 75; a probe with no certificate = the unverified low, partial only when
 * transient) is pinned in
 * packages/dns-checks/src/__tests__/checks/dane-pin-verification.test.ts; THIS file
 * pins the wrapper's contract with the probe: what it sends, how each probe outcome
 * is projected, laziness, the budget signal, and the binding-absent identity.
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
const PROBE_WITH_CERT = { reachable: true, minVersion: 'TLS1.2', maxVersion: 'TLS1.3', certificate: servedCertificate('example.com') };

async function run(binding?: ReturnType<typeof probeBinding>, extra: Record<string, unknown> = {}) {
	const { checkDaneHttps } = await import('../src/tools/check-dane-https');
	return checkDaneHttps('example.com', undefined, { tlsProbeBinding: binding, tlsProbeAuthToken: TLS_PROBE_AUTH_TOKEN, ...extra });
}

describe('checkDaneHttps — pin verification over BV_TLS_PROBE (#841)', () => {
	it('sends host=<domain>&port=443 with the bearer, and a matching pin → 100 verified', async () => {
		mockDns([PIN_CURRENT]);
		const binding = probeBinding(PROBE_WITH_CERT);
		const result = await run(binding);
		expect(binding.fetch).toHaveBeenCalledOnce();
		const [url, init] = binding.fetch.mock.calls[0];
		expect(String(url)).toContain('host=example.com');
		expect(String(url)).toContain('port=443');
		expect((init as RequestInit).headers).toMatchObject({ Authorization: `Bearer ${TLS_PROBE_AUTH_TOKEN}` });
		expect(result.score).toBe(100);
		expect(result.passed).toBe(true);
		expect(result.partial).toBeUndefined();
		const verdict = result.findings.find((f) => f.metadata?.certificateMatchVerified !== undefined)!;
		expect(verdict.severity).toBe('info');
		expect(verdict.category).toBe('dane_https');
		expect(verdict.metadata?.certificateMatchVerified).toBe(true);
		expect(verdict.metadata?.matchedCertData).toBe(LEAF_SPKI_SHA256);
	});

	it('a stale pin → 75 with a high mismatch, category still scored (not partial, no checkStatus)', async () => {
		mockDns([PIN_STALE]);
		const result = await run(probeBinding(PROBE_WITH_CERT));
		expect(result.score).toBe(75);
		expect(result.passed).toBe(true);
		expect(result.partial).toBeUndefined();
		expect(result.checkStatus).toBeUndefined();
		const high = result.findings.find((f) => f.severity === 'high')!;
		expect(high.title).toBe('DANE TLSA pin does not match the served certificate for _443._tcp.example.com');
		expect(high.metadata?.certificateMatchVerified).toBe(false);
		expect(high.metadata?.servedLeafSpkiSha256).toBe(LEAF_SPKI_SHA256);
		expect(high.metadata?.pinned).toEqual([`3 1 1 ${STALE_SHA256}`]);
	});

	it.each([
		['cold-cache pending verdict', { error: 'probe pending — cache warming, retry shortly' }, 'certificate_probe_pending', true],
		[
			'capture failed: off-host redirect',
			{ reachable: true, minVersion: 'TLS1.2', certificateError: 'off-host redirect to www.example.com' },
			'off_host_redirect',
			false,
		],
		[
			'capture failed: no security state',
			{ reachable: true, minVersion: 'TLS1.2', certificateError: 'no security state' },
			'capture_failed',
			true,
		],
		[
			'certificate describes a different host',
			{ reachable: true, certificate: servedCertificate('www.example.com') },
			'host_mismatch',
			false,
		],
		['host unreachable', { reachable: false, error: 'connect timeout' }, 'unreachable', true],
		[
			'probe predates the contract (no certificate block)',
			{ reachable: true, minVersion: 'TLS1.2', maxVersion: 'TLS1.3' },
			'capture_failed',
			true,
		],
	])(
		'%s → unverified 95 (the same low as no-probe) + sub-state metadata; partial only when transient',
		async (_label, body, reason, partial) => {
			mockDns([PIN_STALE]);
			const result = await run(probeBinding(body));
			expect(result.score).toBe(95);
			expect(result.passed).toBe(true);
			expect(result.partial).toBe(partial ? true : undefined);
			expect(result.checkStatus).toBeUndefined();
			const low = result.findings.find((f) => f.title.startsWith('DANE TLSA configured'))!;
			expect(low.severity).toBe('low');
			expect(low.metadata?.notAssessedReason).toBe(reason);
			expect(low.metadata?.certificateProbe).toBe(reason === 'certificate_probe_pending' ? 'pending' : 'failed');
			expect(low.metadata?.certificateMatchVerified).toBe(false);
			expect(low.metadata?.inconclusive).toBeUndefined();
			expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
		},
	);

	it('binding present but failing (503) → probe_unavailable: 95, partial, never a verdict', async () => {
		mockDns([PIN_STALE]);
		const result = await run(probeBinding({ error: 'server error' }, 503));
		expect(result.score).toBe(95);
		expect(result.partial).toBe(true);
		expect(result.findings.find((f) => f.title.startsWith('DANE TLSA configured'))?.metadata?.notAssessedReason).toBe('probe_unavailable');
	});

	it('binding present but its fetch throws → probe_unavailable (fail-soft): 95, partial', async () => {
		mockDns([PIN_STALE]);
		const binding = { fetch: vi.fn(async () => Promise.reject(new Error('binding exploded'))) };
		const result = await run(binding);
		expect(result.score).toBe(95);
		expect(result.partial).toBe(true);
		expect(result.findings.find((f) => f.title.startsWith('DANE TLSA configured'))?.metadata?.notAssessedReason).toBe('probe_unavailable');
	});

	it('is LAZY: no TLSA record → the probe is never called, 95 unchanged', async () => {
		mockDns([]);
		const binding = probeBinding(PROBE_WITH_CERT);
		const result = await run(binding);
		expect(binding.fetch).not.toHaveBeenCalled();
		expect(result.score).toBe(95);
		expect(result.partial).toBeUndefined();
		expect(result.findings[0].title).toBe('No DANE TLSA for HTTPS');
	});

	it('binding absent → identical to the two-argument call (self-host posture, 95 low, not partial)', async () => {
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
	});

	it('a budget threads an AbortSignal into the binding call (a service binding is not fetch-wrapped)', async () => {
		mockDns([PIN_CURRENT]);
		const binding = probeBinding(PROBE_WITH_CERT);
		await run(binding, { budgetMs: 5_000 });
		const [, init] = binding.fetch.mock.calls[0];
		expect((init as RequestInit).signal).toBeInstanceOf(AbortSignal);
	});

	it('an already-exhausted budget aborts the probe → probe_unavailable (95, partial), not a verdict', async () => {
		mockDns([PIN_STALE]);
		const binding = {
			fetch: vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
				// Behave like a real binding: honour the signal.
				if (init?.signal?.aborted) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
				await new Promise<void>((resolve, reject) => {
					init?.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
					setTimeout(resolve, 2_000);
				});
				return new Response(JSON.stringify(PROBE_WITH_CERT), { status: 200, headers: { 'Content-Type': 'application/json' } });
			}),
		};
		const result = await run(binding, { budgetMs: 1 });
		expect(result.score).toBe(95);
		expect(result.partial).toBe(true);
		expect(result.findings.find((f) => f.title.startsWith('DANE TLSA configured'))?.metadata?.notAssessedReason).toBe('probe_unavailable');
	});
});
