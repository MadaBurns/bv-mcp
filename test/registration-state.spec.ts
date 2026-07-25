import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, nxdomainResponse, servfailResponse } from './helpers/dns-mock';
import type { RegistrationState } from '../src/lib/registration-state';

const { restore } = setupFetchMock();
afterEach(() => restore());

/** Route a DoH fetch by the queried record type. */
function routeByType(map: Record<string, Response | (() => never)>) {
	globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
		const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const type = new URL(href).searchParams.get('type') ?? '';
		const entry = map[type];
		if (!entry) return createDohResponse([], []);
		if (typeof entry === 'function') return entry();
		return entry;
	}) as unknown as typeof fetch;
}

function nsAnswer(domain: string, hosts: string[]) {
	return createDohResponse(
		[{ name: domain, type: 2 }],
		hosts.map((h) => ({ name: domain, type: 2, TTL: 300, data: h })),
	);
}

/**
 * Build a DoH response with the TC (truncated) flag set. `createDohResponse`
 * has no TC option, so this is constructed inline rather than extending the
 * shared `dns-mock.ts` helper (out of scope for this task).
 */
function truncatedResponse(domain: string, type: number, status = 0): Response {
	const json = {
		Status: status,
		TC: true,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name: domain, type }],
		Answer: [],
	};
	return {
		ok: true,
		status: 200,
		json: () => Promise.resolve(json),
	} as unknown as Response;
}

describe('resolveRegistration', () => {
	it('returns registered with NS evidence when NS records are present', async () => {
		routeByType({ NS: nsAnswer('bnz.nz', ['ns1.bnz.co.nz.']), SOA: createDohResponse([], []) });
		const { resolveRegistration } = await import('../src/lib/registration-state');
		const result = await resolveRegistration('bnz.nz');
		expect(result.state).toBe('registered');
		if (result.state !== 'registered') throw new Error('narrowing');
		expect(result.ns).toEqual(['ns1.bnz.co.nz.']);
		expect(result.evidence).toContain('ns');
	});

	it('returns unregistered ONLY for NXDOMAIN', async () => {
		routeByType({ NS: nxdomainResponse('bnz.kiwi'), SOA: nxdomainResponse('bnz.kiwi', 6) });
		const { resolveRegistration } = await import('../src/lib/registration-state');
		expect((await resolveRegistration('bnz.kiwi')).state).toBe('unregistered');
	});

	it('returns unknown/servfail for SERVFAIL — never unregistered', async () => {
		routeByType({ NS: servfailResponse('bnz.com'), SOA: servfailResponse('bnz.com', 6) });
		const { resolveRegistration } = await import('../src/lib/registration-state');
		const result = await resolveRegistration('bnz.com');
		expect(result.state).toBe('unknown');
		if (result.state !== 'unknown') throw new Error('narrowing');
		expect(result.reason).toBe('servfail');
	});

	it('returns unknown/refused for REFUSED — never unregistered', async () => {
		routeByType({
			NS: createDohResponse([{ name: 'bnz.com', type: 2 }], [], { status: 5 }),
			SOA: createDohResponse([{ name: 'bnz.com', type: 6 }], [], { status: 5 }),
		});
		const { resolveRegistration } = await import('../src/lib/registration-state');
		const result = await resolveRegistration('bnz.com');
		expect(result.state).toBe('unknown');
		if (result.state !== 'unknown') throw new Error('narrowing');
		expect(result.reason).toBe('refused');
	});

	it('returns unknown/truncated when TC is set — even with an NXDOMAIN rcode', async () => {
		// Status: 3 (NXDOMAIN) alongside TC: true asserts the priority order in
		// registration-state.ts: the truncation check runs BEFORE the NXDOMAIN
		// check, so a truncated answer must never resolve to `unregistered`
		// even when its rcode looks like NXDOMAIN.
		routeByType({
			NS: truncatedResponse('bnz.com', 2, 3),
			SOA: truncatedResponse('bnz.com', 6, 3),
		});
		const { resolveRegistration } = await import('../src/lib/registration-state');
		const result = await resolveRegistration('bnz.com');
		expect(result.state).toBe('unknown');
		if (result.state !== 'unknown') throw new Error('narrowing');
		expect(result.reason).toBe('truncated');
	});

	it('returns unknown/timeout when the transport throws', async () => {
		globalThis.fetch = vi.fn(async () => {
			throw new DOMException('The operation timed out.', 'TimeoutError');
		}) as unknown as typeof fetch;
		const { resolveRegistration } = await import('../src/lib/registration-state');
		const result = await resolveRegistration('slow.example');
		expect(result.state).toBe('unknown');
		if (result.state !== 'unknown') throw new Error('narrowing');
		expect(result.reason).toBe('timeout');
	});

	it('escalates to A when NS and SOA are NOERROR-empty, and reports registered on an A hit', async () => {
		routeByType({
			NS: createDohResponse([], []),
			SOA: createDohResponse([], []),
			A: createDohResponse([{ name: 'x.example', type: 1 }], [{ name: 'x.example', type: 1, TTL: 60, data: '203.0.113.1' }]),
		});
		const { resolveRegistration } = await import('../src/lib/registration-state');
		const result = await resolveRegistration('x.example');
		expect(result.state).toBe('registered');
		if (result.state !== 'registered') throw new Error('narrowing');
		expect(result.evidence).toContain('a');
	});

	it('returns unknown/empty_noerror when nothing answers and nothing errors', async () => {
		routeByType({ NS: createDohResponse([], []), SOA: createDohResponse([], []), A: createDohResponse([], []) });
		const { resolveRegistration } = await import('../src/lib/registration-state');
		const result = await resolveRegistration('statements.bnz.co.nz');
		expect(result.state).toBe('unknown');
		if (result.state !== 'unknown') throw new Error('narrowing');
		expect(result.reason).toBe('empty_noerror');
	});

	it('deduplicates repeat lookups through a shared cache', async () => {
		const fetchSpy = vi.fn(async () => nsAnswer('bnz.nz', ['ns1.bnz.co.nz.']));
		globalThis.fetch = fetchSpy as unknown as typeof fetch;
		const { resolveRegistration } = await import('../src/lib/registration-state');
		const cache = new Map<string, Promise<RegistrationState>>();
		const first = await resolveRegistration('bnz.nz', undefined, cache);
		const callsAfterFirst = fetchSpy.mock.calls.length;
		const second = await resolveRegistration('bnz.nz', undefined, cache);
		expect(second).toEqual(first);
		expect(fetchSpy.mock.calls.length).toBe(callsAfterFirst);
	});

	it('shares one in-flight lookup between concurrent callers', async () => {
		const fetchSpy = vi.fn(async () => nsAnswer('bnz.nz', ['ns1.bnz.co.nz.']));
		globalThis.fetch = fetchSpy as unknown as typeof fetch;
		const { resolveRegistration } = await import('../src/lib/registration-state');
		const cache = new Map<string, Promise<RegistrationState>>();
		const [a, b] = await Promise.all([resolveRegistration('bnz.nz', undefined, cache), resolveRegistration('bnz.nz', undefined, cache)]);
		expect(a).toEqual(b);
		expect(fetchSpy.mock.calls.length).toBe(3); // ONE lookup (NS + SOA + internal query), not two
	});
});
