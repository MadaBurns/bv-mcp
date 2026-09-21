// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import infraProbeWorker, {
	handleAuthoritativeDnsProbe,
	handleDelegationConsistencyProbe,
	handleRootServerSetProbe,
} from '../src/workers/infra-probe';
import { ROOT_HINTS } from '../src/lib/authoritative-dns-infra/root-hints';
import { RecordType } from '../src/lib/dns-types';
import type { AuthoritativeProbeDependencies } from '../src/lib/authoritative-dns-infra/authoritative-probe';
import type { RootSetProbeDependencies } from '../src/lib/authoritative-dns-infra/root-set-probe';
import type { DirectDnsResponse } from '../src/lib/authoritative-dns-infra/dns-tcp';

function response(overrides: Partial<DirectDnsResponse>): DirectDnsResponse {
	return { aa: false, ra: false, tc: false, rcode: 0, answers: [], authority: [], additional: [], ...overrides };
}

/**
 * Routes authoritative-dns / root-server-set requests through the injectable handlers with
 * the given dependencies, bypassing the default `fetch` dispatcher (which has no injection
 * point) — the same pattern the pre-existing delegation-consistency tests already use.
 */
function injectedInfraProbe(
	authoritativeDeps: AuthoritativeProbeDependencies,
	rootSetDeps: RootSetProbeDependencies,
): { fetch: typeof globalThis.fetch } {
	return {
		fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
			const request = new Request(input, init);
			if (request.url.includes('/probe/authoritative-dns')) return handleAuthoritativeDnsProbe(request, authoritativeDeps);
			if (request.url.includes('/probe/root-server-set')) return handleRootServerSetProbe(request, rootSetDeps);
			return infraProbeWorker.fetch(request);
		}) as unknown as typeof globalThis.fetch,
	};
}

/** Healthy injected dependencies for a delegated zone ('example.com', two nameservers). */
function healthyAuthoritativeDeps(): AuthoritativeProbeDependencies {
	return {
		recursiveQuery: async (name: string, type: string) =>
			name === 'example.com' && type === 'NS' ? ['ns1.example.com', 'ns2.example.com'] : [],
		resolveAddresses: async (nameserver: string, type: 'A' | 'AAAA') => {
			const table: Record<string, Record<'A' | 'AAAA', string[]>> = {
				'ns1.example.com': { A: ['1.1.1.1'], AAAA: [] },
				'ns2.example.com': { A: ['1.0.0.1'], AAAA: [] },
			};
			return table[nameserver]?.[type] ?? [];
		},
		openSession: async () => ({
			query: async (_name: string, type: number) => {
				if (type === RecordType.SOA) {
					return response({ aa: true, answers: [{ name: 'example.com', type: RecordType.SOA, data: '2026092201' }] });
				}
				if (type === RecordType.NS) {
					return response({
						aa: true,
						answers: [
							{ name: 'example.com', type: RecordType.NS, data: 'ns1.example.com' },
							{ name: 'example.com', type: RecordType.NS, data: 'ns2.example.com' },
						],
					});
				}
				if (type === RecordType.DNSKEY) {
					return response({
						aa: true,
						answers: [
							{ name: 'example.com', type: RecordType.DNSKEY, data: '' },
							{ name: 'example.com', type: RecordType.RRSIG, data: '' },
						],
					});
				}
				return response({ rcode: 5 }); // unassigned/recursion-canary qtype -> refused (good)
			},
			close: async () => undefined,
		}),
	};
}

/** Healthy injected dependencies for the root-server-set lane: every root hint answers NS/SOA/DNSKEY authoritatively. */
function healthyRootSetDeps(): RootSetProbeDependencies {
	return {
		now: () => new Date('2026-09-22T00:00:00.000Z'),
		openSession: async () => ({
			query: async (_name: string, type: number) => {
				if (type === RecordType.NS) {
					return response({ aa: true, answers: ROOT_HINTS.map((hint) => ({ name: '', type: RecordType.NS, data: hint.name })) });
				}
				if (type === RecordType.SOA) return response({ aa: true, answers: [{ name: '', type: RecordType.SOA, data: '2026092200' }] });
				return response({ aa: true, answers: [{ name: '', type: RecordType.DNSKEY, data: '' }] });
			},
			close: async () => undefined,
		}),
	};
}

describe('infra probe worker', () => {
	it('rejects invalid authoritative DNS probe payloads', async () => {
		const response = await infraProbeWorker.fetch(new Request('https://infra-probe.internal/probe/authoritative-dns', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ hostname: '' }),
		}));

		expect(response.status).toBe(400);
		const body = await response.json() as { error?: string };
		expect(body.error).toBe('invalid_hostname');
	});

	it('rejects an oversized chunked probe body before JSON parsing', async () => {
		const response = await infraProbeWorker.fetch(new Request('https://infra-probe.internal/probe/authoritative-dns', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ hostname: 'a'.repeat(2000) }),
		}));

		expect(response.status).toBe(413);
		await expect(response.json()).resolves.toEqual({ error: 'request_body_too_large' });
	});

	it('rejects non-POST requests with 405 on every probe route', async () => {
		for (const path of ['/probe/authoritative-dns', '/probe/delegation-consistency', '/probe/root-server-set']) {
			const res = await infraProbeWorker.fetch(new Request(`https://infra-probe.internal${path}`, { method: 'GET' }));
			expect(res.status).toBe(405);
			await expect(res.json()).resolves.toEqual({ error: 'method_not_allowed' });
		}
	});

	it('returns a fixed authoritative-probe failure without exposing exception details', async () => {
		const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
		try {
			const res = await handleAuthoritativeDnsProbe(
				new Request('https://infra-probe.internal/probe/authoritative-dns', {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ hostname: 'example.com' }),
				}),
				{
					// `recursiveQuery`/session failures are caught internally by design (the
					// lane must never throw a raw error for an ordinary probe failure) — the
					// unguarded `now()` call at the top of `probeAuthoritativeDns` is the one
					// seam that surfaces an exception here, exactly like the delegation
					// handler's own failure test uses `now`.
					now: () => {
						throw new Error('secret resolver endpoint and stack');
					},
				},
			);

			expect(res.status).toBe(502);
			await expect(res.json()).resolves.toEqual({ error: 'authoritative_probe_failed' });
			expect(consoleError).toHaveBeenCalledWith('Authoritative DNS probe failed');
		} finally {
			consoleError.mockRestore();
		}
	});

	it('returns a fixed root-server-set-probe failure without exposing exception details', async () => {
		const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
		try {
			const res = await handleRootServerSetProbe(
				new Request('https://infra-probe.internal/probe/root-server-set', { method: 'POST' }),
				{
					now: () => {
						throw new Error('secret internal clock detail');
					},
				},
			);

			expect(res.status).toBe(502);
			await expect(res.json()).resolves.toEqual({ error: 'root_server_set_probe_failed' });
			expect(consoleError).toHaveBeenCalledWith('Root server set probe failed');
		} finally {
			consoleError.mockRestore();
		}
	});

	it('accepts only a literal `true` for activeProbes — a truthy non-boolean runs zero AXFR/CHAOS traffic', async () => {
		const openAxfrSocket = vi.fn();
		const deps: AuthoritativeProbeDependencies = { ...healthyAuthoritativeDeps(), openAxfrSocket };

		const res = await handleAuthoritativeDnsProbe(
			new Request('https://infra-probe.internal/probe/authoritative-dns', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				// A string 'true' is truthy but not the literal boolean — must still read as false.
				body: JSON.stringify({ hostname: 'example.com', activeProbes: 'true' }),
			}),
			deps,
		);

		expect(res.status).toBe(200);
		expect(openAxfrSocket).not.toHaveBeenCalled();
		const evidence = await res.json() as { operationalExposure?: { chaosVersion?: string; chaosId?: string } };
		expect(evidence.operationalExposure?.chaosVersion).toBeUndefined();
		expect(evidence.operationalExposure?.chaosId).toBeUndefined();
	});

	it('runs CHAOS active probes for a literal activeProbes: true', async () => {
		const deps = healthyAuthoritativeDeps();
		const baseOpenSession = deps.openSession!;
		deps.openSession = async (...args) => {
			const session = await baseOpenSession(...args);
			return {
				...session,
				query: async (name: string, type: number, options?: { qclass?: number }) => {
					if (type === RecordType.TXT && options?.qclass === 3) {
						return response({ aa: true, answers: [{ name, type: RecordType.TXT, data: 'BIND 9.18.0' }] });
					}
					return session.query(name, type, options);
				},
			};
		};

		const res = await handleAuthoritativeDnsProbe(
			new Request('https://infra-probe.internal/probe/authoritative-dns', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ hostname: 'example.com', activeProbes: true }),
			}),
			deps,
		);

		expect(res.status).toBe(200);
		const evidence = await res.json() as { operationalExposure?: { chaosVersion?: string } };
		expect(evidence.operationalExposure?.chaosVersion).toBe('BIND 9.18.0');
	});

	// The seam, not the units: each lane passed its own spec while the pair once published
	// 100 / passed for lanes that queried nothing (#696/#812), and separately abstained silently
	// on a non-authoritative answer (found by live smoke). Drive the REAL worker handlers
	// through the REAL tools with injected fake sessions.
	it('measures both infra tools end-to-end through the real worker handlers with healthy injected sessions', async () => {
		const { checkAuthoritativeDnsInfra } = await import('../src/tools/check-authoritative-dns-infra');
		const { checkRootServerSet } = await import('../src/tools/check-root-server-set');
		const infraProbe = injectedInfraProbe(healthyAuthoritativeDeps(), healthyRootSetDeps());

		const authoritative = await checkAuthoritativeDnsInfra('example.com', { infraProbe });
		const rootSet = await checkRootServerSet({ infraProbe });

		for (const result of [authoritative, rootSet]) {
			expect(result.checkStatus).toBeUndefined();
			expect(result.score).toBeGreaterThan(0);
			expect(result.findings.every((finding) => finding.metadata?.unprovisioned !== true)).toBe(true);
		}

		const authSummary = authoritative.metadata?.capabilitySummary as { passed: string[] };
		expect(authSummary.passed).toEqual(expect.arrayContaining(['authoritative_aa_flag', 'dns53_tcp_reachability']));

		// Proves the official_root_hints_match fix too: a genuine pass requires a live
		// authoritative observation (observedRootServers here), not a bare hints self-match.
		const rootSummary = rootSet.metadata?.capabilitySummary as { passed: string[] };
		expect(rootSummary.passed).toContain('official_root_hints_match');
		expect(rootSummary.passed).toContain('root_priming_ns_set');
	});

	it('makes both infra tools abstain end-to-end when every injected session fails', async () => {
		const { checkAuthoritativeDnsInfra } = await import('../src/tools/check-authoritative-dns-infra');
		const { checkRootServerSet } = await import('../src/tools/check-root-server-set');
		const connectionRefused = async (): Promise<never> => {
			throw new Error('connection refused');
		};
		const infraProbe = injectedInfraProbe(
			{
				recursiveQuery: async (name: string, type: string) => (name === 'example.com' && type === 'NS' ? ['ns1.example.com'] : []),
				resolveAddresses: async (_ns: string, type: 'A' | 'AAAA') => (type === 'A' ? ['1.1.1.1'] : []),
				openSession: connectionRefused,
			},
			{ now: () => new Date('2026-09-22T00:00:00.000Z'), openSession: connectionRefused },
		);

		for (const result of [
			await checkAuthoritativeDnsInfra('example.com', { infraProbe }),
			await checkRootServerSet({ infraProbe }),
		]) {
			expect(result).toMatchObject({ passed: false, score: 0, checkStatus: 'error', partial: true });
			const summary = result.metadata?.capabilitySummary as { passed: string[]; failed: string[] };
			expect(summary.passed).toEqual([]);
			expect(summary.failed).toEqual([]);
			// A connection failure is transient/environmental, not a provisioning state.
			expect(result.findings.every((finding) => finding.metadata?.unprovisioned !== true)).toBe(true);
		}
	});

	it('returns ordinary-zone parent/child delegation evidence through the injected probe seam', async () => {
		const response = await handleDelegationConsistencyProbe(
			new Request('https://infra-probe.internal/probe/delegation-consistency', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ hostname: 'Example.COM.' }),
			}),
			{
				recursiveQuery: async (name, type) => (name === 'com' && type === 'NS' ? ['a.gtld-servers.net'] : []),
				directQuery: async (server) => server === 'a.gtld-servers.net'
					? {
						aa: false, rcode: 0, answers: [],
						authority: [{ name: 'example.com', type: 2, data: 'ns.provider.net' }],
						additional: [],
					}
					: {
						aa: true, rcode: 0,
						answers: [{ name: 'example.com', type: 2, data: 'ns.provider.net' }],
						authority: [], additional: [],
					},
				now: () => new Date('2026-08-07T00:00:00.000Z'),
			},
		);

		expect(response.status).toBe(200);
		await expect(response.json()).resolves.toMatchObject({
			hostname: 'example.com',
			parentZone: 'com',
			parentDelegationNs: ['ns.provider.net'],
			childObservations: [{ nameserver: 'ns.provider.net', aaFlag: true }],
		});
	});

	it('returns a fixed delegation failure without exposing exception details', async () => {
		const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
		try {
			const response = await handleDelegationConsistencyProbe(
				new Request('https://infra-probe.internal/probe/delegation-consistency', {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ hostname: 'example.com' }),
				}),
				{
					recursiveQuery: async () => [],
					now: () => { throw new Error('secret resolver endpoint and stack'); },
				},
			);

			expect(response.status).toBe(502);
			await expect(response.json()).resolves.toEqual({ error: 'delegation_probe_failed' });
			expect(consoleError).toHaveBeenCalledWith('Delegation consistency probe failed');
		} finally {
			consoleError.mockRestore();
		}
	});
});

// The lane specs (root-set-probe.spec.ts, authoritative-probe.spec.ts) inject fake sessions
// exclusively, so a defect in the REAL socket path is invisible to them — exactly how the
// root-zone `encodeName` bug (dns-tcp.ts, fixed e1155ee72) shipped as "always abstains" and
// was only caught by a live smoke test (US-4 story decision log #5). Drive the REAL
// `openDnsTcpSession` (the sidecar's actual default) through the mocked `cloudflare:sockets`
// virtual module, end to end through the worker handler and the tool.
let connectSpy: Mock<(...args: unknown[]) => unknown>;

vi.mock('cloudflare:sockets', () => ({
	connect: (...args: unknown[]) => connectSpy(...args),
}));

interface FakeSocket {
	opened: Promise<unknown>;
	closed: Promise<void>;
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	close: ReturnType<typeof vi.fn>;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
	const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
	let offset = 0;
	for (const part of parts) {
		output.set(part, offset);
		offset += part.length;
	}
	return output;
}

function uint16(value: number): Uint8Array {
	const bytes = new Uint8Array(2);
	new DataView(bytes.buffer).setUint16(0, value);
	return bytes;
}

function uint32(value: number): Uint8Array {
	const bytes = new Uint8Array(4);
	new DataView(bytes.buffer).setUint32(0, value);
	return bytes;
}

function encodeWireName(name: string): Uint8Array {
	const encoder = new TextEncoder();
	const parts: Uint8Array[] = [];
	for (const label of name.split('.')) {
		if (label.length === 0) continue;
		const bytes = encoder.encode(label);
		parts.push(new Uint8Array([bytes.length]), bytes);
	}
	parts.push(new Uint8Array([0]));
	return concatBytes(...parts);
}

function wireRecord(owner: Uint8Array, type: number, rdata: Uint8Array): Uint8Array {
	return concatBytes(owner, uint16(type), uint16(1), uint32(60), uint16(rdata.length), rdata);
}

const ROOT_OWNER = new Uint8Array([0]); // the root's wire name is a single zero-length octet

function rootZoneFrame(id: number, ancount: number, records: Uint8Array[]): Uint8Array {
	const header = new Uint8Array(12);
	const view = new DataView(header.buffer);
	view.setUint16(0, id);
	view.setUint16(2, 0x8400); // QR + AA, RCODE=0
	view.setUint16(6, ancount);
	return concatBytes(header, ...records);
}

function rootNsFrame(id: number): Uint8Array {
	const records = ROOT_HINTS.map((hint) => wireRecord(ROOT_OWNER, RecordType.NS, encodeWireName(hint.name)));
	return rootZoneFrame(id, records.length, records);
}

function rootSoaFrame(id: number, serial: number): Uint8Array {
	const mname = encodeWireName('a.root-servers.net');
	const rname = encodeWireName('nstld.verisign-grs.com');
	const rdata = concatBytes(mname, rname, uint32(serial), uint32(1800), uint32(900), uint32(604_800), uint32(86_400));
	return rootZoneFrame(id, 1, [wireRecord(ROOT_OWNER, RecordType.SOA, rdata)]);
}

function rootDnskeyFrame(id: number): Uint8Array {
	return rootZoneFrame(id, 1, [wireRecord(ROOT_OWNER, RecordType.DNSKEY, new Uint8Array(0))]);
}

/** Every socket answers NS, then SOA, then DNSKEY, in that order — matching root-set-probe.ts's
 * own sequential `ROOT_ZONE_QUERIES` (ns, soa, dnskey) on a single session. */
function fakeHealthyRootSocket(): FakeSocket {
	let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
	let callIndex = 0;
	const builders = [(id: number) => rootNsFrame(id), (id: number) => rootSoaFrame(id, 2026092200), (id: number) => rootDnskeyFrame(id)];
	const readable = new ReadableStream<Uint8Array>({
		start(c) {
			controller = c;
		},
	});
	const writable = new WritableStream<Uint8Array>({
		write(chunk: Uint8Array) {
			const view = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
			const queryId = view.getUint16(2); // framed: [len(2)][id(2) ...]
			const frame = builders[callIndex % builders.length](queryId);
			callIndex += 1;
			controller?.enqueue(concatBytes(uint16(frame.length), frame));
		},
	});
	return {
		opened: Promise.resolve({}),
		closed: new Promise<void>(() => undefined),
		readable,
		writable,
		close: vi.fn(async () => undefined),
	};
}

describe('infra probe worker (real socket path)', () => {
	it('drives the real openDnsTcpSession through a mocked cloudflare:sockets module, end to end through the worker handler and the tool', async () => {
		connectSpy = vi.fn(() => fakeHealthyRootSocket());

		const infraProbe = {
			fetch: ((input: RequestInfo | URL, init?: RequestInit) => handleRootServerSetProbe(
				new Request(input, init),
				{ now: () => new Date('2026-09-22T00:00:00.000Z') }, // openSession defaults to the REAL openDnsTcpSession
			)) as unknown as typeof globalThis.fetch,
		};

		const { checkRootServerSet } = await import('../src/tools/check-root-server-set');
		const result = await checkRootServerSet({ infraProbe });

		// Before e1155ee72, `buildDirectDnsQuery('.', ...)` threw for every query this lane
		// issues, so the real path always fell through to the no-contact abstention — the lane
		// spec (fake sessions) could never see that. A real, non-abstaining measured result
		// here proves the codec fix holds through the full worker+tool call chain.
		expect(connectSpy).toHaveBeenCalled();
		expect(result.checkStatus).toBeUndefined();
		expect(result.score).toBeGreaterThan(0);
		const summary = result.metadata?.capabilitySummary as { passed: string[] };
		expect(summary.passed).toContain('official_root_hints_match');
		expect(summary.passed).toContain('root_priming_ns_set');
	});
});
