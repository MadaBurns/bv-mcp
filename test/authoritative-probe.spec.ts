// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import { probeAuthoritativeDns } from '../src/lib/authoritative-dns-infra/authoritative-probe';
import type { DirectDnsResponse } from '../src/lib/authoritative-dns-infra/dns-tcp';
import { RecordType } from '../src/lib/dns-types';

function response(overrides: Partial<DirectDnsResponse>): DirectDnsResponse {
	return { aa: false, ra: false, tc: false, rcode: 0, answers: [], authority: [], additional: [], ...overrides };
}

function concat(...parts: Uint8Array[]): Uint8Array {
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

function encodeName(name: string): Uint8Array {
	const encoder = new TextEncoder();
	const parts: Uint8Array[] = [];
	for (const label of name.split('.')) {
		const bytes = encoder.encode(label);
		parts.push(new Uint8Array([bytes.length]), bytes);
	}
	parts.push(new Uint8Array([0]));
	return concat(...parts);
}

function rr(owner: Uint8Array, type: number, rdata: Uint8Array): Uint8Array {
	return concat(owner, uint16(type), uint16(1), uint32(60), uint16(rdata.length), rdata);
}

/** A self-contained NOERROR/AA response with QDCOUNT=0 and one SOA answer (no compression pointers needed). */
function soaAllowedAxfrFrame(id: number, zone: string, serial: number): Uint8Array {
	const header = new Uint8Array(12);
	const view = new DataView(header.buffer);
	view.setUint16(0, id);
	view.setUint16(2, 0x8400); // QR + AA
	view.setUint16(6, 1); // ANCOUNT = 1
	const owner = encodeName(zone);
	const rdata = concat(owner, owner, uint32(serial), uint32(3600), uint32(600), uint32(1_209_600), uint32(60));
	return concat(header, rr(owner, RecordType.SOA, rdata));
}

interface FakeAxfrSocket {
	opened: Promise<unknown>;
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	close: Mock<() => Promise<void>>;
	cancelled: boolean;
}

/**
 * Echoes framed response chunks (built from the outgoing query's transaction id) back on the
 * readable side, exactly like `fakeDnsSocket` in dns-tcp.spec.ts does for `openDnsTcpSession`.
 */
function fakeAxfrSocket(buildFrames: (queryId: number) => Uint8Array[]): FakeAxfrSocket {
	let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
	const state = { cancelled: false };
	const readable = new ReadableStream<Uint8Array>({
		start(c) {
			controller = c;
		},
		cancel() {
			state.cancelled = true;
		},
	});
	const writable = new WritableStream<Uint8Array>({
		write(chunk: Uint8Array) {
			const view = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
			const queryId = view.getUint16(2); // framed: [len(2)][id(2) ...]
			for (const frame of buildFrames(queryId)) controller?.enqueue(frame);
		},
	});
	return {
		opened: Promise.resolve(),
		readable,
		writable,
		close: vi.fn(async () => undefined),
		get cancelled() {
			return state.cancelled;
		},
	} as FakeAxfrSocket;
}

describe('probeAuthoritativeDns', () => {
	it('returns full measured evidence for a healthy zone and nothing extra', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) =>
			name === 'example.com' && type === 'NS' ? ['ns1.example.com', 'ns2.example.com'] : [],
		);
		const resolveAddresses = vi.fn(async (nameserver: string, type: 'A' | 'AAAA') => {
			const table: Record<string, Record<'A' | 'AAAA', string[]>> = {
				'ns1.example.com': { A: ['1.1.1.1'], AAAA: ['2606:4700:4700:0:0:0:0:1111'] },
				'ns2.example.com': { A: ['1.0.0.1'], AAAA: ['2606:4700:4700:0:0:0:0:1112'] },
			};
			return table[nameserver]?.[type] ?? [];
		});

		const openSession = vi.fn(async () => ({
			query: vi.fn(async (name: string, type: number) => {
				if (type === RecordType.SOA) return response({ aa: true, answers: [{ name: 'example.com', type: RecordType.SOA, data: '2026092201' }] });
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
				if (type === RecordType.A && name === 'example.com') return response({ aa: false, ra: false });
				return response({ rcode: 5 }); // unassigned qtype -> REFUSED (good)
			}),
			close: vi.fn(async () => undefined),
		}));

		const evidence = await probeAuthoritativeDns('Example.COM.', { recursiveQuery, resolveAddresses, openSession }, { activeProbes: false });

		expect(evidence.hostname).toBe('example.com');
		expect(evidence.reachability).toEqual({
			ipv4: { addresses: ['1.1.1.1', '1.0.0.1'], reachable: true },
			ipv6: { addresses: ['2606:4700:4700:0:0:0:0:1111', '2606:4700:4700:0:0:0:0:1112'], reachable: true },
			tcp53Reachable: true,
		});
		expect(evidence.authoritative).toEqual({ aaFlag: true, recursionAvailable: false, recursionRefused: true });
		expect(evidence.soaSerial).toEqual({
			serialsByNameserver: { 'ns1.example.com': 2026092201, 'ns2.example.com': 2026092201 },
			consistent: true,
		});
		expect(evidence.dnssec).toEqual({ dnskeyPresent: true, rrsigPresent: true });
		expect(evidence.operationalExposure).toEqual({ unsupportedQueriesRefused: true });
		expect(evidence.transportParity).toEqual({ ipv4Ipv6Parity: true });
		expect(evidence.zoneTransfer).toBeUndefined();
		expect(evidence.rootPriming).toBeUndefined();
		expect(evidence.errors).toBeUndefined();

		// Never sets fields outside this lane's measured set.
		expect(evidence).not.toHaveProperty('dnssec.validates');
		expect(evidence).not.toHaveProperty('dnssec.dsPresent');
		expect(evidence).not.toHaveProperty('reachability.udp53Reachable');
		expect(evidence).not.toHaveProperty('amplification');
		expect(evidence).not.toHaveProperty('largeResponse');
		expect(evidence).not.toHaveProperty('abuseResistance');
		expect(evidence).not.toHaveProperty('routing');
		expect(evidence).not.toHaveProperty('vantage');
		expect(evidence).not.toHaveProperty('operationalExposure.ptrRecords');
		expect(evidence).not.toHaveProperty('operationalExposure.rir');
		expect(evidence).not.toHaveProperty('operationalExposure.rdapHandle');
	});

	it('flags open recursion as recursionAvailable true', async () => {
		const recursionCanary = 'example.com';
		const recursiveQuery = vi.fn(async (name: string, type: string) => (name === 'other.example' && type === 'NS' ? ['ns1.other.example'] : []));
		const resolveAddresses = vi.fn(async (_nameserver: string, type: 'A' | 'AAAA') => (type === 'A' ? ['1.1.1.1'] : []));
		const openSession = vi.fn(async () => ({
			query: vi.fn(async (name: string, type: number) => {
				if (type === RecordType.A && name === recursionCanary) return response({ aa: false, ra: true });
				return response({ aa: true });
			}),
			close: vi.fn(async () => undefined),
		}));

		const evidence = await probeAuthoritativeDns('other.example', { recursiveQuery, resolveAddresses, openSession }, { activeProbes: false });

		expect(evidence.authoritative?.recursionAvailable).toBe(true);
		expect(evidence.authoritative?.recursionRefused).toBe(false);
	});

	it('detects AXFR is allowed from the first frame and proves the socket closed after it', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) => (name === 'example.com' && type === 'NS' ? ['ns1.example.com'] : []));
		const resolveAddresses = vi.fn(async (_nameserver: string, type: 'A' | 'AAAA') => (type === 'A' ? ['1.1.1.1'] : []));
		const openSession = vi.fn(async () => ({
			query: vi.fn(async () => response({ aa: true })),
			close: vi.fn(async () => undefined),
		}));

		// Deliver frame 1 (SOA answer) plus a second framed message representing transfer
		// continuation, both in one push, to prove readFirstFramedResponse's trailing-data
		// tolerance (and its cancel-after-frame-1 behaviour) is what this path actually uses.
		const axfrSocket = fakeAxfrSocket((id) => {
			const message = soaAllowedAxfrFrame(id, 'example.com', 2026092201);
			const frame1 = concat(uint16(message.length), message);
			const frame2 = concat(uint16(4), new Uint8Array([9, 9, 9, 9]));
			return [concat(frame1, frame2)];
		});
		const openAxfrSocket = vi.fn(async () => axfrSocket);

		const evidence = await probeAuthoritativeDns(
			'example.com',
			{ recursiveQuery, resolveAddresses, openSession, openAxfrSocket },
			{ activeProbes: true },
		);

		expect(evidence.zoneTransfer).toEqual({ axfrRefused: false });
		expect(openAxfrSocket).toHaveBeenCalledTimes(1);
		expect(axfrSocket.close).toHaveBeenCalledTimes(1);
		expect(axfrSocket.cancelled).toBe(true);
	});

	it('never opens CHAOS or AXFR sessions when activeProbes is false', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) => (name === 'example.com' && type === 'NS' ? ['ns1.example.com'] : []));
		const resolveAddresses = vi.fn(async (_nameserver: string, type: 'A' | 'AAAA') => (type === 'A' ? ['1.1.1.1'] : []));
		const queriedNames: string[] = [];
		const openSession = vi.fn(async () => ({
			query: vi.fn(async (name: string) => {
				queriedNames.push(name);
				return response({ aa: true });
			}),
			close: vi.fn(async () => undefined),
		}));
		const openAxfrSocket = vi.fn(async () => {
			throw new Error('should never be called');
		});

		const evidence = await probeAuthoritativeDns('example.com', { recursiveQuery, resolveAddresses, openSession, openAxfrSocket }, { activeProbes: false });

		expect(openAxfrSocket).not.toHaveBeenCalled();
		expect(queriedNames).not.toContain('version.bind');
		expect(queriedNames).not.toContain('id.server');
		expect(evidence.zoneTransfer).toBeUndefined();
		expect(evidence.operationalExposure?.chaosVersion).toBeUndefined();
		expect(evidence.operationalExposure?.chaosId).toBeUndefined();
	});

	it('leaves transport parity undefined, not false, when one family never answered', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) => (name === 'example.com' && type === 'NS' ? ['ns1.example.com'] : []));
		const resolveAddresses = vi.fn(async (_nameserver: string, type: 'A' | 'AAAA') => (type === 'A' ? ['1.1.1.1'] : []));
		const openSession = vi.fn(async () => ({
			query: vi.fn(async () => response({ aa: true })),
			close: vi.fn(async () => undefined),
		}));

		const evidence = await probeAuthoritativeDns('example.com', { recursiveQuery, resolveAddresses, openSession }, { activeProbes: false });

		expect(evidence.reachability?.ipv6).toBeUndefined();
		expect(evidence.transportParity).toBeUndefined();
	});

	it('reports soaSerial.consistent false on a serial mismatch across nameservers', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) =>
			name === 'example.com' && type === 'NS' ? ['ns1.example.com', 'ns2.example.com'] : [],
		);
		const resolveAddresses = vi.fn(async (nameserver: string, type: 'A' | 'AAAA') => {
			if (type !== 'A') return [];
			return nameserver === 'ns1.example.com' ? ['1.1.1.1'] : ['1.0.0.1'];
		});
		const openSession = vi.fn(async (address: string) => ({
			query: vi.fn(async (_name: string, type: number) => {
				if (type === RecordType.SOA) {
					const serial = address === '1.1.1.1' ? '100' : '200';
					return response({ aa: true, answers: [{ name: 'example.com', type: RecordType.SOA, data: serial }] });
				}
				return response({ aa: true });
			}),
			close: vi.fn(async () => undefined),
		}));

		const evidence = await probeAuthoritativeDns('example.com', { recursiveQuery, resolveAddresses, openSession }, { activeProbes: false });

		expect(evidence.soaSerial).toEqual({
			serialsByNameserver: { 'ns1.example.com': 100, 'ns2.example.com': 200 },
			consistent: false,
		});
	});

	it('abstains without any verdict field, not even aaFlag, when every session answers non-authoritatively', async () => {
		// Models a middlebox transparently intercepting TCP/53: it answers, but REFUSED/AA=0/RA=1 —
		// never proof it is the zone's real nameserver.
		const recursiveQuery = vi.fn(async (name: string, type: string) => (name === 'example.com' && type === 'NS' ? ['ns1.example.com'] : []));
		const resolveAddresses = vi.fn(async (_nameserver: string, type: 'A' | 'AAAA') => (type === 'A' ? ['1.1.1.1'] : []));
		const openSession = vi.fn(async () => ({
			query: vi.fn(async () => response({ aa: false, ra: true, rcode: 5 })),
			close: vi.fn(async () => undefined),
		}));

		const evidence = await probeAuthoritativeDns('example.com', { recursiveQuery, resolveAddresses, openSession }, { activeProbes: false });

		expect(evidence).toEqual({ hostname: 'example.com', checkedAt: expect.any(String), errors: ['raw_dns_probe_no_authoritative_answer'] });
		expect(evidence.authoritative?.recursionAvailable).toBeUndefined();
	});

	it('takes verdicts only from the AA=1 server when mixed with an intercepted one, and reports aaFlag false', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) =>
			name === 'example.com' && type === 'NS' ? ['ns1.example.com', 'ns2.example.com'] : [],
		);
		const resolveAddresses = vi.fn(async (nameserver: string, type: 'A' | 'AAAA') => {
			if (type !== 'A') return [];
			return nameserver === 'ns1.example.com' ? ['1.1.1.1'] : ['1.0.0.1'];
		});
		const queryCallsByAddress: Record<string, number> = {};
		const openSession = vi.fn(async (address: string) => ({
			query: vi.fn(async (_name: string, type: number) => {
				queryCallsByAddress[address] = (queryCallsByAddress[address] ?? 0) + 1;
				if (address === '1.1.1.1') {
					// The genuine authoritative nameserver.
					if (type === RecordType.SOA) {
						return response({ aa: true, answers: [{ name: 'example.com', type: RecordType.SOA, data: '2026092201' }] });
					}
					if (type === RecordType.DNSKEY) return response({ aa: true, answers: [{ name: 'example.com', type: RecordType.DNSKEY, data: '' }] });
					return response({ aa: true });
				}
				// An intercepting middlebox: answers, but never authoritatively.
				return response({ aa: false, ra: true, rcode: 0 });
			}),
			close: vi.fn(async () => undefined),
		}));

		const evidence = await probeAuthoritativeDns('example.com', { recursiveQuery, resolveAddresses, openSession }, { activeProbes: false });

		expect(evidence.authoritative?.aaFlag).toBe(false);
		expect(evidence.dnssec).toEqual({ dnskeyPresent: true, rrsigPresent: false });
		expect(evidence.errors).toBeUndefined();
		// Nothing but the zone SOA query ran against the intercepted session.
		expect(queryCallsByAddress['1.0.0.1']).toBe(1);
		expect(queryCallsByAddress['1.1.1.1']).toBeGreaterThan(1);
	});

	it('abstains with no-contact and zero verdict fields when every session fails', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) => (name === 'example.com' && type === 'NS' ? ['ns1.example.com'] : []));
		const resolveAddresses = vi.fn(async (_nameserver: string, type: 'A' | 'AAAA') => (type === 'A' ? ['1.1.1.1'] : []));
		const openSession = vi.fn(async () => {
			throw new Error('connection refused');
		});

		const evidence = await probeAuthoritativeDns('example.com', { recursiveQuery, resolveAddresses, openSession }, { activeProbes: false });

		expect(evidence).toEqual({ hostname: 'example.com', checkedAt: expect.any(String), errors: ['raw_dns_probe_no_contact'] });
	});

	it('never opens more than 4 sessions concurrently', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) =>
			name === 'example.com' && type === 'NS' ? ['ns1.example.com', 'ns2.example.com', 'ns3.example.com'] : [],
		);
		const resolveAddresses = vi.fn(async (nameserver: string, type: 'A' | 'AAAA') => {
			const index = Number(nameserver.match(/\d+/)?.[0] ?? '0');
			return type === 'A' ? [`1.1.1.${index}`] : [`2606:4700:4700:0:0:0:0:${1100 + index}`];
		});

		let active = 0;
		let maxActive = 0;
		const openSession = vi.fn(async () => {
			active += 1;
			maxActive = Math.max(maxActive, active);
			return {
				query: vi.fn(async () => {
					await new Promise((resolve) => setTimeout(resolve, 15));
					return response({ aa: true });
				}),
				close: vi.fn(async () => {
					active -= 1;
				}),
			};
		});

		await probeAuthoritativeDns('example.com', { recursiveQuery, resolveAddresses, openSession }, { activeProbes: false });

		expect(openSession).toHaveBeenCalledTimes(6); // 3 nameservers x (1 IPv4 + 1 IPv6)
		expect(maxActive).toBeLessThanOrEqual(4);
		expect(maxActive).toBeGreaterThan(1);
	});

	it('returns partial measured evidence instead of throwing when the budget is exhausted', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) =>
			name === 'example.com' && type === 'NS' ? ['ns1.example.com', 'ns2.example.com', 'ns3.example.com'] : [],
		);
		const resolveAddresses = vi.fn(async (nameserver: string, type: 'A' | 'AAAA') => {
			const index = Number(nameserver.match(/\d+/)?.[0] ?? '0');
			return type === 'A' ? [`1.1.1.${index}`] : [`2606:4700:4700:0:0:0:0:${1100 + index}`];
		});
		const openSession = vi.fn(async () => ({
			query: vi.fn(async () => {
				await new Promise((resolve) => setTimeout(resolve, 40));
				return response({ aa: true });
			}),
			close: vi.fn(async () => undefined),
		}));

		const evidence = await probeAuthoritativeDns(
			'example.com',
			{ recursiveQuery, resolveAddresses, openSession },
			{ activeProbes: false, budgetMs: 5 },
		);

		// The tight budget lets only the first concurrency-capped batch even start; the rest
		// never got a session opened. This must resolve with partial evidence, never throw.
		expect(openSession.mock.calls.length).toBeLessThan(6);
		expect(openSession.mock.calls.length).toBeGreaterThan(0);
		expect(evidence.hostname).toBe('example.com');
	});

	it('resolves nameserver addresses concurrently so slow lookups cannot outlive the lane budget before any session opens', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) =>
			name === 'example.com' && type === 'NS' ? ['ns1.example.com', 'ns2.example.com', 'ns3.example.com'] : [],
		);
		// Counts NAMESERVERS with a lookup in flight (not A/AAAA pairs, which one nameserver
		// already issues together). Serial resolution can never exceed 1 here.
		const inFlight = new Map<string, number>();
		let maxNameserversInFlight = 0;
		const resolveAddresses = vi.fn(async (nameserver: string, type: 'A' | 'AAAA') => {
			inFlight.set(nameserver, (inFlight.get(nameserver) ?? 0) + 1);
			maxNameserversInFlight = Math.max(maxNameserversInFlight, inFlight.size);
			await new Promise((resolve) => setTimeout(resolve, 20));
			const remaining = (inFlight.get(nameserver) ?? 1) - 1;
			if (remaining === 0) inFlight.delete(nameserver);
			else inFlight.set(nameserver, remaining);
			const index = Number(nameserver.match(/\d+/)?.[0] ?? '0');
			return type === 'A' ? [`1.1.1.${index}`] : [];
		});
		const openSession = vi.fn(async () => ({
			query: vi.fn(async () => response({ aa: true })),
			close: vi.fn(async () => undefined),
		}));

		await probeAuthoritativeDns('example.com', { recursiveQuery, resolveAddresses, openSession }, { activeProbes: false });

		expect(maxNameserversInFlight).toBe(3);
		// Order is still nameserver order — buildEvidence relies on it.
		expect(openSession.mock.calls.map((call) => (call as unknown[])[0])).toEqual(['1.1.1.1', '1.1.1.2', '1.1.1.3']);
	});

	it('skips a nameserver that resolves only to private addresses, never connecting to it', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) =>
			name === 'example.com' && type === 'NS' ? ['ns1.example.com', 'ns2.example.com'] : [],
		);
		const resolveAddresses = vi.fn(async (nameserver: string, type: 'A' | 'AAAA') => {
			if (nameserver === 'ns1.example.com') return type === 'A' ? ['10.0.0.5'] : []; // private-only -> skipped
			return type === 'A' ? ['1.1.1.1'] : [];
		});
		const openSession = vi.fn(async () => ({
			query: vi.fn(async () => response({ aa: true })),
			close: vi.fn(async () => undefined),
		}));

		await probeAuthoritativeDns('example.com', { recursiveQuery, resolveAddresses, openSession }, { activeProbes: false });

		expect(openSession).toHaveBeenCalledTimes(1);
		expect(openSession).toHaveBeenCalledWith('1.1.1.1', expect.any(Number));
	});
});
