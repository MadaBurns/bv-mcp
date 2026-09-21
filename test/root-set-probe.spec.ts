// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { probeRootServerSet, type RootSetProbeDependencies } from '../src/lib/authoritative-dns-infra/root-set-probe';
import type { DirectDnsResponse, DnsTcpSession, DnsTcpSessionFactory, DirectQueryOptions } from '../src/lib/authoritative-dns-infra/dns-tcp';
import { ROOT_HINTS, ROOT_SERVER_NAMES } from '../src/lib/authoritative-dns-infra/root-hints';
import { RecordType } from '../src/lib/dns-types';

function response(overrides: Partial<DirectDnsResponse>): DirectDnsResponse {
	return { aa: false, rcode: 0, answers: [], authority: [], additional: [], ...overrides };
}

function healthyNsResponse(): DirectDnsResponse {
	return response({
		aa: true,
		answers: ROOT_HINTS.map((hint) => ({ name: '', type: RecordType.NS, data: hint.name })),
	});
}

function healthySoaResponse(serial: number): DirectDnsResponse {
	return response({ aa: true, answers: [{ name: '', type: RecordType.SOA, data: String(serial) }] });
}

/** Fake DnsTcpSessionFactory that answers deterministically per pinned address. */
function fakeOpenSession(
	handlers: Record<string, (name: string, type: number, options?: DirectQueryOptions) => DirectDnsResponse | undefined>,
	opts?: { onOpen?: (address: string) => void; onClose?: (address: string) => void; concurrencyTracker?: ConcurrencyTracker },
): DnsTcpSessionFactory {
	return async (pinnedAddress: string, _timeoutMs: number): Promise<DnsTcpSession> => {
		opts?.concurrencyTracker?.open();
		opts?.onOpen?.(pinnedAddress);
		const handler = handlers[pinnedAddress];
		const query = vi.fn(async (name: string, type: number, options?: DirectQueryOptions) => {
			if (!handler) throw new Error(`no handler for ${pinnedAddress}`);
			const result = handler(name, type, options);
			if (!result) throw new Error(`handler refused ${pinnedAddress} type ${type}`);
			return result;
		});
		const close = vi.fn(async () => {
			opts?.concurrencyTracker?.close();
			opts?.onClose?.(pinnedAddress);
		});
		return { query, close };
	};
}

class ConcurrencyTracker {
	current = 0;
	max = 0;
	open(): void {
		this.current += 1;
		this.max = Math.max(this.max, this.current);
	}
	close(): void {
		this.current -= 1;
	}
}

/** Builds a full-coverage handler set: every ROOT_HINTS address answers NS/SOA/DNSKEY consistently. */
function healthyHandlers(serial = 2026092200): Record<string, (name: string, type: number) => DirectDnsResponse | undefined> {
	const handlers: Record<string, (name: string, type: number) => DirectDnsResponse | undefined> = {};
	for (const hint of ROOT_HINTS) {
		const handler = (_name: string, type: number): DirectDnsResponse | undefined => {
			if (type === RecordType.NS) return healthyNsResponse();
			if (type === RecordType.SOA) return healthySoaResponse(serial);
			if (type === RecordType.DNSKEY) return response({ aa: true, answers: [{ name: '', type: RecordType.DNSKEY, data: '' }] });
			return undefined;
		};
		handlers[hint.ipv4] = handler;
		handlers[hint.ipv6] = handler;
	}
	return handlers;
}

describe('probeRootServerSet', () => {
	it('samples 3 of 13 roots deterministically for a fixed now, and rotates across hours', async () => {
		const opened: string[][] = [];
		const captureOpened: string[] = [];
		const deps: RootSetProbeDependencies = {
			now: () => new Date('2026-09-22T05:00:00.000Z'),
			openSession: fakeOpenSession(healthyHandlers(), { onOpen: (address) => captureOpened.push(address) }),
		};
		await probeRootServerSet(deps);
		opened.push([...captureOpened]);

		// Same `now` -> identical sample (stable).
		captureOpened.length = 0;
		await probeRootServerSet({ ...deps });
		expect(captureOpened.sort()).toEqual(opened[0].sort());

		// Exactly 3 roots x 2 families = 6 addresses queried.
		expect(opened[0]).toHaveLength(6);

		// A different UTC hour picks a different sample.
		captureOpened.length = 0;
		await probeRootServerSet({
			now: () => new Date('2026-09-22T11:00:00.000Z'),
			openSession: fakeOpenSession(healthyHandlers(), { onOpen: (address) => captureOpened.push(address) }),
		});
		expect(captureOpened.sort()).not.toEqual(opened[0].sort());
	});

	it('covers all 13 roots across a 24-hour rotation', async () => {
		const seenNames = new Set<string>();
		for (let hour = 0; hour < 24; hour += 1) {
			const seenAtHour = new Set<string>();
			await probeRootServerSet({
				now: () => new Date(Date.UTC(2026, 8, 22, hour)),
				openSession: fakeOpenSession(healthyHandlers(), {
					onOpen: (address) => {
						const hint = ROOT_HINTS.find((h) => h.ipv4 === address || h.ipv6 === address);
						if (hint) seenAtHour.add(hint.name);
					},
				}),
			});
			expect(seenAtHour.size).toBe(3);
			for (const name of seenAtHour) seenNames.add(name);
		}
		expect(seenNames.size).toBe(ROOT_HINTS.length);
	});

	it('fills full evidence when every sampled root answers healthily', async () => {
		const evidence = await probeRootServerSet({
			now: () => new Date('2026-09-22T00:00:00.000Z'),
			openSession: fakeOpenSession(healthyHandlers(555)),
		});

		expect(evidence.hostname).toBe('.');
		expect(evidence.rootHints).toEqual([...ROOT_HINTS]);
		expect(evidence.observedRootServers).toEqual([...ROOT_SERVER_NAMES].sort());
		expect(evidence.parentChildDelegationMatches).toBe(true);
		expect(evidence.errors).toBeUndefined();
		expect(evidence.serialsByRoot).toBeDefined();
		expect(Object.values(evidence.serialsByRoot ?? {}).every((serial) => serial === 555)).toBe(true);
	});

	it('surfaces a set mismatch when one root returns 12 names instead of 13', async () => {
		const handlers = healthyHandlers();
		const oddOneOut = ROOT_HINTS[0];
		const shortNames = ROOT_HINTS.slice(1).map((hint) => hint.name); // 12 names, missing the first
		const shortResponse = response({ aa: true, answers: shortNames.map((name) => ({ name: '', type: RecordType.NS, data: name })) });
		handlers[oddOneOut.ipv4] = (_name, type) => (type === RecordType.NS ? shortResponse : handlers[ROOT_HINTS[1].ipv4](_name, type));
		handlers[oddOneOut.ipv6] = handlers[oddOneOut.ipv4];

		const evidence = await probeRootServerSet({
			now: () => new Date('2026-09-22T00:00:00.000Z'), // samples index 0,1,2 -> includes oddOneOut
			openSession: fakeOpenSession(handlers),
		});

		expect(evidence.observedRootServers).toBeDefined();
		expect(evidence.observedRootServers).not.toEqual([...ROOT_SERVER_NAMES].sort());
		expect(evidence.parentChildDelegationMatches).toBe(false);
	});

	it('leaves glueMatchesHints undefined when no glue is returned', async () => {
		const evidence = await probeRootServerSet({
			now: () => new Date('2026-09-22T00:00:00.000Z'),
			openSession: fakeOpenSession(healthyHandlers()),
		});
		expect(evidence.glueMatchesHints).toBeUndefined();
	});

	it('reports glueMatchesHints=false when returned glue does not match ROOT_HINTS', async () => {
		const handlers = healthyHandlers();
		const target = ROOT_HINTS[0];
		const nsWithBadGlue = response({
			aa: true,
			answers: ROOT_HINTS.map((hint) => ({ name: '', type: RecordType.NS, data: hint.name })),
			additional: [{ name: target.name, type: RecordType.A, data: '203.0.113.5' }],
		});
		handlers[target.ipv4] = (_name, type) => (type === RecordType.NS ? nsWithBadGlue : handlers[ROOT_HINTS[1].ipv4](_name, type));

		const evidence = await probeRootServerSet({
			now: () => new Date('2026-09-22T00:00:00.000Z'),
			openSession: fakeOpenSession(handlers),
		});
		expect(evidence.glueMatchesHints).toBe(false);
	});

	it('reports glueMatchesHints=true when returned glue matches ROOT_HINTS (including compressed IPv6)', async () => {
		const handlers = healthyHandlers();
		const target = ROOT_HINTS[0];
		const nsWithGoodGlue = response({
			aa: true,
			answers: ROOT_HINTS.map((hint) => ({ name: '', type: RecordType.NS, data: hint.name })),
			additional: [
				{ name: target.name, type: RecordType.A, data: target.ipv4 },
				// Fully expanded form, as dns-tcp.ts's ipv6Presentation() would emit it.
				{ name: target.name, type: RecordType.AAAA, data: expandIpv6ForTest(target.ipv6) },
			],
		});
		handlers[target.ipv4] = (_name, type) => (type === RecordType.NS ? nsWithGoodGlue : handlers[ROOT_HINTS[1].ipv4](_name, type));

		const evidence = await probeRootServerSet({
			now: () => new Date('2026-09-22T00:00:00.000Z'),
			openSession: fakeOpenSession(handlers),
		});
		expect(evidence.glueMatchesHints).toBe(true);
	});

	it('still measures from the surviving family when one family is entirely dead', async () => {
		const handlers = healthyHandlers();
		const target = ROOT_HINTS[0];
		delete handlers[target.ipv6]; // IPv6 session has no handler -> query() throws every time

		const evidence = await probeRootServerSet({
			now: () => new Date('2026-09-22T00:00:00.000Z'),
			openSession: fakeOpenSession(handlers),
		});

		expect(evidence.errors).toBeUndefined();
		expect(evidence.observedRootServers).toEqual([...ROOT_SERVER_NAMES].sort());
	});

	it('returns the exact no-contact shape when every root is unreachable', async () => {
		const openSession: DnsTcpSessionFactory = async () => {
			throw new Error('connection refused');
		};
		const evidence = await probeRootServerSet({
			now: () => new Date('2026-09-22T00:00:00.000Z'),
			openSession,
		});

		expect(evidence).toEqual({
			hostname: '.',
			checkedAt: '2026-09-22T00:00:00.000Z',
			rootHints: [...ROOT_HINTS],
			errors: ['root_server_set_probe_no_contact'],
		});
	});

	it('never opens more than 4 concurrent sessions', async () => {
		const tracker = new ConcurrencyTracker();
		await probeRootServerSet({
			now: () => new Date('2026-09-22T00:00:00.000Z'),
			openSession: fakeOpenSession(healthyHandlers(), { concurrencyTracker: tracker }),
		});
		expect(tracker.max).toBeLessThanOrEqual(4);
		expect(tracker.current).toBe(0); // all sessions closed
	});

	it('returns the no-authoritative-answer abstention when every session answers but none is AA=1', async () => {
		// A middlebox transparently intercepting TCP/53 also "answers" (a TCP response is
		// parsed), so `answered: true` alone is not contact — only an AA=1 response is
		// trustworthy evidence about the root zone. Comment c_mubkwv04_a0fee8: this exact
		// shape (REFUSED/AA=0/RA=1 from every session) used to fall through with NO evidence
		// AND NO errors, which the analyzer read as a self-consistent hints match and
		// published a fabricated pass.
		const handlers = healthyHandlers();
		for (const hint of ROOT_HINTS) {
			const nonAuthoritative = (_name: string, type: number): DirectDnsResponse | undefined => {
				if (type === RecordType.NS) return response({ aa: false, answers: [{ name: '', type: RecordType.NS, data: 'a.root-servers.net' }] });
				if (type === RecordType.SOA) return response({ aa: false, answers: [{ name: '', type: RecordType.SOA, data: '123' }] });
				return response({ aa: false });
			};
			handlers[hint.ipv4] = nonAuthoritative;
			handlers[hint.ipv6] = nonAuthoritative;
		}

		const evidence = await probeRootServerSet({
			now: () => new Date('2026-09-22T00:00:00.000Z'),
			openSession: fakeOpenSession(handlers),
		});

		// The lane DID get responses (answered=true), so this is not the no-contact shape;
		// but none of those responses were AA=1, so the lane must abstain explicitly rather
		// than silently omit every verdict-shaped field.
		expect(evidence).toEqual({
			hostname: '.',
			checkedAt: '2026-09-22T00:00:00.000Z',
			rootHints: [...ROOT_HINTS],
			errors: ['root_server_set_probe_no_authoritative_answer'],
		});
	});

	it('always includes rootHints and never fills dnskeyDigestsByRoot (W1 decodes DNSKEY as presence-only)', async () => {
		const evidence = await probeRootServerSet({
			now: () => new Date('2026-09-22T00:00:00.000Z'),
			openSession: fakeOpenSession(healthyHandlers()),
		});
		expect(evidence.rootHints).toEqual([...ROOT_HINTS]);
		expect(evidence.dnskeyDigestsByRoot).toBeUndefined();
	});

	it('honors a custom budgetMs by passing a shrinking deadline to openSession', async () => {
		const seenTimeouts: number[] = [];
		const openSession: DnsTcpSessionFactory = async (_address: string, timeoutMs: number) => {
			seenTimeouts.push(timeoutMs);
			const query = vi.fn(async () => healthyNsResponse());
			const close = vi.fn(async () => undefined);
			return { query, close };
		};
		await probeRootServerSet({ now: () => new Date('2026-09-22T00:00:00.000Z'), openSession }, { budgetMs: 1500 });
		expect(seenTimeouts.every((timeout) => timeout <= 1500 && timeout > 0)).toBe(true);
	});
});

function expandIpv6ForTest(address: string): string {
	const lower = address.toLowerCase();
	const halves = lower.split('::');
	const expandSide = (side: string): string[] => (side ? side.split(':') : []);
	if (halves.length === 1) return expandSide(halves[0]).map((group) => group.padStart(4, '0')).join(':');
	const left = expandSide(halves[0]);
	const right = expandSide(halves[1]);
	const missing = Math.max(0, 8 - left.length - right.length);
	return [...left, ...Array(missing).fill('0'), ...right].map((group) => group.padStart(4, '0')).join(':');
}
