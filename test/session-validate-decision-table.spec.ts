// SPDX-License-Identifier: BUSL-1.1

/**
 * Decision table for `validateSession` (src/lib/session.ts), the gate that decides whether an
 * `Mcp-Session-Id` is honoured. Every row states input -> boolean verdict + the observable side
 * effects (KV writes/deletes, in-memory eviction/hydration). A session that cannot be proven live
 * is denied (false); a storage fault never turns into an allow.
 *
 *  #  format  tombstone     in-memory         kv state                         -> verdict, effect
 *  1  bad     -             -                 -                                -> false, KV untouched
 *  2  ok      local         active            -                                -> false
 *  3  ok      KV            active            tombstone                        -> false, local copy evicted
 *  4  ok      KV read throws active (fresh)   -                                -> true  (tombstone probe fails open)
 *  5  ok      -             fresh             any                              -> true, no KV write
 *  6  ok      -             stale (>=refresh) kv bound                         -> true, KV record refreshed
 *  7  ok      -             stale             kv put throws                    -> true
 *  8  ok      -             stale             no kv                            -> true, no KV
 *  9  ok      -             expired           no kv                            -> false, evicted
 * 10  ok      -             expired           fresh record                     -> true, re-hydrated
 * 11  ok      -             absent            no kv                            -> false
 * 12  ok      -             absent            no record                        -> false
 * 13  ok      -             absent            malformed record                 -> false
 * 14  ok      -             absent            expired record                   -> false, KV record deleted
 * 15  ok      -             absent            fresh record                     -> true, hydrated, no write
 * 16  ok      -             absent            stale record                     -> true, hydrated, KV refreshed
 * 17  ok      -             absent            stale record, put throws         -> true
 * 18  ok      -             absent            read throws                      -> false
 * 19  ok      -             absent            expired record, delete throws    -> false
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ACTIVE_SESSIONS, resetSessions, SESSION_REFRESH_INTERVAL_MS, SESSION_TTL_MS, validateSession } from '../src/lib/session';
import { deleteSessionInMemory } from '../src/lib/session-memory';

const ID = 'a'.repeat(64);
const NOW = 1_800_000_000_000;

type FakeKv = {
	kv: KVNamespace;
	store: Map<string, string>;
	get: ReturnType<typeof vi.fn>;
	put: ReturnType<typeof vi.fn>;
	del: ReturnType<typeof vi.fn>;
};

function makeKv(opts: { failGet?: boolean; failPut?: boolean; failDelete?: boolean; failTombstoneGet?: boolean } = {}): FakeKv {
	const store = new Map<string, string>();
	const get = vi.fn(async (key: string, type?: string) => {
		if (key.startsWith('session-tombstone:') && opts.failTombstoneGet) throw new Error('tombstone read failed');
		if (key.startsWith('session:') && opts.failGet) throw new Error('read failed');
		const raw = store.get(key);
		if (raw === undefined) return null;
		return type === 'json' ? JSON.parse(raw) : raw;
	});
	const put = vi.fn(async (key: string, value: string) => {
		if (opts.failPut) throw new Error('put failed');
		store.set(key, value);
	});
	const del = vi.fn(async (key: string) => {
		if (opts.failDelete) throw new Error('delete failed');
		store.delete(key);
	});
	return { kv: { get, put, delete: del } as unknown as KVNamespace, store, get, put, del };
}

const sessionRecord = (lastAccessedAt: number, createdAt = NOW - 10_000) => JSON.stringify({ createdAt, lastAccessedAt });

beforeEach(() => {
	resetSessions();
	vi.useFakeTimers();
	vi.setSystemTime(NOW);
});

afterEach(() => {
	vi.useRealTimers();
	resetSessions();
});

describe('validateSession decision table', () => {
	it.each(['', 'short', 'A'.repeat(64), 'g'.repeat(64), 'a'.repeat(63), 'a'.repeat(65)])(
		'1: malformed id %j is denied without touching KV',
		async (bad) => {
			const k = makeKv();
			expect(await validateSession(bad, k.kv)).toBe(false);
			expect(k.get).not.toHaveBeenCalled();
			expect(k.put).not.toHaveBeenCalled();
		},
	);

	it('2: a locally tombstoned session is denied even if an in-memory record reappears', async () => {
		deleteSessionInMemory(ID);
		ACTIVE_SESSIONS.set(ID, { createdAt: NOW, lastAccessedAt: NOW });
		expect(await validateSession(ID)).toBe(false);
	});

	it('3: a KV tombstone denies the session and evicts (and locally tombstones) the in-memory copy', async () => {
		const k = makeKv();
		k.store.set(`session-tombstone:${ID}`, '1');
		ACTIVE_SESSIONS.set(ID, { createdAt: NOW, lastAccessedAt: NOW });
		expect(await validateSession(ID, k.kv)).toBe(false);
		expect(ACTIVE_SESSIONS.has(ID)).toBe(false);
		// The local tombstone now denies even with no KV bound.
		ACTIVE_SESSIONS.set(ID, { createdAt: NOW, lastAccessedAt: NOW });
		expect(await validateSession(ID)).toBe(false);
	});

	it('4: an unreadable KV tombstone probe does not deny a live in-memory session', async () => {
		const k = makeKv({ failTombstoneGet: true });
		ACTIVE_SESSIONS.set(ID, { createdAt: NOW, lastAccessedAt: NOW });
		expect(await validateSession(ID, k.kv)).toBe(true);
	});

	it('5: a fresh in-memory session is allowed with no KV write', async () => {
		const k = makeKv();
		ACTIVE_SESSIONS.set(ID, { createdAt: NOW, lastAccessedAt: NOW - 1000 });
		expect(await validateSession(ID, k.kv)).toBe(true);
		expect(k.put).not.toHaveBeenCalled();
	});

	it('6: a stale in-memory session is allowed and its KV record refreshed with the new timestamp', async () => {
		const k = makeKv();
		const createdAt = NOW - 50_000;
		ACTIVE_SESSIONS.set(ID, { createdAt, lastAccessedAt: NOW - SESSION_REFRESH_INTERVAL_MS });
		expect(await validateSession(ID, k.kv)).toBe(true);
		expect(k.put).toHaveBeenCalledTimes(1);
		const [key, value, options] = k.put.mock.calls[0];
		expect(key).toBe(`session:${ID}`);
		expect(JSON.parse(value as string)).toEqual({ createdAt, lastAccessedAt: NOW });
		expect(options).toEqual({ expirationTtl: Math.ceil(SESSION_TTL_MS / 1000) });
		expect(ACTIVE_SESSIONS.get(ID)?.lastAccessedAt).toBe(NOW);
	});

	it('7: a failing KV refresh write is non-fatal', async () => {
		const k = makeKv({ failPut: true });
		ACTIVE_SESSIONS.set(ID, { createdAt: NOW - 50_000, lastAccessedAt: NOW - SESSION_REFRESH_INTERVAL_MS });
		expect(await validateSession(ID, k.kv)).toBe(true);
		expect(k.put).toHaveBeenCalledTimes(1);
	});

	it('8: a stale in-memory session with no KV is allowed and refreshed in memory only', async () => {
		ACTIVE_SESSIONS.set(ID, { createdAt: NOW - 50_000, lastAccessedAt: NOW - SESSION_REFRESH_INTERVAL_MS });
		expect(await validateSession(ID)).toBe(true);
		expect(ACTIVE_SESSIONS.get(ID)?.lastAccessedAt).toBe(NOW);
	});

	it('9: an expired in-memory session with no KV is denied and evicted', async () => {
		ACTIVE_SESSIONS.set(ID, { createdAt: NOW - SESSION_TTL_MS * 2, lastAccessedAt: NOW - SESSION_TTL_MS - 1 });
		expect(await validateSession(ID)).toBe(false);
		expect(ACTIVE_SESSIONS.has(ID)).toBe(false);
	});

	it('10: an expired in-memory session falls through to a fresher KV record and is re-hydrated', async () => {
		const k = makeKv();
		k.store.set(`session:${ID}`, sessionRecord(NOW - 1000, NOW - 99_000));
		ACTIVE_SESSIONS.set(ID, { createdAt: NOW - SESSION_TTL_MS * 2, lastAccessedAt: NOW - SESSION_TTL_MS - 1 });
		expect(await validateSession(ID, k.kv)).toBe(true);
		expect(ACTIVE_SESSIONS.get(ID)).toEqual({ createdAt: NOW - 99_000, lastAccessedAt: NOW });
	});

	it('11: an unknown session with no KV is denied', async () => {
		expect(await validateSession(ID)).toBe(false);
		expect(ACTIVE_SESSIONS.has(ID)).toBe(false);
	});

	it('12: an unknown session with no KV record is denied', async () => {
		const k = makeKv();
		expect(await validateSession(ID, k.kv)).toBe(false);
		expect(ACTIVE_SESSIONS.has(ID)).toBe(false);
	});

	it('13: a malformed KV record is denied', async () => {
		const k = makeKv();
		k.store.set(`session:${ID}`, JSON.stringify({ createdAt: 'x' }));
		expect(await validateSession(ID, k.kv)).toBe(false);
		expect(ACTIVE_SESSIONS.has(ID)).toBe(false);
	});

	it('14: an expired KV record is denied and deleted', async () => {
		const k = makeKv();
		k.store.set(`session:${ID}`, sessionRecord(NOW - SESSION_TTL_MS - 1));
		expect(await validateSession(ID, k.kv)).toBe(false);
		expect(k.del).toHaveBeenCalledWith(`session:${ID}`);
		expect(k.store.has(`session:${ID}`)).toBe(false);
		expect(ACTIVE_SESSIONS.has(ID)).toBe(false);
	});

	it('14b: a KV record exactly at the TTL boundary is still live', async () => {
		const k = makeKv();
		k.store.set(`session:${ID}`, sessionRecord(NOW - SESSION_TTL_MS));
		expect(await validateSession(ID, k.kv)).toBe(true);
	});

	it('15: a fresh KV record is allowed, hydrated with the original createdAt and a fresh lastAccessedAt, with no write', async () => {
		const k = makeKv();
		k.store.set(`session:${ID}`, sessionRecord(NOW - 1000, NOW - 77_000));
		expect(await validateSession(ID, k.kv)).toBe(true);
		expect(ACTIVE_SESSIONS.get(ID)).toEqual({ createdAt: NOW - 77_000, lastAccessedAt: NOW });
		expect(k.put).not.toHaveBeenCalled();
	});

	it('16: a stale KV record is allowed and rewritten with lastAccessedAt = now', async () => {
		const k = makeKv();
		k.store.set(`session:${ID}`, sessionRecord(NOW - SESSION_REFRESH_INTERVAL_MS, NOW - 77_000));
		expect(await validateSession(ID, k.kv)).toBe(true);
		expect(k.put).toHaveBeenCalledTimes(1);
		expect(JSON.parse(k.put.mock.calls[0][1] as string)).toEqual({ createdAt: NOW - 77_000, lastAccessedAt: NOW });
		expect(ACTIVE_SESSIONS.get(ID)).toEqual({ createdAt: NOW - 77_000, lastAccessedAt: NOW });
	});

	it('17: a failing KV rewrite of a stale record is non-fatal', async () => {
		const k = makeKv({ failPut: true });
		k.store.set(`session:${ID}`, sessionRecord(NOW - SESSION_REFRESH_INTERVAL_MS));
		expect(await validateSession(ID, k.kv)).toBe(true);
		expect(ACTIVE_SESSIONS.has(ID)).toBe(true);
	});

	it('18: a failing KV read denies the session (fail closed)', async () => {
		const k = makeKv({ failGet: true });
		expect(await validateSession(ID, k.kv)).toBe(false);
		expect(ACTIVE_SESSIONS.has(ID)).toBe(false);
	});

	it('19: a failing KV delete of an expired record still denies the session', async () => {
		const k = makeKv({ failDelete: true });
		k.store.set(`session:${ID}`, sessionRecord(NOW - SESSION_TTL_MS - 1));
		expect(await validateSession(ID, k.kv)).toBe(false);
		expect(ACTIVE_SESSIONS.has(ID)).toBe(false);
	});
});
