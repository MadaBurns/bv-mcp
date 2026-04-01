import { afterEach, describe, expect, it, vi } from 'vitest';
import {
	createSession,
	validateSession,
	deleteSession,
	resetSessions,
	SESSION_REFRESH_INTERVAL_MS,
	SESSION_TTL_MS,
	checkSessionCreateRateLimit,
	isValidSessionIdFormat,
} from '../src/lib/session';

afterEach(() => {
	resetSessions();
	vi.restoreAllMocks();
});

describe('session', () => {
	it('uses KV-backed session lifecycle when SESSION_STORE is provided', async () => {
		const kvStore = new Map<string, string>();
		const kv = {
			get: vi.fn(async (key: string) => {
				const raw = kvStore.get(key);
				return raw ? JSON.parse(raw) : null;
			}),
			put: vi.fn(async (key: string, value: string) => {
				kvStore.set(key, value);
			}),
			delete: vi.fn(async (key: string) => {
				kvStore.delete(key);
			}),
		} as unknown as KVNamespace;

		const id = await createSession(kv);
		expect(kv.put).toHaveBeenCalledOnce();
		expect(kvStore.size).toBe(1);

		// Validation uses in-memory fast path (dual-write on create), no KV read needed
		expect(await validateSession(id, kv)).toBe(true);
		expect(kv.put).toHaveBeenCalledTimes(1);

		expect(await deleteSession(id, kv)).toBe(true);
		expect(kv.delete).toHaveBeenCalledOnce();
		expect(await validateSession(id, kv)).toBe(false);
	});

	it('refreshes KV-backed sessions only after the refresh interval elapses', async () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);
		const kvStore = new Map<string, string>();
		const kv = {
			get: vi.fn(async (key: string) => {
				const raw = kvStore.get(key);
				return raw ? JSON.parse(raw) : null;
			}),
			put: vi.fn(async (key: string, value: string) => {
				kvStore.set(key, value);
			}),
			delete: vi.fn(async (key: string) => {
				kvStore.delete(key);
			}),
		} as unknown as KVNamespace;

		const id = await createSession(kv);
		expect(kv.put).toHaveBeenCalledTimes(1); // KV create

		// Not yet stale — no KV refresh
		nowSpy.mockReturnValue(base + SESSION_REFRESH_INTERVAL_MS - 1_000);
		expect(await validateSession(id, kv)).toBe(true);
		expect(kv.put).toHaveBeenCalledTimes(1);

		// Now stale — in-memory fast path triggers KV refresh
		nowSpy.mockReturnValue(base + SESSION_REFRESH_INTERVAL_MS + 1_000);
		expect(await validateSession(id, kv)).toBe(true);
		expect(kv.put).toHaveBeenCalledTimes(2); // 1 create + 1 refresh
	});

	it('validates a newly created session', async () => {
		const id = await createSession();
		expect(await validateSession(id)).toBe(true);
	});

	it('invalidates expired sessions', async () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);
		const id = await createSession();

		nowSpy.mockReturnValue(base + SESSION_TTL_MS + 1);
		expect(await validateSession(id)).toBe(false);
	});

	it('extends session lifetime on successful validation', async () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);
		const id = await createSession();

		nowSpy.mockReturnValue(base + SESSION_TTL_MS - 1_000);
		expect(await validateSession(id)).toBe(true);

		nowSpy.mockReturnValue(base + SESSION_TTL_MS + 10_000);
		expect(await validateSession(id)).toBe(true);
	});

	it('deletes sessions explicitly', async () => {
		const id = await createSession();
		expect(await deleteSession(id)).toBe(true);
		expect(await validateSession(id)).toBe(false);
	});

	it('limits repeated session creation attempts per IP window', async () => {
		for (let i = 0; i < 30; i++) {
			const allowed = await checkSessionCreateRateLimit('198.51.100.25');
			expect(allowed.allowed).toBe(true);
		}

		const blocked = await checkSessionCreateRateLimit('198.51.100.25');
		expect(blocked.allowed).toBe(false);
		expect(blocked.retryAfterMs).toBeGreaterThan(0);
	});

	it('resetSessions clears session creation limiter state', async () => {
		for (let i = 0; i < 30; i++) {
			await checkSessionCreateRateLimit('203.0.113.7');
		}
		expect((await checkSessionCreateRateLimit('203.0.113.7')).allowed).toBe(false);

		resetSessions();

		expect((await checkSessionCreateRateLimit('203.0.113.7')).allowed).toBe(true);
	});

	it('uses KV-backed limiter when provided', async () => {
		const kv = {
			get: vi.fn().mockResolvedValue('29'),
			put: vi.fn().mockResolvedValue(undefined),
		} as unknown as KVNamespace;

		const allowed = await checkSessionCreateRateLimit('198.51.100.88', kv);
		expect(allowed.allowed).toBe(true);
		expect(kv.put).toHaveBeenCalledTimes(1);

		(kv.get as ReturnType<typeof vi.fn>).mockResolvedValue('30');
		const blocked = await checkSessionCreateRateLimit('198.51.100.88', kv);
		expect(blocked.allowed).toBe(false);
	});

	it('isValidSessionIdFormat accepts valid 64-char hex IDs', () => {
		// Valid: 64 lowercase hex chars (32 bytes)
		const validId = 'a'.repeat(64);
		expect(isValidSessionIdFormat(validId)).toBe(true);
		expect(isValidSessionIdFormat('0123456789abcdef'.repeat(4))).toBe(true);
	});

	it('isValidSessionIdFormat rejects malformed IDs', () => {
		// Too short
		expect(isValidSessionIdFormat('abc123')).toBe(false);
		// Too long
		expect(isValidSessionIdFormat('a'.repeat(65))).toBe(false);
		// Uppercase hex
		expect(isValidSessionIdFormat('A'.repeat(64))).toBe(false);
		// Non-hex characters
		expect(isValidSessionIdFormat('g'.repeat(64))).toBe(false);
		// Empty string
		expect(isValidSessionIdFormat('')).toBe(false);
		// Correct length but with spaces
		expect(isValidSessionIdFormat(' '.repeat(64))).toBe(false);
	});

	it('validateSession returns false immediately for malformed IDs without hitting KV', async () => {
		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		} as unknown as KVNamespace;

		// Malformed session ID — should return false without any KV calls
		expect(await validateSession('not-a-valid-session-id', kv)).toBe(false);
		expect(kv.get).not.toHaveBeenCalled();

		// Too long ID — should return false without any KV calls
		expect(await validateSession('a'.repeat(200), kv)).toBe(false);
		expect(kv.get).not.toHaveBeenCalled();
	});

	it('deleteSession returns false immediately for malformed IDs without hitting KV', async () => {
		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		} as unknown as KVNamespace;

		expect(await deleteSession('not-valid', kv)).toBe(false);
		expect(kv.delete).not.toHaveBeenCalled();
	});

	it('cross-isolate KV hydration uses fresh lastAccessedAt, not stale KV value', async () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);

		const kvStore = new Map<string, string>();
		const kv = {
			get: vi.fn(async (key: string) => {
				const raw = kvStore.get(key);
				return raw ? JSON.parse(raw) : null;
			}),
			put: vi.fn(async (key: string, value: string) => {
				kvStore.set(key, value);
			}),
			delete: vi.fn(async (key: string) => {
				kvStore.delete(key);
			}),
		} as unknown as KVNamespace;

		// Create session in KV at base time
		const id = await createSession(kv);

		// Simulate cross-isolate: remove from in-memory but keep in KV
		const { ACTIVE_SESSIONS } = await import('../src/lib/session-memory');
		ACTIVE_SESSIONS.delete(id);

		// Advance time significantly (but within TTL)
		const hydrateTime = base + 30 * 60 * 1000; // 30 min later
		nowSpy.mockReturnValue(hydrateTime);

		// Validate — should hydrate from KV
		expect(await validateSession(id, kv)).toBe(true);

		// The in-memory record's lastAccessedAt should be fresh (hydrateTime),
		// not the stale KV value (base)
		const hydrated = ACTIVE_SESSIONS.get(id);
		expect(hydrated).toBeDefined();
		expect(hydrated!.lastAccessedAt).toBe(hydrateTime);
		// createdAt should be preserved from KV
		expect(hydrated!.createdAt).toBe(base);
	});

	it('deleteSession with KV calls only kv.delete, not kv.get', async () => {
		const kvStore = new Map<string, string>();
		const kv = {
			get: vi.fn(async (key: string) => {
				const raw = kvStore.get(key);
				return raw ? JSON.parse(raw) : null;
			}),
			put: vi.fn(async (key: string, value: string) => {
				kvStore.set(key, value);
			}),
			delete: vi.fn(async (key: string) => {
				kvStore.delete(key);
			}),
		} as unknown as KVNamespace;

		const id = await createSession(kv);
		// Reset call counts after session creation
		(kv.get as ReturnType<typeof vi.fn>).mockClear();
		(kv.put as ReturnType<typeof vi.fn>).mockClear();
		(kv.delete as ReturnType<typeof vi.fn>).mockClear();

		const result = await deleteSession(id, kv);
		expect(result).toBe(true);

		// deleteSession should NOT call kv.get (no unnecessary read before delete)
		expect(kv.get).not.toHaveBeenCalled();
		// deleteSession SHOULD call kv.delete
		expect(kv.delete).toHaveBeenCalledOnce();
	});
});
