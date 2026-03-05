import { afterEach, describe, expect, it, vi } from 'vitest';
import {
	createSession,
	validateSession,
	deleteSession,
	resetSessions,
	SESSION_TTL_MS,
	checkSessionCreateRateLimit,
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

		expect(await validateSession(id, kv)).toBe(true);
		expect(kv.get).toHaveBeenCalled();
		expect(kv.put).toHaveBeenCalledTimes(2);

		expect(await deleteSession(id, kv)).toBe(true);
		expect(kv.delete).toHaveBeenCalledOnce();
		expect(await validateSession(id, kv)).toBe(false);
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

	it('limits repeated session creation attempts per IP window', () => {
		for (let i = 0; i < 30; i++) {
			const allowed = checkSessionCreateRateLimit('198.51.100.25');
			expect(allowed.allowed).toBe(true);
		}

		const blocked = checkSessionCreateRateLimit('198.51.100.25');
		expect(blocked.allowed).toBe(false);
		expect(blocked.retryAfterMs).toBeGreaterThan(0);
	});

	it('resetSessions clears session creation limiter state', () => {
		for (let i = 0; i < 30; i++) {
			checkSessionCreateRateLimit('203.0.113.7');
		}
		expect(checkSessionCreateRateLimit('203.0.113.7').allowed).toBe(false);

		resetSessions();

		expect(checkSessionCreateRateLimit('203.0.113.7').allowed).toBe(true);
	});
});
