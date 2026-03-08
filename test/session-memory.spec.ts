import { afterEach, describe, expect, it, vi } from 'vitest';

import {
	activeSessions,
	checkSessionCreateRateLimitInMemory,
	createSessionInMemory,
	deleteSessionInMemory,
	resetSessions,
	SESSION_REFRESH_INTERVAL_MS,
	SESSION_TTL_MS,
	validateSessionInMemory,
} from '../src/lib/session-memory';

afterEach(() => {
	resetSessions();
	vi.restoreAllMocks();
});

describe('session-memory', () => {
	it('creates and validates in-memory sessions', () => {
		createSessionInMemory('session-1');
		expect(activeSessions.has('session-1')).toBe(true);
		expect(validateSessionInMemory('session-1')).toBe(true);
	});

	it('expires old in-memory sessions', () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);
		createSessionInMemory('session-1');

		nowSpy.mockReturnValue(base + SESSION_TTL_MS + 1);
		expect(validateSessionInMemory('session-1')).toBe(false);
	});

	it('refreshes in-memory sessions after the refresh interval', () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);
		createSessionInMemory('session-1');

		nowSpy.mockReturnValue(base + SESSION_REFRESH_INTERVAL_MS + 1_000);
		expect(validateSessionInMemory('session-1')).toBe(true);
		expect(activeSessions.get('session-1')?.lastAccessedAt).toBe(base + SESSION_REFRESH_INTERVAL_MS + 1_000);
	});

	it('deletes in-memory sessions explicitly', () => {
		createSessionInMemory('session-1');
		expect(deleteSessionInMemory('session-1')).toBe(true);
		expect(activeSessions.has('session-1')).toBe(false);
	});

	it('limits repeated in-memory session creation attempts per IP window', () => {
		for (let i = 0; i < 30; i++) {
			expect(checkSessionCreateRateLimitInMemory('198.51.100.25').allowed).toBe(true);
		}

		expect(checkSessionCreateRateLimitInMemory('198.51.100.25').allowed).toBe(false);
	});
});