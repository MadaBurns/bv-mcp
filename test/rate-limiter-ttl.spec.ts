import { describe, it, expect, vi, afterEach } from 'vitest';
import { checkRateLimit, resetAllRateLimits } from '../src/lib/rate-limiter';

afterEach(() => {
	resetAllRateLimits();
	vi.restoreAllMocks();
});

describe('rate-limiter KV TTL precision', () => {
	it('uses remaining-window TTL for minute key written at start of window', async () => {
		// At the start of a minute window, TTL should be ~60s
		const windowStart = 60_000 * 1000; // exact start of window 1000
		vi.spyOn(Date, 'now').mockReturnValue(windowStart);

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		} as unknown as KVNamespace;

		await checkRateLimit('10.0.0.1', kv);

		const minutePutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[0];
		const minuteTtl = minutePutCall[2].expirationTtl;
		// At the start of the window, remaining is ~60s
		expect(minuteTtl).toBe(60);
	});

	it('uses remaining-window TTL for minute key written mid-window', async () => {
		// 30 seconds into the minute window
		const windowStart = 60_000 * 1000;
		const midWindow = windowStart + 30_000;
		vi.spyOn(Date, 'now').mockReturnValue(midWindow);

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		} as unknown as KVNamespace;

		await checkRateLimit('10.0.0.2', kv);

		const minutePutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[0];
		const minuteTtl = minutePutCall[2].expirationTtl;
		// 30s remaining in the window
		expect(minuteTtl).toBe(30);
	});

	it('uses remaining-window TTL for minute key written near end of window', async () => {
		// 59 seconds into the minute window
		const windowStart = 60_000 * 1000;
		const nearEnd = windowStart + 59_000;
		vi.spyOn(Date, 'now').mockReturnValue(nearEnd);

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		} as unknown as KVNamespace;

		await checkRateLimit('10.0.0.3', kv);

		const minutePutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[0];
		const minuteTtl = minutePutCall[2].expirationTtl;
		// 1s remaining, at least 1
		expect(minuteTtl).toBe(1);
	});

	it('uses remaining-window TTL for hour key written mid-window', async () => {
		// 30 minutes into the hour window
		const hourWindowStart = 3_600_000 * 1000;
		const midHour = hourWindowStart + 1_800_000; // 30 min in
		vi.spyOn(Date, 'now').mockReturnValue(midHour);

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		} as unknown as KVNamespace;

		await checkRateLimit('10.0.0.4', kv);

		const hourPutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[1];
		const hourTtl = hourPutCall[2].expirationTtl;
		// 30 minutes remaining = 1800s
		expect(hourTtl).toBe(1800);
	});

	it('hour key at start of window gets full TTL', async () => {
		const hourWindowStart = 3_600_000 * 1000;
		vi.spyOn(Date, 'now').mockReturnValue(hourWindowStart);

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		} as unknown as KVNamespace;

		await checkRateLimit('10.0.0.5', kv);

		const hourPutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[1];
		const hourTtl = hourPutCall[2].expirationTtl;
		expect(hourTtl).toBe(3600);
	});
});
