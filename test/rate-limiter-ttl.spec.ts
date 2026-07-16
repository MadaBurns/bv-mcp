import { describe, it, expect, vi, afterEach } from 'vitest';
import { checkRateLimit, resetAllRateLimits } from '../src/lib/rate-limiter';

afterEach(() => {
	resetAllRateLimits();
	vi.restoreAllMocks();
});

// Cloudflare KV rejects expirationTtl values below 60 seconds, so every put
// must clamp to at least 60 — otherwise the write throws and the counter is
// silently lost (the KV path fails open). Window keys are window-numbered, so
// a key lingering up to 59s past its window end can never leak counts forward.
describe('rate-limiter KV TTL precision', () => {
	it('minute key written at start of window gets the full 60s TTL', async () => {
		const windowStart = 60_000 * 1000; // exact start of window 1000
		vi.spyOn(Date, 'now').mockReturnValue(windowStart);

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		} as unknown as KVNamespace;

		await checkRateLimit('10.0.0.1', kv);

		const minutePutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[0];
		const minuteTtl = minutePutCall[2].expirationTtl;
		expect(minuteTtl).toBe(60);
	});

	it('minute key written mid-window clamps to the KV 60s minimum', async () => {
		// 30 seconds into the minute window — remaining window is 30s, below
		// KV's minimum, so the TTL must clamp up to 60.
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
		expect(minuteTtl).toBe(60);
	});

	it('minute key written near end of window clamps to the KV 60s minimum', async () => {
		// 59 seconds into the minute window — 1s remaining, clamps to 60.
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
		expect(minuteTtl).toBe(60);
	});

	it('never emits an expirationTtl below the KV 60s minimum', async () => {
		// Arbitrary awkward offset within both windows.
		vi.spyOn(Date, 'now').mockReturnValue(60_000 * 1000 + 59_999);

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		} as unknown as KVNamespace;

		await checkRateLimit('10.0.0.6', kv);

		for (const call of (kv.put as ReturnType<typeof vi.fn>).mock.calls) {
			expect(call[2].expirationTtl).toBeGreaterThanOrEqual(60);
		}
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
