// SPDX-License-Identifier: BUSL-1.1

/**
 * createNotificationStream keeps the GET /mcp SSE channel open with heartbeats and closes it
 * after NOTIFICATION_STREAM_TTL_MS. The timers are captured (not awaited) so each callback
 * can be fired deterministically and the stream observed from the reader side.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

type TimerCallback = () => void;

function captureTimers() {
	const timeouts: Array<{ fn: TimerCallback; delay: number | undefined }> = [];
	const intervals: Array<{ fn: TimerCallback; delay: number | undefined }> = [];
	const cleared: unknown[] = [];
	vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: TimerCallback, delay?: number) => {
		timeouts.push({ fn, delay });
		return timeouts.length as unknown as ReturnType<typeof setTimeout>;
	}) as unknown as typeof setTimeout);
	vi.spyOn(globalThis, 'setInterval').mockImplementation(((fn: TimerCallback, delay?: number) => {
		intervals.push({ fn, delay });
		return (100 + intervals.length) as unknown as ReturnType<typeof setInterval>;
	}) as unknown as typeof setInterval);
	vi.spyOn(globalThis, 'clearInterval').mockImplementation(((handle: unknown) => {
		cleared.push(handle);
	}) as unknown as typeof clearInterval);
	return { timeouts, intervals, cleared };
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe('createNotificationStream', () => {
	it('opens with a comment, emits heartbeats, then closes and stops the heartbeat when the TTL fires', async () => {
		const timers = captureTimers();
		const { createNotificationStream } = await import('../src/lib/sse');
		const reader = createNotificationStream().getReader();
		const decoder = new TextDecoder();

		expect(decoder.decode((await reader.read()).value)).toBe(': stream opened\n\n');
		expect(timers.intervals).toHaveLength(1);
		expect(timers.timeouts).toHaveLength(1);
		expect(timers.timeouts[0]!.delay).toBe(300_000);

		timers.intervals[0]!.fn();
		expect(decoder.decode((await reader.read()).value)).toBe(': heartbeat\n\n');

		// TTL expiry: the stream ends cleanly and the heartbeat interval is cleared.
		timers.timeouts[0]!.fn();
		expect((await reader.read()).done).toBe(true);
		expect(timers.cleared).toEqual([101]);
	});

	it('ignores a second TTL expiry instead of closing the controller twice', async () => {
		const timers = captureTimers();
		const { createNotificationStream } = await import('../src/lib/sse');
		const reader = createNotificationStream().getReader();
		await reader.read();

		timers.timeouts[0]!.fn();
		expect(() => timers.timeouts[0]!.fn()).not.toThrow();
		expect((await reader.read()).done).toBe(true);
		// Only the first expiry clears the heartbeat.
		expect(timers.cleared).toHaveLength(1);
	});

	it('marks the stream closed when a heartbeat cannot be enqueued, so the TTL timer becomes a no-op', async () => {
		const timers = captureTimers();
		const { createNotificationStream } = await import('../src/lib/sse');
		const reader = createNotificationStream().getReader();
		await reader.read();

		// Client disconnect: enqueue on a cancelled stream throws inside the heartbeat.
		await reader.cancel();
		expect(() => timers.intervals[0]!.fn()).not.toThrow();
		expect(timers.cleared).toEqual([101]);

		// closed is now true: the pending TTL callback returns before touching the controller,
		// and a later heartbeat tick is skipped.
		expect(() => timers.timeouts[0]!.fn()).not.toThrow();
		expect(() => timers.intervals[0]!.fn()).not.toThrow();
		expect(timers.cleared).toEqual([101]);
	});
});
