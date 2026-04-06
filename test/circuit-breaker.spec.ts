// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CircuitBreaker, CircuitBreakerOpen } from '../src/lib/circuit-breaker';

describe('CircuitBreaker', () => {
	let cb: CircuitBreaker;

	beforeEach(() => {
		vi.restoreAllMocks();
		cb = new CircuitBreaker({ name: 'test', failureThreshold: 3, cooldownMs: 1000 });
	});

	it('starts in CLOSED state', () => {
		expect(cb.state).toBe('CLOSED');
	});

	it('passes through calls when CLOSED', async () => {
		const result = await cb.call(() => Promise.resolve('ok'));
		expect(result).toBe('ok');
		expect(cb.state).toBe('CLOSED');
	});

	it('counts failures but stays CLOSED below threshold', async () => {
		const failing = () => Promise.reject(new Error('fail'));
		await expect(cb.call(failing)).rejects.toThrow('fail');
		expect(cb.state).toBe('CLOSED');
		await expect(cb.call(failing)).rejects.toThrow('fail');
		expect(cb.state).toBe('CLOSED');
	});

	it('transitions to OPEN after failureThreshold consecutive failures', async () => {
		const failing = () => Promise.reject(new Error('fail'));
		for (let i = 0; i < 3; i++) {
			await expect(cb.call(failing)).rejects.toThrow('fail');
		}
		expect(cb.state).toBe('OPEN');
	});

	it('rejects immediately with CircuitBreakerOpen when OPEN', async () => {
		const failing = () => Promise.reject(new Error('fail'));
		for (let i = 0; i < 3; i++) {
			await expect(cb.call(failing)).rejects.toThrow('fail');
		}
		const fn = vi.fn().mockResolvedValue('should not run');
		await expect(cb.call(fn)).rejects.toThrow(CircuitBreakerOpen);
		expect(fn).not.toHaveBeenCalled();
	});

	it('transitions to HALF_OPEN after cooldown period', async () => {
		const now = Date.now();
		vi.spyOn(Date, 'now').mockReturnValue(now);

		const failing = () => Promise.reject(new Error('fail'));
		for (let i = 0; i < 3; i++) {
			await expect(cb.call(failing)).rejects.toThrow('fail');
		}
		expect(cb.state).toBe('OPEN');

		// Advance past cooldown
		vi.spyOn(Date, 'now').mockReturnValue(now + 1001);
		expect(cb.state).toBe('HALF_OPEN');
	});

	it('HALF_OPEN: success transitions back to CLOSED', async () => {
		const now = Date.now();
		vi.spyOn(Date, 'now').mockReturnValue(now);

		const failing = () => Promise.reject(new Error('fail'));
		for (let i = 0; i < 3; i++) {
			await expect(cb.call(failing)).rejects.toThrow('fail');
		}

		// Advance past cooldown
		vi.spyOn(Date, 'now').mockReturnValue(now + 1001);

		const result = await cb.call(() => Promise.resolve('recovered'));
		expect(result).toBe('recovered');
		expect(cb.state).toBe('CLOSED');
	});

	it('HALF_OPEN: failure transitions back to OPEN', async () => {
		const now = Date.now();
		vi.spyOn(Date, 'now').mockReturnValue(now);

		const failing = () => Promise.reject(new Error('fail'));
		for (let i = 0; i < 3; i++) {
			await expect(cb.call(failing)).rejects.toThrow('fail');
		}

		// Advance past cooldown
		vi.spyOn(Date, 'now').mockReturnValue(now + 1001);

		await expect(cb.call(failing)).rejects.toThrow('fail');
		expect(cb.state).toBe('OPEN');
	});

	it('a single success resets the failure counter', async () => {
		const failing = () => Promise.reject(new Error('fail'));
		// Two failures
		await expect(cb.call(failing)).rejects.toThrow('fail');
		await expect(cb.call(failing)).rejects.toThrow('fail');
		// One success resets counter
		await cb.call(() => Promise.resolve('ok'));
		// Two more failures — still under threshold
		await expect(cb.call(failing)).rejects.toThrow('fail');
		await expect(cb.call(failing)).rejects.toThrow('fail');
		expect(cb.state).toBe('CLOSED');
	});

	it('reset() clears state to CLOSED', async () => {
		const failing = () => Promise.reject(new Error('fail'));
		for (let i = 0; i < 3; i++) {
			await expect(cb.call(failing)).rejects.toThrow('fail');
		}
		expect(cb.state).toBe('OPEN');
		cb.reset();
		expect(cb.state).toBe('CLOSED');
		// Should work normally after reset
		const result = await cb.call(() => Promise.resolve('ok'));
		expect(result).toBe('ok');
	});

	it('uses custom failure threshold', async () => {
		const cb5 = new CircuitBreaker({ name: 'cb5', failureThreshold: 5, cooldownMs: 1000 });
		const failing = () => Promise.reject(new Error('fail'));
		for (let i = 0; i < 4; i++) {
			await expect(cb5.call(failing)).rejects.toThrow('fail');
		}
		expect(cb5.state).toBe('CLOSED');
		await expect(cb5.call(failing)).rejects.toThrow('fail');
		expect(cb5.state).toBe('OPEN');
	});

	it('tracks failure count via failureCount getter', async () => {
		expect(cb.failureCount).toBe(0);
		const failing = () => Promise.reject(new Error('fail'));
		await expect(cb.call(failing)).rejects.toThrow('fail');
		expect(cb.failureCount).toBe(1);
		await cb.call(() => Promise.resolve('ok'));
		expect(cb.failureCount).toBe(0);
	});

	it('CircuitBreakerOpen error includes breaker name', async () => {
		const failing = () => Promise.reject(new Error('fail'));
		for (let i = 0; i < 3; i++) {
			await expect(cb.call(failing)).rejects.toThrow('fail');
		}
		try {
			await cb.call(() => Promise.resolve('x'));
			expect.unreachable('should have thrown');
		} catch (e) {
			expect(e).toBeInstanceOf(CircuitBreakerOpen);
			expect((e as CircuitBreakerOpen).message).toContain('test');
		}
	});

	it('callWithFallback returns fallback when OPEN', async () => {
		const failing = () => Promise.reject(new Error('fail'));
		for (let i = 0; i < 3; i++) {
			await expect(cb.call(failing)).rejects.toThrow('fail');
		}
		const result = await cb.callWithFallback(() => Promise.resolve('primary'), 'fallback-val');
		expect(result).toBe('fallback-val');
	});

	it('callWithFallback returns primary result when CLOSED', async () => {
		const result = await cb.callWithFallback(() => Promise.resolve('primary'), 'fallback-val');
		expect(result).toBe('primary');
	});
});
