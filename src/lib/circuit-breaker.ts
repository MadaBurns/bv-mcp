// SPDX-License-Identifier: BUSL-1.1

/**
 * Lightweight per-isolate circuit breaker for external dependencies.
 *
 * States: CLOSED → OPEN (after failureThreshold) → HALF_OPEN (after cooldownMs) → CLOSED/OPEN
 *
 * Workers-compatible: uses only Date.now(), no Node.js APIs.
 */

type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerConfig {
	/** Descriptive name for logging / error messages. */
	name: string;
	/** Number of consecutive failures before opening the circuit. */
	failureThreshold: number;
	/** Milliseconds to wait before transitioning from OPEN to HALF_OPEN. */
	cooldownMs: number;
}

/** Thrown when a call is rejected because the circuit is OPEN. */
export class CircuitBreakerOpen extends Error {
	constructor(name: string) {
		super(`Circuit breaker '${name}' is OPEN — call rejected`);
		this.name = 'CircuitBreakerOpen';
	}
}

export class CircuitBreaker {
	private _state: CircuitState = 'CLOSED';
	private _failureCount = 0;
	private _lastFailureAt = 0;
	private readonly config: CircuitBreakerConfig;

	constructor(config: CircuitBreakerConfig) {
		this.config = config;
	}

	/** Current state (evaluates HALF_OPEN transition lazily). */
	get state(): CircuitState {
		if (this._state === 'OPEN' && Date.now() - this._lastFailureAt >= this.config.cooldownMs) {
			this._state = 'HALF_OPEN';
		}
		return this._state;
	}

	get failureCount(): number {
		return this._failureCount;
	}

	/** Execute a function through the circuit breaker. Throws CircuitBreakerOpen if OPEN. */
	async call<T>(fn: () => Promise<T>): Promise<T> {
		const currentState = this.state;

		if (currentState === 'OPEN') {
			throw new CircuitBreakerOpen(this.config.name);
		}

		try {
			const result = await fn();
			this.onSuccess();
			return result;
		} catch (err) {
			this.onFailure();
			throw err;
		}
	}

	/** Execute with a fallback value returned when the circuit is OPEN. */
	async callWithFallback<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
		try {
			return await this.call(fn);
		} catch (err) {
			if (err instanceof CircuitBreakerOpen) {
				return fallback;
			}
			throw err;
		}
	}

	/** Reset to CLOSED state. */
	reset(): void {
		this._state = 'CLOSED';
		this._failureCount = 0;
		this._lastFailureAt = 0;
	}

	private onSuccess(): void {
		this._failureCount = 0;
		this._state = 'CLOSED';
	}

	private onFailure(): void {
		this._failureCount++;
		this._lastFailureAt = Date.now();
		if (this._failureCount >= this.config.failureThreshold) {
			this._state = 'OPEN';
		}
	}
}
