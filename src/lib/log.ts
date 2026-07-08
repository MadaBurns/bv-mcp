// SPDX-License-Identifier: BUSL-1.1

/**
 * Structured logging utility for Cloudflare Worker (MCP server)
 * Logs JSON objects with request, tool, result, and error metadata
 * Usage: logEvent({ ... })
 */

export type LogEvent = {
	timestamp: string;
	/**
	 * Server-generated per-request correlation id (`crypto.randomUUID()`),
	 * minted once at the Worker entry point and stamped onto EVERY log line on
	 * the request path so multi-line traces (auth, rate-limit, parse-error,
	 * session, dispatch, error) can be stitched together. Distinct from
	 * {@link LogEvent.requestId}, which is the client-chosen JSON-RPC id.
	 */
	correlationId?: string;
	requestId?: string;
	/**
	 * FNV-1a hash of the client IP (`i_` prefix), aligned with the analytics
	 * `ipHash` dimension. Raw IPs must never appear here — top-level fields
	 * are NOT routed through `sanitizeLogValue`, so a raw IP would land in
	 * tail/log storage unredacted. Callers must hash before logging.
	 */
	ipHash?: string;
	/**
	 * Cloudflare edge colo (`request.cf.colo`) the request landed on, aligned with
	 * the analytics `colo` dimension. Stamped at the Worker entry point so log
	 * traces can be correlated per-datacenter alongside the per-colo analytics
	 * queries. Undefined off the request path / in tests.
	 */
	colo?: string;
	tool?: string;
	domain?: string;
	severity?: 'info' | 'warn' | 'error';
	category?: string;
	result?: string;
	details?: unknown;
	error?: string;
	durationMs?: number;
	userAgent?: string;
};

const REDACTED = '[redacted]';
const MAX_LOG_STRING_LENGTH = 256;
const MAX_ERROR_STRING_LENGTH = 1024;
export const SENSITIVE_KEY_PATTERN =
	/(^ip$|cf-connecting-ip|authorization|mcp-session-id|session|token|api[-_]?key|secret|password|cookie|rawbody|^query$|^email$|e[-_]?mail|user[-_]?principal[-_]?name|userPrincipalName|ms[-_]?tenant[-_]?id|tenantId)/i;

export function isSensitiveKey(key: string): boolean {
	return !/^has[A-Z]/.test(key) && SENSITIVE_KEY_PATTERN.test(key);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function sanitizeString(value: string, maxLength = MAX_LOG_STRING_LENGTH): string {
	// Strip control characters (except tab) to prevent log injection via newlines/ANSI sequences
	const stripped = value.replace(/[\x00-\x08\x0a-\x1f\x7f]/g, ' ');
	if (stripped.length <= maxLength) return stripped;
	// Preserve start and end for error context (type + stack tail)
	const half = Math.floor((maxLength - 5) / 2);
	return `${stripped.slice(0, half)} ... ${stripped.slice(-half)}`;
}

export function sanitizeLogValue(value: unknown, key?: string, maxLength?: number): unknown {
	if (key && isSensitiveKey(key)) {
		return REDACTED;
	}

	if (typeof value === 'string') {
		return sanitizeString(value, maxLength);
	}

	if (Array.isArray(value)) {
		return value.map((item) => sanitizeLogValue(item, undefined, maxLength));
	}

	if (isPlainObject(value)) {
		const sanitized: Record<string, unknown> = {};
		for (const [entryKey, entryValue] of Object.entries(value)) {
			sanitized[entryKey] = sanitizeLogValue(entryValue, entryKey, maxLength);
		}
		return sanitized;
	}

	return value;
}

export function sanitizeHeadersForLog(headers: Headers | Record<string, string>): Record<string, string> {
	const sanitized: Record<string, string> = {};
	if (headers instanceof Headers) {
		headers.forEach((value, rawKey) => {
			const key = rawKey.toLowerCase();
			sanitized[key] = isSensitiveKey(key) ? REDACTED : sanitizeString(value);
		});
		return sanitized;
	}

	for (const [rawKey, value] of Object.entries(headers)) {
		const key = rawKey.toLowerCase();
		sanitized[key] = isSensitiveKey(key) ? REDACTED : sanitizeString(value);
	}
	return sanitized;
}

/**
 * Emit a structured log event (console.log as JSON)
 */
export function logEvent(event: LogEvent): void {
	const isError = event.severity === 'error';
	const maxLen = isError ? MAX_ERROR_STRING_LENGTH : MAX_LOG_STRING_LENGTH;
	const log = {
		...event,
		timestamp: event.timestamp || new Date().toISOString(),
		// Top-level fields bypass sanitizeLogValue (they're not nested in
		// `details`); the two that carry attacker-controlled strings get the
		// same control-char strip + truncation so a hostile UA or domain can't
		// inject log lines or bloat tail storage. (JSON.stringify drops the
		// undefined keys this adds for events without them.)
		domain: typeof event.domain === 'string' ? sanitizeString(event.domain, maxLen) : event.domain,
		userAgent: typeof event.userAgent === 'string' ? sanitizeString(event.userAgent, maxLen) : event.userAgent,
		details: sanitizeLogValue(event.details, undefined, maxLen),
		error: typeof event.error === 'string' ? sanitizeString(event.error, maxLen) : event.error,
	};
	console.log(JSON.stringify(log));
}

/**
 * Helper for error logging
 */
export function logError(error: Error | string, context?: Partial<LogEvent>): void {
	logEvent({
		timestamp: new Date().toISOString(),
		severity: 'error',
		error: typeof error === 'string' ? error : error.message,
		...context,
	});
}

export interface StructuredLogger {
	info(message: string, details?: Record<string, unknown>): void;
	warn(message: string, details?: Record<string, unknown>): void;
	error(message: string, details?: Record<string, unknown>): void;
}

export function getLogger(): StructuredLogger {
	return {
		info: (message, details) => logEvent({ timestamp: new Date().toISOString(), severity: 'info', category: 'logger', result: message, details }),
		warn: (message, details) => logEvent({ timestamp: new Date().toISOString(), severity: 'warn', category: 'logger', result: message, details }),
		error: (message, details) => logError(message, { category: 'logger', details }),
	};
}

export function fireAndForget(
	work: Promise<unknown> | (() => Promise<unknown>),
	logger: Pick<StructuredLogger, 'warn'>,
	operation = 'fire_and_forget',
): Promise<void> {
	const promise = typeof work === 'function' ? work() : work;
	return promise
		.then(() => undefined)
		.catch((err: unknown) => {
			logger.warn('Fire-and-forget operation failed', {
				operation,
				error: err instanceof Error ? err.message : String(err),
			});
		});
}
