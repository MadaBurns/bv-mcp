/**
 * Audit logging for security-related events.
 * Tracks authentication, rate limiting, and suspicious patterns.
 */

import { logEvent } from './log';

export type AuditEventType = 
	| 'auth-success'
	| 'auth-invalid-token'
	| 'rate-limit-exceeded'
	| 'rate-limit-warning'
	| 'session-created'
	| 'session-invalidated'
	| 'invalid-request'
	| 'scan-initiated'
	| 'scan-completed'
	| 'scan-error';

export interface AuditLogEvent {
	eventType: AuditEventType;
	ip: string;
	timestamp: string;
	sessionId?: string;
	tool?: string;
	domain?: string;
	severity: 'info' | 'warn' | 'error';
	message: string;
	details?: Record<string, unknown>;
}

/**
 * Log a security-relevant audit event
 */
export function auditLog(event: AuditLogEvent): void {
	logEvent({
		timestamp: event.timestamp || new Date().toISOString(),
		severity: event.severity,
		category: 'audit',
		details: {
			eventType: event.eventType,
			ip: event.ip,
			sessionId: event.sessionId,
			tool: event.tool,
			domain: event.domain,
			message: event.message,
			...event.details,
		},
	});
}

/**
 * Log successful authentication
 */
export function auditAuthSuccess(ip: string, sessionId: string): void {
	auditLog({
		eventType: 'auth-success',
		ip,
		sessionId,
		timestamp: new Date().toISOString(),
		severity: 'info',
		message: 'Bearer token authentication succeeded',
	});
}

/**
 * Log failed authentication attempt
 */
export function auditAuthFailure(ip: string, reason: string): void {
	auditLog({
		eventType: 'auth-invalid-token',
		ip,
		timestamp: new Date().toISOString(),
		severity: 'warn',
		message: `Authentication failure: ${reason}`,
	});
}

/**
 * Log rate limit exceeded
 */
export function auditRateLimitExceeded(ip: string, tool: string, remainingMs: number): void {
	auditLog({
		eventType: 'rate-limit-exceeded',
		ip,
		tool,
		timestamp: new Date().toISOString(),
		severity: 'warn',
		message: `Rate limit exceeded for tool: ${tool}`,
		details: {
			retryAfterMs: remainingMs,
		},
	});
}

/**
 * Log rate limit warning (approaching threshold)
 */
export function auditRateLimitWarning(ip: string, minuteRemaining: number): void {
	auditLog({
		eventType: 'rate-limit-warning',
		ip,
		timestamp: new Date().toISOString(),
		severity: 'warn',
		message: `Rate limit approaching: ${minuteRemaining} requests remaining in current minute`,
		details: {
			remainingRequests: minuteRemaining,
		},
	});
}

/**
 * Log session creation
 */
export function auditSessionCreated(ip: string, sessionId: string): void {
	auditLog({
		eventType: 'session-created',
		ip,
		sessionId,
		timestamp: new Date().toISOString(),
		severity: 'info',
		message: 'New session created',
	});
}

/**
 * Log invalid session or session invalidation
 */
export function auditSessionInvalidated(ip: string, sessionId: string, reason: string): void {
	auditLog({
		eventType: 'session-invalidated',
		ip,
		sessionId,
		timestamp: new Date().toISOString(),
		severity: 'warn',
		message: `Session invalidated: ${reason}`,
	});
}

/**
 * Log invalid request
 */
export function auditInvalidRequest(ip: string, reason: string, details?: Record<string, unknown>): void {
	auditLog({
		eventType: 'invalid-request',
		ip,
		timestamp: new Date().toISOString(),
		severity: 'warn',
		message: `Invalid request: ${reason}`,
		details,
	});
}

/**
 * Log scan initiation
 */
export function auditScanInitiated(ip: string, domain: string, sessionId?: string): void {
	auditLog({
		eventType: 'scan-initiated',
		ip,
		domain,
		sessionId,
		timestamp: new Date().toISOString(),
		severity: 'info',
		message: `DNS security scan initiated for domain: ${domain}`,
	});
}

/**
 * Log scan completion
 */
export function auditScanCompleted(ip: string, domain: string, score: number, durationMs: number, sessionId?: string): void {
	auditLog({
		eventType: 'scan-completed',
		ip,
		domain,
		sessionId,
		timestamp: new Date().toISOString(),
		severity: 'info',
		message: `DNS security scan completed for domain: ${domain}`,
		details: {
			score,
			durationMs,
		},
	});
}

/**
 * Log scan error
 */
export function auditScanError(ip: string, domain: string, error: string, sessionId?: string): void {
	auditLog({
		eventType: 'scan-error',
		ip,
		domain,
		sessionId,
		timestamp: new Date().toISOString(),
		severity: 'error',
		message: `DNS security scan failed for domain: ${domain}`,
		details: {
			error,
		},
	});
}
