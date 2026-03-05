/**
 * Audit logging for security-related events.
 * Tracks authentication, rate limiting, and suspicious patterns.
 */

import { logEvent } from './log';

export type AuditEventType = 'session-created';

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
