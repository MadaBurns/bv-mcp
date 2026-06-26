// src/lib/access-log-event.ts
// SPDX-License-Identifier: BUSL-1.1

import { piiAllows, type AnalyticsPiiLevel } from './analytics-pii';

/**
 * One captured access-log record. Used both as the queue message payload and
 * (after the consumer fills `ptrHostname`) as the D1 insert row. `ip` is the
 * raw address — carried for the consumer's PTR + encryption only; NEVER persisted.
 */
export interface AccessLogEvent {
	ip: string;
	ipHash: string;
	ipMasked: string;
	toolName: string;
	domain: string;
	country: string | null;
	region: string | null;
	city: string | null;
	latitude: string | null;
	longitude: string | null;
	asn: number | null;
	asOrg: string | null;
	ptrHostname: string | null;
	keyHash: string | null;
	clientType: string | null;
	colo: string | null;
	sessionHash: string | null;
	userAgent: string | null;
	method: string | null;
	transport: string | null;
	status: string | null;
	responseMs: number;
	rateLimited: boolean;
	piiLevel: AnalyticsPiiLevel;
}

/** Raw enrichment inputs before PII gating; `ptrHostname`/`piiLevel` are added by the builder. */
export type AccessLogEventInput = Omit<AccessLogEvent, 'piiLevel' | 'ptrHostname'>;

/** Apply PII gating: null out city + precise geo when the level forbids them. */
export function buildAccessLogEvent(raw: AccessLogEventInput, level: AnalyticsPiiLevel): AccessLogEvent {
	return {
		...raw,
		city: piiAllows(level, 'city') ? raw.city : null,
		latitude: piiAllows(level, 'precise_geo') ? raw.latitude : null,
		longitude: piiAllows(level, 'precise_geo') ? raw.longitude : null,
		ptrHostname: null,
		piiLevel: level,
	};
}
