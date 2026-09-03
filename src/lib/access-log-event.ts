// src/lib/access-log-event.ts
// SPDX-License-Identifier: BUSL-1.1

import { piiAllows, type AnalyticsPiiLevel } from './analytics-pii';
import { hashNetworkLocalityForAnalytics, type NetworkLocalityInput } from './analytics';

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
	/**
	 * Request-path origin: `'public'` (public /mcp path) | `'internal'`
	 * (service-binding /internal/tools/*). NULL on pre-0003 rows → treated as
	 * `'public'` via COALESCE in queries.
	 */
	source: string | null;
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

/** Apply PII gating: null out city, precise geo, and user_agent when the level forbids them. */
export function buildAccessLogEvent(raw: AccessLogEventInput, level: AnalyticsPiiLevel): AccessLogEvent {
	return {
		...raw,
		city: piiAllows(level, 'city') ? raw.city : null,
		latitude: piiAllows(level, 'precise_geo') ? raw.latitude : null,
		longitude: piiAllows(level, 'precise_geo') ? raw.longitude : null,
		userAgent: piiAllows(level, 'user_agent') ? raw.userAgent : null,
		ptrHostname: null,
		piiLevel: level,
	};
}

/**
 * `ip_masked` marker for a public-path row whose request carried no
 * `cf-connecting-ip` but did carry `request.cf` (#876). Distinguishes "the edge
 * never gave us a client IP" from a hashing failure or the internal door's
 * deliberate `'unknown'` sentinel.
 */
export const NO_CF_HEADER_MARKER = 'no-cf-header';

/** Inputs for {@link resolveAccessLogAttribution}. */
export interface AccessLogAttributionInput extends NetworkLocalityInput {
	/** Already-computed `i_` hash of cf-connecting-ip, or the internal door's explicit `'unknown'`; undefined = header absent. */
	ipHash?: string;
	/** `maskIp(ip)` output — passed through unchanged when the header was present. */
	ipMasked: string;
}

/**
 * Attribution for one access-log row (#876). Precedence:
 *   1. an explicit `ipHash` (real `i_` hash, or the internal door's `'unknown'`) wins untouched;
 *   2. header absent but any `request.cf` locality field usable → `n_` network-locality
 *      key + `ip_masked = 'no-cf-header'`, so the rows stop collapsing into one "user";
 *   3. nothing usable (off-CF, tests) → the historical bare `'unknown'` sentinel.
 * The IP-source rule (cf-connecting-ip only; never x-forwarded-for) is NOT touched — this
 * never feeds rate limiting, dedup, or tier gating, only the analytics attribution key.
 */
export function resolveAccessLogAttribution(input: AccessLogAttributionInput): { ipHash: string; ipMasked: string } {
	if (input.ipHash !== undefined) return { ipHash: input.ipHash, ipMasked: input.ipMasked };
	const usable = (v: string | null | undefined) => typeof v === 'string' && v.length > 0 && v !== 'unknown';
	const cfPresent = (typeof input.asn === 'number' && Number.isFinite(input.asn)) || usable(input.colo) || usable(input.country);
	if (!cfPresent) return { ipHash: 'unknown', ipMasked: input.ipMasked };
	return {
		ipHash: hashNetworkLocalityForAnalytics({
			asn: input.asn,
			colo: usable(input.colo) ? input.colo : null,
			country: usable(input.country) ? input.country : null,
		}),
		ipMasked: NO_CF_HEADER_MARKER,
	};
}
