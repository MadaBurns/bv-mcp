// SPDX-License-Identifier: BUSL-1.1

/**
 * Public-door `cf-connecting-ip` presence audit (#896) — the SINGLE SOURCE OF
 * TRUTH for the aggregate SQL and the healthy / degraded / unknown thresholds.
 *
 * Two consumers read this contract:
 *   - the 15-min cron lane `handleClientIpHeaderAudit` in `src/scheduled.ts`,
 *     which imports it directly and pages the operator webhook on `degraded`;
 *   - the operator CLI `scripts/audits/client-ip-header-audit.mjs`
 *     (`npm run audit:client-ip-headers`), which cannot import TypeScript from a
 *     bare `node` invocation and therefore carries a byte-for-byte copy of the two
 *     pure functions below. `test/audits/client-ip-header-audit.node.test.ts`
 *     pins that copy to this module (same SQL, same verdicts) so the two cannot
 *     drift silently.
 *
 * Why this exists: the header is what every per-IP security decision keys on
 * (rate limits, quotas, owner-tier gating, audit `ipHash`). When a zone-level
 * transform strips it, the Worker sees NO error — every request simply becomes
 * `'unknown'` and the access log records `ip_masked = 'no-cf-header'`
 * (`NO_CF_HEADER_MARKER` in `src/lib/access-log-event.ts`). Measured live on
 * 2026-09-09: 94.4% of public-door rows (24h) and 79.5% (168h) carried no header.
 * The fix is an operator zone-config change; this module only makes the
 * regression visible.
 *
 * Fail-open doctrine: "0 missing of 0" is NOT healthy — below the sample floor the
 * verdict is `unknown`, never `healthy`.
 */

/** Minimum public-door rows in the window before a ratio is believed. */
export const CLIENT_IP_AUDIT_MIN_SAMPLES = 20;

/** Highest tolerated `missing / total` ratio; strictly above this is `degraded`. */
export const CLIENT_IP_AUDIT_MAX_MISSING_RATIO = 0.05;

/** Observation window the cron lane queries (hours). */
export const CLIENT_IP_AUDIT_WINDOW_HOURS = 1;

/** Alert kind emitted by the cron lane when the audit is `degraded`. */
export const CLIENT_IP_HEADER_MISSING_ALERT_KIND = 'client_ip_header_missing';

/** Shape of the single aggregate row returned by {@link clientIpHeaderAuditSql}. */
export interface ClientIpAuditRow {
	total: number;
	missing: number;
}

export type ClientIpAuditStatus = 'healthy' | 'degraded' | 'unknown';

export interface ClientIpAuditAssessment {
	status: ClientIpAuditStatus;
	/** Present only for `unknown` verdicts. */
	reason?: 'invalid_aggregate' | 'insufficient_samples';
	total?: number;
	missing?: number;
	missingRatio?: number | null;
	/** CLI exit code: 0 healthy, 1 degraded, 2 unknown. */
	exitCode: 0 | 1 | 2;
}

/**
 * Classify aggregate observations without treating missing data as healthy.
 *
 * Mirrors `assessClientIpHeaders` in `scripts/audits/client-ip-header-audit.mjs`
 * — keep the two in lockstep (pinned by the node audit test).
 */
export function assessClientIpHeaders(
	row: Partial<ClientIpAuditRow> | null | undefined,
	minimumSamples: number = CLIENT_IP_AUDIT_MIN_SAMPLES,
	maximumMissingRatio: number = CLIENT_IP_AUDIT_MAX_MISSING_RATIO,
): ClientIpAuditAssessment {
	if (
		!row ||
		!Number.isInteger(row.total) ||
		!Number.isInteger(row.missing) ||
		(row.total as number) < 0 ||
		(row.missing as number) < 0 ||
		(row.missing as number) > (row.total as number)
	) {
		return { status: 'unknown', reason: 'invalid_aggregate', exitCode: 2 };
	}
	const total = row.total as number;
	const missing = row.missing as number;
	const metrics = { total, missing, missingRatio: total ? missing / total : null };
	if (total < minimumSamples) return { status: 'unknown', reason: 'insufficient_samples', ...metrics, exitCode: 2 };
	const failed = (metrics.missingRatio as number) > maximumMissingRatio;
	return { status: failed ? 'degraded' : 'healthy', ...metrics, exitCode: failed ? 1 : 0 };
}

/**
 * One aggregate SELECT over the public door in a bounded window. The SQL
 * contains only a validated integer — never interpolate anything else.
 *
 * Mirrors `clientIpHeaderAuditSql` in `scripts/audits/client-ip-header-audit.mjs`
 * — keep the two in lockstep (pinned by the node audit test).
 */
export function clientIpHeaderAuditSql(hours: number = CLIENT_IP_AUDIT_WINDOW_HOURS): string {
	if (!Number.isInteger(hours) || hours < 1 || hours > 168) throw new Error('hours must be an integer from 1 to 168');
	return `SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN ip_masked = 'no-cf-header' THEN 1 ELSE 0 END), 0) AS missing FROM mcp_access_log WHERE COALESCE(source, 'public') = 'public' AND created_at >= unixepoch('now', '-${hours} hours')`;
}

/**
 * Coerce a D1 row into integers. D1 returns COUNT/SUM as JS numbers already, but
 * a driver that hands back strings (or a missing column on an unmigrated table)
 * must degrade to `unknown`, not to a false `healthy`.
 */
export function coerceClientIpAuditRow(raw: unknown): Partial<ClientIpAuditRow> | undefined {
	if (!raw || typeof raw !== 'object') return undefined;
	const rec = raw as Record<string, unknown>;
	const toInt = (v: unknown): number | undefined => {
		if (typeof v === 'number') return v;
		if (typeof v === 'string' && /^\d+$/.test(v)) return Number(v);
		return undefined;
	};
	return { total: toInt(rec.total), missing: toInt(rec.missing) };
}
