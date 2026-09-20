// SPDX-License-Identifier: BUSL-1.1
// Read-only public-door IP-header audit (#896). Outputs aggregate counts only.
// Usage: node scripts/audits/client-ip-header-audit.mjs --config <private-config> --database <binding> [--hours 24]
// Or, with the defaults the alert runbook prints: npm run audit:client-ip-headers
// Below CLIENT_IP_AUDIT_MIN_SAMPLES the window widens once to the fallback, unless --hours was given.
// Exit 0: healthy; 1: missing-header regression; 2: unknown/insufficient evidence.
//
// SSOT: `src/lib/client-ip-audit.ts`. The two pure functions below are a byte-for-
// byte COPY of `assessClientIpHeaders` / `clientIpHeaderAuditSql` there — this script
// runs under bare `node` (no TypeScript loader, no build step), so it cannot import
// the module. Change the SSOT first, then mirror here;
// `test/audits/client-ip-header-audit.node.test.ts` pins both to the same SQL and
// the same verdicts, so a one-sided edit fails CI. The 15-min cron lane
// `handleClientIpHeaderAudit` (src/scheduled.ts) reads the SSOT directly.
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

/** Classify aggregate observations without treating missing data as healthy. Mirror of src/lib/client-ip-audit.ts. */
export function assessClientIpHeaders(row, minimumSamples = 20, maximumMissingRatio = 0.05) {
	if (
		!row ||
		!Number.isInteger(row.total) ||
		!Number.isInteger(row.missing) ||
		row.total < 0 ||
		row.missing < 0 ||
		row.missing > row.total
	) {
		return { status: 'unknown', reason: 'invalid_aggregate', exitCode: 2 };
	}
	const metrics = { total: row.total, missing: row.missing, missingRatio: row.total ? row.missing / row.total : null };
	if (row.total < minimumSamples) return { status: 'unknown', reason: 'insufficient_samples', ...metrics, exitCode: 2 };
	const failed = metrics.missingRatio > maximumMissingRatio;
	return { status: failed ? 'degraded' : 'healthy', ...metrics, exitCode: failed ? 1 : 0 };
}

/** Default observation window (hours). Mirror of CLIENT_IP_AUDIT_WINDOW_HOURS in src/lib/client-ip-audit.ts. */
export const CLIENT_IP_AUDIT_WINDOW_HOURS = 24;

/** Wider window retried below the sample floor. Mirror of CLIENT_IP_AUDIT_FALLBACK_WINDOW_HOURS in src/lib/client-ip-audit.ts. */
export const CLIENT_IP_AUDIT_FALLBACK_WINDOW_HOURS = 168;

/** Bound the observation window; SQL contains only a validated integer. Mirror of src/lib/client-ip-audit.ts. */
export function clientIpHeaderAuditSql(hours = CLIENT_IP_AUDIT_WINDOW_HOURS) {
	if (!Number.isInteger(hours) || hours < 1 || hours > 168) throw new Error('hours must be an integer from 1 to 168');
	return `SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN ip_masked = 'no-cf-header' THEN 1 ELSE 0 END), 0) AS missing FROM mcp_access_log WHERE COALESCE(source, 'public') = 'public' AND created_at >= unixepoch('now', '-${hours} hours')`;
}

/**
 * Usage errors are OUR OWN literal strings and carry no paths or credentials, so
 * they are safe to print — unlike a wrangler/auth failure. #1066: previously every
 * failure collapsed into one `audit_failed`, so running the command as the alert
 * printed it (no flags) produced a guaranteed non-answer that read like a
 * measurement. Distinguishing the two is the whole fix.
 */
class UsageError extends Error {}

function main() {
	try {
		const args = process.argv.slice(2);
		const values = new Map();
		for (let i = 0; i < args.length; i += 2) {
			if (!['--config', '--database', '--hours'].includes(args[i]) || !args[i + 1] || values.has(args[i]))
				throw new UsageError('invalid arguments: expected --config <path> --database <binding> [--hours N]');
			values.set(args[i], args[i + 1]);
		}
		const config = values.get('--config');
		const database = values.get('--database');
		if (!config || !database || !/^[a-zA-Z0-9_-]+$/.test(database))
			throw new UsageError('--config <path> and --database <binding> are required (binding: letters, digits, _ or -)');
		const explicitHours = values.has('--hours');
		const hours = Number(values.get('--hours') ?? CLIENT_IP_AUDIT_WINDOW_HOURS);
		const wrangler = fileURLToPath(new URL('../../node_modules/wrangler/bin/wrangler.js', import.meta.url));
		const readWindow = (windowHours) => {
			const output = execFileSync(
				process.execPath,
				[wrangler, 'd1', 'execute', database, '--config', config, '--remote', '--json', '--command', clientIpHeaderAuditSql(windowHours)],
				{
					encoding: 'utf8',
					timeout: 60_000,
					stdio: ['ignore', 'pipe', 'pipe'],
				},
			);
			const response = JSON.parse(output);
			const row = Array.isArray(response) && response.length === 1 && response[0].success === true ? response[0].results?.[0] : undefined;
			return assessClientIpHeaders(row);
		};

		let effectiveHours = hours;
		let result = readWindow(effectiveHours);
		// Mirrors queryClientIpHeaderAuditEscalating in src/scheduled.ts (#1066): below the
		// sample floor, widen once rather than report `unknown`. Skipped when the caller
		// named --hours explicitly — an explicit window is an instruction, not a default.
		if (!explicitHours && result.status === 'unknown' && result.reason === 'insufficient_samples') {
			effectiveHours = CLIENT_IP_AUDIT_FALLBACK_WINDOW_HOURS;
			result = readWindow(effectiveHours);
		}
		console.log(JSON.stringify({ hours: effectiveHours, widenedWindow: effectiveHours !== hours, ...result }));
		process.exitCode = result.exitCode;
	} catch (err) {
		// A usage error is our own literal text — safe, and the thing an operator most
		// needs to see. Anything else may carry CLI output, local paths or credentials,
		// so it stays redacted to the bare `audit_failed` verdict.
		const reason = err instanceof UsageError ? 'invalid_usage' : 'audit_failed';
		const detail = err instanceof UsageError ? { detail: err.message } : {};
		console.error(JSON.stringify({ status: 'unknown', reason, ...detail, exitCode: 2 }));
		process.exitCode = 2;
	}
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
