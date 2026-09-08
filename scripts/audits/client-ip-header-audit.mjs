// SPDX-License-Identifier: BUSL-1.1
// Read-only public-door IP-header audit (#896). Outputs aggregate counts only.
// Usage: node scripts/audits/client-ip-header-audit.mjs --config <private-config> --database <binding> [--hours 1]
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

/** Bound the observation window; SQL contains only a validated integer. Mirror of src/lib/client-ip-audit.ts. */
export function clientIpHeaderAuditSql(hours = 1) {
	if (!Number.isInteger(hours) || hours < 1 || hours > 168) throw new Error('hours must be an integer from 1 to 168');
	return `SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN ip_masked = 'no-cf-header' THEN 1 ELSE 0 END), 0) AS missing FROM mcp_access_log WHERE COALESCE(source, 'public') = 'public' AND created_at >= unixepoch('now', '-${hours} hours')`;
}

function main() {
	try {
		const args = process.argv.slice(2);
		const values = new Map();
		for (let i = 0; i < args.length; i += 2) {
			if (!['--config', '--database', '--hours'].includes(args[i]) || !args[i + 1] || values.has(args[i]))
				throw new Error('invalid arguments');
			values.set(args[i], args[i + 1]);
		}
		const config = values.get('--config');
		const database = values.get('--database');
		if (!config || !database || !/^[a-zA-Z0-9_-]+$/.test(database)) throw new Error('config and database are required');
		const hours = Number(values.get('--hours') ?? 1);
		const sql = clientIpHeaderAuditSql(hours);
		const wrangler = fileURLToPath(new URL('../../node_modules/wrangler/bin/wrangler.js', import.meta.url));
		const output = execFileSync(
			process.execPath,
			[wrangler, 'd1', 'execute', database, '--config', config, '--remote', '--json', '--command', sql],
			{
				encoding: 'utf8',
				timeout: 60_000,
				stdio: ['ignore', 'pipe', 'pipe'],
			},
		);
		const response = JSON.parse(output);
		const row = Array.isArray(response) && response.length === 1 && response[0].success === true ? response[0].results?.[0] : undefined;
		const result = assessClientIpHeaders(row);
		console.log(JSON.stringify({ hours, ...result }));
		process.exitCode = result.exitCode;
	} catch {
		// Do not echo CLI output, local paths or credentials on query/auth failure.
		console.error(JSON.stringify({ status: 'unknown', reason: 'audit_failed', exitCode: 2 }));
		process.exitCode = 2;
	}
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
