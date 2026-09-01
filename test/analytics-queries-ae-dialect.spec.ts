// SPDX-License-Identifier: BUSL-1.1

/**
 * AE SQL DIALECT CONTRACT.
 *
 * Cloudflare Analytics Engine's SQL API accepts a SUBSET of ClickHouse SQL. Several
 * constructs that are valid ClickHouse — and that read as obviously correct — are
 * rejected by the AE parser with HTTP 422, which `queryAnalyticsEngine` surfaces as a
 * thrown error. In the scheduled alerting path that single throw aborts the whole
 * check, disabling EVERY threshold alert (error rate, p95, rate-limit surge, binding
 * degradation, queue failures, tail exceptions) while leaving only the watchdog.
 *
 * That is not hypothetical: `CASE WHEN` + `GREATEST()` in the alerting queries had the
 * bv-mcp alerting pipeline 422-ing on every 15-minute tick, continuously, from the
 * commit that introduced the builders until this test landed.
 *
 * Every entry below was MEASURED against the live AE SQL API
 * (`POST /accounts/{id}/analytics_engine/sql`) on 2026-08-19 — each `bad` string
 * returned 422 with the quoted message, and each `use` replacement returned 200
 * against the prod `bv_dns_security_mcp` dataset. Do not relax an entry without
 * re-measuring: the string-level test is the only gate here, because no unit test
 * executes these queries.
 */

import { describe, it, expect } from 'vitest';
import * as builders from '../src/lib/analytics-queries';

/** Constructs the AE SQL parser rejects, with the measured 422 message and the fix. */
const UNSUPPORTED: ReadonlyArray<{ label: string; pattern: RegExp; measured: string; use: string }> = [
	{
		label: 'CASE WHEN',
		pattern: /\bCASE\s+WHEN\b/i,
		measured: "Input was invalid: unsupported expression type: CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END",
		use: "if(cond, a, b)  — e.g. SUM(if(blob3 = 'error', _sample_interval, 0))",
	},
	{
		label: 'GREATEST()',
		pattern: /\bGREATEST\s*\(/i,
		// Rejected in BOTH cases — the parser reports the name upper-cased regardless.
		measured: 'Input was invalid: unknown function call: GREATEST',
		use: 'if(x > n, x, n)  — mind the branch types, see the IF() type rule below',
	},
	{
		label: 'multiIf()',
		pattern: /\bmultiIf\s*\(/i,
		measured: 'Input was invalid: unknown function call: MULTIIF',
		use: 'nested if(...)',
	},
	{
		label: 'max2()',
		pattern: /\bmax2\s*\(/i,
		measured: 'Input was invalid: unknown function call: MAX2',
		use: 'if(x > n, x, n)',
	},
	{
		label: 'COUNT(*)',
		pattern: /\bCOUNT\s*\(\s*\*\s*\)/i,
		measured: 'Input was invalid: COUNT() function must have 0 arguments: 1',
		use: 'count()',
	},
];

/**
 * AE's IF() is strictly typed: the 2nd and 3rd arguments must share a type. A Double
 * expression guarded by an Integer literal 422s with
 *   "the 2nd and 3rd arguments to IF() function must have the same type but instead
 *    had Double and Integer"
 * so a guard over avg()/a division must spell its literal `1.0`, not `1`.
 * Measured 2026-08-19. Aggregates that return an integer type (SUM over
 * `_sample_interval`) correctly pair with a bare `1`.
 */
const DOUBLE_RETURNING_AGGREGATES = /\bif\s*\(\s*(avg|quantile\w*)\s*\([^)]*\)[^,]*,[^,]*,\s*(\d+)\s*\)/gi;

/**
 * Invoke every exported builder with plausible arguments so the assertions run over
 * the SQL that actually ships, not over a hand-picked subset. Builders take
 * (interval, ...optional) — passing the optional args exercises both branches of the
 * tier-filtered / unfiltered shapes.
 */
function allGeneratedSql(): Array<{ name: string; sql: string }> {
	const out: Array<{ name: string; sql: string }> = [];
	for (const [name, fn] of Object.entries(builders)) {
		if (typeof fn !== 'function' || !name.startsWith('query')) continue;
		const build = fn as (...args: unknown[]) => unknown;
		// Both the filtered and unfiltered shapes: the 2nd arg is `tier`/`keyHash` on
		// the per-tier builders and `dataset` on the rest, so try each arity.
		for (const args of [['15'], ['15', 'pro'], ['15', undefined, 'bv_dns_security_mcp']]) {
			let sql: unknown;
			try {
				sql = build(...args);
			} catch {
				continue;
			}
			if (typeof sql === 'string' && sql.length > 0) out.push({ name: `${name}(${args.filter(Boolean).join(', ')})`, sql });
		}
	}
	return out;
}

describe('AE SQL dialect contract', () => {
	it('exercises every exported query builder', () => {
		const generated = allGeneratedSql();
		const names = new Set(generated.map((g) => g.name.split('(')[0]));
		const exported = Object.entries(builders).filter(([n, f]) => typeof f === 'function' && n.startsWith('query')).length;
		expect(names.size).toBe(exported);
		expect(exported).toBeGreaterThan(20);
	});

	for (const { label, pattern, measured, use } of UNSUPPORTED) {
		it(`no builder emits ${label} — AE returns 422: ${measured}`, () => {
			const offenders = allGeneratedSql()
				.filter(({ sql }) => pattern.test(sql))
				.map(({ name }) => name);
			expect(offenders, `${label} is rejected by the AE SQL API. Use ${use}. Offending builders:\n  ${offenders.join('\n  ')}`).toEqual([]);
		});
	}

	it('guards a Double-returning aggregate with a Double literal, not an Integer', () => {
		const offenders = allGeneratedSql()
			.filter(({ sql }) => {
				DOUBLE_RETURNING_AGGREGATES.lastIndex = 0;
				return DOUBLE_RETURNING_AGGREGATES.test(sql);
			})
			.map(({ name }) => name);
		expect(offenders, `AE IF() requires both branches to share a type; write 1.0 not 1. Offending builders:\n  ${offenders.join('\n  ')}`).toEqual([]);
	});

	it('the alerting queries specifically are dialect-clean (the ones whose 422 blinded every alert)', () => {
		const alerting = [
			builders.queryRecentAnomalies('15'),
			builders.queryRecentAnomaliesByColo('15'),
			builders.queryRateLimitSurge('15'),
			builders.queryBindingDegradation('15'),
			builders.queryQueueFailures('15'),
			builders.queryTailExceptions('15'),
			builders.queryToolOutcomeReasons('15'),
			builders.queryTierDigest('24'),
		];
		for (const sql of alerting) {
			for (const { pattern } of UNSUPPORTED) expect(sql).not.toMatch(pattern);
		}
	});
});
