// SPDX-License-Identifier: BUSL-1.1

/**
 * Pre-built SQL queries for Cloudflare Analytics Engine.
 *
 * Returns query strings for the Analytics Engine SQL API.
 *
 * IMPORTANT — dataset vs binding name: AE's SQL API queries by DATASET name, NOT
 * by Worker binding name. The binding `MCP_ANALYTICS` maps to the dataset
 * `bv_dns_security_mcp` in prod (and `bv_mcp_usage_reporting` locally). Querying
 * `FROM MCP_ANALYTICS` (the binding name) silently returns 0 rows. The dataset is
 * therefore injected per-call (defaulting to {@link DEFAULT_ANALYTICS_DATASET}) and
 * validated against `/^[a-z0-9_]+$/` before interpolation. Override via the
 * `ANALYTICS_DATASET` env var, threaded from the query call sites the same way
 * `CF_ACCOUNT_ID` / `CF_ANALYTICS_TOKEN` are.
 *
 * Callers must account for _sample_interval in aggregations.
 *
 * Blob positions (mcp_request): blob1=method, blob2=transport, blob3=status,
 *   blob4=auth, blob5=jsonrpc, blob6=country, blob7=clientType, blob8=tier, blob9=sessionHash,
 *   blob10=keyHash, blob11=ipHash, blob12=colo (edge datacenter, append-only).
 *   Double positions: double1=durationMs, double2=abs(jsonRpcErrorCode) (0 when no error).
 * Blob positions (tool_call): blob1=toolName, blob2=status, blob3=isError,
 *   blob4=hashedDomain, blob5=country, blob6=clientType, blob7=tier, blob8=cacheStatus,
 *   blob9=keyHash, blob10=ipHash, blob11=colo (edge datacenter, append-only).
 * Double positions (tool_call): double1=durationMs, double2=score
 * Blob positions (rate_limit): blob1=limitType, blob2=toolName, blob3=country, blob4=tier
 * Blob positions (session): blob1=action, blob2=country, blob3=clientType, blob4=tier
 */

/**
 * Default Analytics Engine DATASET name (not the Worker binding name). This is the
 * prod dataset the `MCP_ANALYTICS` binding writes to; using it as the in-code default
 * means prod works with zero config. Overridable per-deploy via `ANALYTICS_DATASET`.
 */
export const DEFAULT_ANALYTICS_DATASET = 'bv_dns_security_mcp';

/**
 * Resolve + validate a dataset name for safe SQL interpolation. Since the name can
 * now come from env, it is validated against `/^[a-z0-9_]+$/` (defense-in-depth) and
 * any empty/invalid value falls back to {@link DEFAULT_ANALYTICS_DATASET}. Idempotent,
 * so call sites and the builders can both apply it.
 */
export function resolveAnalyticsDataset(name: string | undefined): string {
	return name && /^[a-z0-9_]+$/.test(name) ? name : DEFAULT_ANALYTICS_DATASET;
}

/** Sanitize interval parameter to prevent SQL injection. */
function safeInterval(value: string): string {
	const parsed = parseInt(value, 10);
	return String(Number.isFinite(parsed) && parsed > 0 ? parsed : 1);
}

/** Unique sessions (by hashed session ID) in the given interval. */
export function queryDailyActiveUsers(days: string, dataset?: string): string {
	days = safeInterval(days);
	return `SELECT
  toStartOfDay(timestamp) AS day,
  COUNT(DISTINCT blob9) AS unique_sessions,
  SUM(_sample_interval) AS total_requests
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'mcp_request'
  AND blob9 != 'none'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY day
ORDER BY day DESC`;
}

/** Tool call counts ranked by popularity. */
export function queryToolPopularity(days: string, dataset?: string): string {
	days = safeInterval(days);
	return `SELECT
  blob1 AS tool_name,
  SUM(_sample_interval) AS call_count,
  SUM(CASE WHEN blob2 = 'pass' THEN _sample_interval ELSE 0 END) AS pass_count,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS error_count
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY tool_name
ORDER BY call_count DESC`;
}

/** Error rate per tool over the given interval. */
export function queryErrorRate(days: string, dataset?: string): string {
	days = safeInterval(days);
	return `SELECT
  blob1 AS tool_name,
  SUM(_sample_interval) AS total,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS errors,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) * 100.0 / SUM(_sample_interval) AS error_pct
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY tool_name
HAVING total > 10
ORDER BY error_pct DESC`;
}

/** Latency percentiles per tool. */
export function queryLatencyPercentiles(days: string, dataset?: string): string {
	days = safeInterval(days);
	return `SELECT
  blob1 AS tool_name,
  SUM(_sample_interval) AS call_count,
  quantileExactWeighted(0.50)(double1, _sample_interval) AS p50_ms,
  quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_ms,
  quantileExactWeighted(0.99)(double1, _sample_interval) AS p99_ms
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY tool_name
ORDER BY call_count DESC`;
}

/** Request breakdown by MCP client type. */
export function queryClientBreakdown(days: string, dataset?: string): string {
	days = safeInterval(days);
	return `SELECT
  blob7 AS client_type,
  SUM(_sample_interval) AS request_count,
  COUNT(DISTINCT blob9) AS unique_sessions
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'mcp_request'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY client_type
ORDER BY request_count DESC`;
}

/** Geographic distribution by country. */
export function queryGeoDistribution(days: string, dataset?: string): string {
	days = safeInterval(days);
	return `SELECT
  blob6 AS country,
  SUM(_sample_interval) AS request_count,
  COUNT(DISTINCT blob9) AS unique_sessions
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'mcp_request'
  AND blob6 != 'unknown'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY country
ORDER BY request_count DESC
LIMIT 30`;
}

/**
 * Geographic rollup for heatmaps — request volume per country/region/city/asn
 * from `tool_call`. The geo dimensions are append-only blobs (blob5=country,
 * blob13=region, blob14=city, blob15=asn — see analytics.ts), so positions
 * 1–12 are untouched. Sampled: sums `_sample_interval`.
 */
export function queryGeoRollup(days: string, dataset?: string): string {
	days = safeInterval(days);
	return `SELECT
  blob5 AS country,
  blob13 AS region,
  blob14 AS city,
  blob15 AS asn,
  SUM(_sample_interval) AS calls
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY country, region, city, asn
ORDER BY calls DESC
LIMIT 1000`;
}

/** Rate limit hit counts by type. */
export function queryRateLimitHits(days: string, dataset?: string): string {
	days = safeInterval(days);
	return `SELECT
  blob1 AS limit_type,
  blob2 AS tool_name,
  SUM(_sample_interval) AS hit_count
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'rate_limit'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY limit_type, tool_name
ORDER BY hit_count DESC`;
}

/** Auth tier distribution. */
export function queryTierBreakdown(days: string, dataset?: string): string {
	days = safeInterval(days);
	return `SELECT
  blob8 AS tier,
  SUM(_sample_interval) AS request_count
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'mcp_request'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY tier
ORDER BY request_count DESC`;
}

/** Anomaly detection query for alerting. Returns error rate and p95 latency for the last N minutes. */
export function queryRecentAnomalies(minutes: string, dataset?: string): string {
	minutes = safeInterval(minutes);
	return `SELECT
  SUM(_sample_interval) AS total_calls,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS error_count,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) * 100.0
    / GREATEST(SUM(_sample_interval), 1) AS error_pct,
  quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_ms
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${minutes}' MINUTE`;
}

/**
 * Per-colo anomaly detection for alerting. Same error-rate / p95 shape as
 * {@link queryRecentAnomalies} but GROUPed BY edge datacenter (`tool_call` blob11),
 * so a single-colo regression that averages out in the global aggregate is
 * surfaced on its own row and can trip ALERT_P95_THRESHOLD / error-rate alerts.
 * `HAVING total_calls > 0` drops empty colos. Excludes the `'unknown'` colo
 * (off-CF / local) so it doesn't pollute the per-datacenter view.
 */
export function queryRecentAnomaliesByColo(minutes: string, dataset?: string): string {
	minutes = safeInterval(minutes);
	return `SELECT
  blob11 AS colo,
  SUM(_sample_interval) AS total_calls,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS error_count,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) * 100.0
    / GREATEST(SUM(_sample_interval), 1) AS error_pct,
  quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_ms
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'
  AND blob11 != 'unknown'
  AND timestamp > NOW() - INTERVAL '${minutes}' MINUTE
GROUP BY colo
HAVING total_calls > 0
ORDER BY p95_ms DESC`;
}

/** Rate limit surge detection for alerting. */
export function queryRateLimitSurge(minutes: string, dataset?: string): string {
	minutes = safeInterval(minutes);
	return `SELECT
  SUM(_sample_interval) AS total_hits
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'rate_limit'
  AND timestamp > NOW() - INTERVAL '${minutes}' MINUTE`;
}

/**
 * Degradation-event detection for alerting. Counts `degradation` events over the
 * last N minutes, grouped by component + kind. The signal families that land here:
 *  - operator-only service-binding failures (BV_RECON / BV_TLS_PROBE 5xx /
 *    timeout / unavailable), and
 *  - `cost_ceiling_degraded` (component `global_cost_ceiling`) when the
 *    QuotaCoordinator DO breaker is OPEN and the global cost ceiling is running on
 *    a degraded fallback (R9 — this MUST reach the alert).
 *
 * Excludes the `kv_fallback` member (deliberate session-store noise, alerted
 * separately if at all) and the `quota_coordinator_fallback` member (R8 — a
 * quota-guardrail concern queried/alerted separately, NOT a service-binding
 * failure). The filter keys on degradationType (blob1), NOT component (blob2) --
 * a new alertable signal must therefore use a non-excluded degradationType, not
 * merely a distinct component.
 *
 * Blob positions (degradation): blob1=degradationType, blob2=component.
 */
export function queryBindingDegradation(minutes: string, dataset?: string): string {
	minutes = safeInterval(minutes);
	return `SELECT
  blob2 AS component,
  blob1 AS degradation_type,
  SUM(_sample_interval) AS event_count
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'degradation'
  AND blob1 != 'kv_fallback'
  AND blob1 != 'quota_coordinator_fallback'
  AND blob1 != 'quota_shard_salt_missing'
  AND timestamp > NOW() - INTERVAL '${minutes}' MINUTE
GROUP BY component, degradation_type
ORDER BY event_count DESC`;
}

/**
 * R8 per-shard load-SKEW detection. Aggregates `quota_shard` events (emitted only
 * while QuotaCoordinator sharding is ON — see `emitQuotaShardEvent` in analytics.ts)
 * into per-shard load, then returns the MAX-shard load, the MEAN across active shards,
 * and their ratio. A healthy fan-out keeps `skew_ratio` near 1; a hot shard (an
 * IP-range concentrating onto one DO, or a missing salt making the mapping
 * precomputable) pushes it up — the signal an operator watches after flipping the flag.
 * `GREATEST(avg(...), 1)` guards the divide when no shard traffic exists.
 *
 * Blob positions (quota_shard): blob1=shardIndex, blob2=country, blob3=tier.
 */
export function queryQuotaShardSkew(minutes: string, dataset?: string): string {
	minutes = safeInterval(minutes);
	return `SELECT
  max(shard_load) AS max_shard_load,
  avg(shard_load) AS mean_shard_load,
  max(shard_load) / GREATEST(avg(shard_load), 1) AS skew_ratio,
  COUNT(*) AS active_shards
FROM (
  SELECT
    blob1 AS shard,
    SUM(_sample_interval) AS shard_load
  FROM ${resolveAnalyticsDataset(dataset)}
  WHERE index1 = 'quota_shard'
    AND timestamp > NOW() - INTERVAL '${minutes}' MINUTE
  GROUP BY shard
)`;
}

/**
 * Async-path (queue/cron) batch-failure detection for alerting. The queue
 * consumer + cron handlers emit a `queue_batch` event per run (see
 * `emitQueueBatchEvent` in analytics.ts) so a brand-audit queue batch that
 * throws — invisible to `queryRecentAnomalies` (which filters
 * `index1='tool_call'`) — becomes alertable. Counts errored batches and the
 * total failed messages/sub-tasks per handler over the last N minutes.
 *
 * Blob positions (queue_batch): blob1=handler, blob2=outcome. Doubles:
 *   double1=durationMs, double2=failureCount, double3=messageCount.
 */
export function queryQueueFailures(minutes: string, dataset?: string): string {
	minutes = safeInterval(minutes);
	return `SELECT
  blob1 AS handler,
  SUM(_sample_interval) AS batch_count,
  SUM(CASE WHEN blob2 = 'error' THEN _sample_interval ELSE 0 END) AS error_batch_count,
  SUM(double2 * _sample_interval) AS failure_count
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'queue_batch'
  AND timestamp > NOW() - INTERVAL '${minutes}' MINUTE
GROUP BY handler
HAVING error_batch_count > 0 OR failure_count > 0
ORDER BY failure_count DESC`;
}

/** Fatal Worker exception detection from Tail Worker exports. */
export function queryTailExceptions(minutes: string, dataset?: string): string {
	minutes = safeInterval(minutes);
	// emitTailAggregate (analytics.ts) writes blob1=colo, blob2=outcome,
	// double1=invocations in the bucket. Fatal invocations are the ones in
	// outcome='exception' buckets; double1 × _sample_interval is the
	// sampled-correct invocation count (mirrors queryQueueFailures above).
	return `SELECT
  SUM(double1 * _sample_interval) AS exception_count
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tail'
  AND blob2 = 'exception'
  AND timestamp > NOW() - INTERVAL '${minutes}' MINUTE`;
}

// ---------------------------------------------------------------------------
// Per-Tier Analytics Queries
// ---------------------------------------------------------------------------
// All accept an optional `tier` parameter. When provided, results are filtered
// to that tier. When omitted, results are grouped by tier.

/** Sanitize tier value: lowercase, alphanumeric/underscore only, max 20 chars. */
function safeTier(value: string | undefined): string | undefined {
	if (!value) return undefined;
	const cleaned = value
		.trim()
		.toLowerCase()
		.replace(/[^a-z0-9_]/g, '')
		.slice(0, 20);
	return cleaned || undefined;
}

/** Helper: builds WHERE clause fragment for optional tier filter on a given blob position. */
function tierClause(tier: string | undefined, blobPosition: string): string {
	return tier ? `\n  AND ${blobPosition} = '${tier}'` : '';
}

/** Helper: builds GROUP BY / ORDER BY for tier column when no filter is specified. */
function tierGroupBy(tier: string | undefined, alias: string): string {
	return tier ? '' : `\nGROUP BY ${alias}`;
}

/** Tool popularity breakdown per tier. Which tools does each tier use most? */
export function queryTierToolUsage(days: string, tier?: string, dataset?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  blob1 AS tool_name,
  SUM(_sample_interval) AS call_count,
  SUM(CASE WHEN blob2 = 'pass' THEN _sample_interval ELSE 0 END) AS pass_count,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS error_count
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'tool_name' : 'tier, tool_name'}
ORDER BY ${tier ? 'call_count DESC' : 'tier, call_count DESC'}`;
}

/** P50/P95/P99 latency per tier. */
export function queryTierLatency(days: string, tier?: string, dataset?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  SUM(_sample_interval) AS call_count,
  quantileExactWeighted(0.50)(double1, _sample_interval) AS p50_ms,
  quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_ms,
  quantileExactWeighted(0.99)(double1, _sample_interval) AS p99_ms
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY${tierGroupBy(tier, 'tier')}
ORDER BY ${tier ? 'call_count DESC' : 'tier'}`;
}

/** Error rate per tier. */
export function queryTierErrorRate(days: string, tier?: string, dataset?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  SUM(_sample_interval) AS total,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS errors,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) * 100.0
    / GREATEST(SUM(_sample_interval), 1) AS error_pct
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY${tierGroupBy(tier, 'tier')}
HAVING total > 0
ORDER BY ${tier ? 'error_pct DESC' : 'tier'}`;
}

/** Cache hit/miss ratio per tier. */
export function queryTierCachePerformance(days: string, tier?: string, dataset?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  blob8 AS cache_status,
  SUM(_sample_interval) AS call_count
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'
  AND blob8 != 'n/a'${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'cache_status' : 'tier, cache_status'}
ORDER BY ${tier ? 'call_count DESC' : 'tier, call_count DESC'}`;
}

/** Rate limit hits per tier. */
export function queryTierRateLimits(days: string, tier?: string, dataset?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob4 AS tier,'}
  blob1 AS limit_type,
  blob2 AS tool_name,
  SUM(_sample_interval) AS hit_count
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'rate_limit'${tierClause(tier, 'blob4')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'limit_type, tool_name' : 'tier, limit_type, tool_name'}
ORDER BY ${tier ? 'hit_count DESC' : 'tier, hit_count DESC'}`;
}

/** Session creation/termination per tier. */
export function queryTierSessions(days: string, tier?: string, dataset?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob4 AS tier,'}
  blob1 AS action,
  SUM(_sample_interval) AS event_count
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'session'${tierClause(tier, 'blob4')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'action' : 'tier, action'}
ORDER BY ${tier ? 'event_count DESC' : 'tier, event_count DESC'}`;
}

/** Unique domains scanned per tier. */
export function queryTierDomainDiversity(days: string, tier?: string, dataset?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  COUNT(DISTINCT blob4) AS unique_domains,
  SUM(_sample_interval) AS total_calls
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'
  AND blob4 != 'none'${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY${tierGroupBy(tier, 'tier')}
ORDER BY ${tier ? 'total_calls DESC' : 'tier'}`;
}

/** Scan score distribution per tier (average, min, max). */
export function queryTierScoreDistribution(days: string, tier?: string, dataset?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  SUM(_sample_interval) AS scan_count,
  avg(double2) AS avg_score,
  min(double2) AS min_score,
  max(double2) AS max_score,
  quantileExactWeighted(0.50)(double2, _sample_interval) AS median_score
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'
  AND blob1 = 'scan_domain'
  AND double2 > 0${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY${tierGroupBy(tier, 'tier')}
ORDER BY ${tier ? 'scan_count DESC' : 'tier'}`;
}

/** Daily request volume trended over time, per tier. */
export function queryTierDailyTrend(days: string, tier?: string, dataset?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT
  toStartOfDay(timestamp) AS day,${tier ? '' : '\n  blob8 AS tier,'}
  SUM(_sample_interval) AS request_count,
  COUNT(DISTINCT blob9) AS unique_sessions
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'mcp_request'${tierClause(tier, 'blob8')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'day' : 'day, tier'}
ORDER BY day DESC${tier ? '' : ', tier'}`;
}

/** MCP client type distribution per tier. */
export function queryTierClientTypes(days: string, tier?: string, dataset?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob8 AS tier,'}
  blob7 AS client_type,
  SUM(_sample_interval) AS request_count,
  COUNT(DISTINCT blob9) AS unique_sessions
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'mcp_request'${tierClause(tier, 'blob8')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'client_type' : 'tier, client_type'}
ORDER BY ${tier ? 'request_count DESC' : 'tier, request_count DESC'}`;
}

/** Per-API-key usage breakdown. Requires keyHash blob (blob9 in tool_call). */
export function queryKeyUsage(days: string, keyHash?: string, dataset?: string): string {
	days = safeInterval(days);
	const keyFilter = keyHash ? `\n  AND blob9 = '${safeTier(keyHash) ?? 'none'}'` : `\n  AND blob9 != 'none'`;
	return `SELECT
  blob9 AS key_hash,
  blob7 AS tier,
  SUM(_sample_interval) AS call_count,
  COUNT(DISTINCT blob1) AS unique_tools,
  COUNT(DISTINCT blob4) AS unique_domains,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS error_count,
  quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_ms
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'${keyFilter}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY key_hash, tier
ORDER BY call_count DESC
LIMIT 50`;
}

/** Daily tier usage digest — all tiers in one query, aggregated for the past N hours. */
export function queryTierDigest(hours: string, dataset?: string): string {
	hours = safeInterval(hours);
	return `SELECT
  blob7 AS tier,
  SUM(_sample_interval) AS total_calls,
  COUNT(DISTINCT blob4) AS unique_domains,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS error_count,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) * 100.0
    / GREATEST(SUM(_sample_interval), 1) AS error_pct,
  quantileExactWeighted(0.50)(double1, _sample_interval) AS p50_ms,
  quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_ms,
  SUM(CASE WHEN blob8 = 'hit' THEN _sample_interval ELSE 0 END) AS cache_hits,
  SUM(CASE WHEN blob8 = 'miss' THEN _sample_interval ELSE 0 END) AS cache_misses
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${hours}' HOUR
GROUP BY tier
ORDER BY total_calls DESC`;
}

/** Top tools per tier for digest. */
export function queryTierTopTools(hours: string, dataset?: string): string {
	hours = safeInterval(hours);
	return `SELECT
  blob7 AS tier,
  blob1 AS tool_name,
  SUM(_sample_interval) AS call_count
FROM ${resolveAnalyticsDataset(dataset)}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${hours}' HOUR
GROUP BY tier, tool_name
ORDER BY tier, call_count DESC`;
}
