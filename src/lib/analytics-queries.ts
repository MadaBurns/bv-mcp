// SPDX-License-Identifier: BUSL-1.1

/**
 * Pre-built SQL queries for Cloudflare Analytics Engine.
 *
 * Returns query strings for the Analytics Engine SQL API.
 * Dataset name is always MCP_ANALYTICS.
 * Callers must account for _sample_interval in aggregations.
 *
 * Blob positions (mcp_request): blob1=method, blob2=transport, blob3=status,
 *   blob4=auth, blob5=jsonrpc, blob6=country, blob7=clientType, blob8=tier, blob9=sessionHash
 * Blob positions (tool_call): blob1=toolName, blob2=status, blob3=isError,
 *   blob4=hashedDomain, blob5=country, blob6=clientType, blob7=tier, blob8=cacheStatus
 * Double positions (tool_call): double1=durationMs, double2=score
 * Blob positions (rate_limit): blob1=limitType, blob2=toolName, blob3=country, blob4=tier
 * Blob positions (session): blob1=action, blob2=country, blob3=clientType, blob4=tier
 */

const DS = 'MCP_ANALYTICS';

/** Sanitize interval parameter to prevent SQL injection. */
function safeInterval(value: string): string {
	const parsed = parseInt(value, 10);
	return String(Number.isFinite(parsed) && parsed > 0 ? parsed : 1);
}

/** Unique sessions (by hashed session ID) in the given interval. */
export function queryDailyActiveUsers(days: string): string {
	days = safeInterval(days);
	return `SELECT
  toStartOfDay(timestamp) AS day,
  COUNT(DISTINCT blob9) AS unique_sessions,
  SUM(_sample_interval) AS total_requests
FROM ${DS}
WHERE index1 = 'mcp_request'
  AND blob9 != 'none'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY day
ORDER BY day DESC`;
}

/** Tool call counts ranked by popularity. */
export function queryToolPopularity(days: string): string {
	days = safeInterval(days);
	return `SELECT
  blob1 AS tool_name,
  SUM(_sample_interval) AS call_count,
  SUM(CASE WHEN blob2 = 'pass' THEN _sample_interval ELSE 0 END) AS pass_count,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS error_count
FROM ${DS}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY tool_name
ORDER BY call_count DESC`;
}

/** Error rate per tool over the given interval. */
export function queryErrorRate(days: string): string {
	days = safeInterval(days);
	return `SELECT
  blob1 AS tool_name,
  SUM(_sample_interval) AS total,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS errors,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) * 100.0 / SUM(_sample_interval) AS error_pct
FROM ${DS}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY tool_name
HAVING total > 10
ORDER BY error_pct DESC`;
}

/** Latency percentiles per tool. */
export function queryLatencyPercentiles(days: string): string {
	days = safeInterval(days);
	return `SELECT
  blob1 AS tool_name,
  SUM(_sample_interval) AS call_count,
  quantileExactWeighted(0.50)(double1, _sample_interval) AS p50_ms,
  quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_ms,
  quantileExactWeighted(0.99)(double1, _sample_interval) AS p99_ms
FROM ${DS}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY tool_name
ORDER BY call_count DESC`;
}

/** Request breakdown by MCP client type. */
export function queryClientBreakdown(days: string): string {
	days = safeInterval(days);
	return `SELECT
  blob7 AS client_type,
  SUM(_sample_interval) AS request_count,
  COUNT(DISTINCT blob9) AS unique_sessions
FROM ${DS}
WHERE index1 = 'mcp_request'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY client_type
ORDER BY request_count DESC`;
}

/** Geographic distribution by country. */
export function queryGeoDistribution(days: string): string {
	days = safeInterval(days);
	return `SELECT
  blob6 AS country,
  SUM(_sample_interval) AS request_count,
  COUNT(DISTINCT blob9) AS unique_sessions
FROM ${DS}
WHERE index1 = 'mcp_request'
  AND blob6 != 'unknown'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY country
ORDER BY request_count DESC
LIMIT 30`;
}

/** Rate limit hit counts by type. */
export function queryRateLimitHits(days: string): string {
	days = safeInterval(days);
	return `SELECT
  blob1 AS limit_type,
  blob2 AS tool_name,
  SUM(_sample_interval) AS hit_count
FROM ${DS}
WHERE index1 = 'rate_limit'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY limit_type, tool_name
ORDER BY hit_count DESC`;
}

/** Auth tier distribution. */
export function queryTierBreakdown(days: string): string {
	days = safeInterval(days);
	return `SELECT
  blob8 AS tier,
  SUM(_sample_interval) AS request_count
FROM ${DS}
WHERE index1 = 'mcp_request'
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY tier
ORDER BY request_count DESC`;
}

/** Anomaly detection query for alerting. Returns error rate and p95 latency for the last N minutes. */
export function queryRecentAnomalies(minutes: string): string {
	minutes = safeInterval(minutes);
	return `SELECT
  SUM(_sample_interval) AS total_calls,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS error_count,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) * 100.0
    / GREATEST(SUM(_sample_interval), 1) AS error_pct,
  quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_ms
FROM ${DS}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${minutes}' MINUTE`;
}

/** Rate limit surge detection for alerting. */
export function queryRateLimitSurge(minutes: string): string {
	minutes = safeInterval(minutes);
	return `SELECT
  SUM(_sample_interval) AS total_hits
FROM ${DS}
WHERE index1 = 'rate_limit'
  AND timestamp > NOW() - INTERVAL '${minutes}' MINUTE`;
}
