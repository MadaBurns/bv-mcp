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

// ---------------------------------------------------------------------------
// Per-Tier Analytics Queries
// ---------------------------------------------------------------------------
// All accept an optional `tier` parameter. When provided, results are filtered
// to that tier. When omitted, results are grouped by tier.

/** Sanitize tier value: lowercase, alphanumeric/underscore only, max 20 chars. */
function safeTier(value: string | undefined): string | undefined {
	if (!value) return undefined;
	const cleaned = value.trim().toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20);
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
export function queryTierToolUsage(days: string, tier?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  blob1 AS tool_name,
  SUM(_sample_interval) AS call_count,
  SUM(CASE WHEN blob2 = 'pass' THEN _sample_interval ELSE 0 END) AS pass_count,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS error_count
FROM ${DS}
WHERE index1 = 'tool_call'${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'tool_name' : 'tier, tool_name'}
ORDER BY ${tier ? 'call_count DESC' : 'tier, call_count DESC'}`;
}

/** P50/P95/P99 latency per tier. */
export function queryTierLatency(days: string, tier?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  SUM(_sample_interval) AS call_count,
  quantileExactWeighted(0.50)(double1, _sample_interval) AS p50_ms,
  quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_ms,
  quantileExactWeighted(0.99)(double1, _sample_interval) AS p99_ms
FROM ${DS}
WHERE index1 = 'tool_call'${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY${tierGroupBy(tier, 'tier')}
ORDER BY ${tier ? 'call_count DESC' : 'tier'}`;
}

/** Error rate per tier. */
export function queryTierErrorRate(days: string, tier?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  SUM(_sample_interval) AS total,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) AS errors,
  SUM(CASE WHEN blob3 = 'error' THEN _sample_interval ELSE 0 END) * 100.0
    / GREATEST(SUM(_sample_interval), 1) AS error_pct
FROM ${DS}
WHERE index1 = 'tool_call'${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY${tierGroupBy(tier, 'tier')}
HAVING total > 0
ORDER BY ${tier ? 'error_pct DESC' : 'tier'}`;
}

/** Cache hit/miss ratio per tier. */
export function queryTierCachePerformance(days: string, tier?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  blob8 AS cache_status,
  SUM(_sample_interval) AS call_count
FROM ${DS}
WHERE index1 = 'tool_call'
  AND blob8 != 'n/a'${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'cache_status' : 'tier, cache_status'}
ORDER BY ${tier ? 'call_count DESC' : 'tier, call_count DESC'}`;
}

/** Rate limit hits per tier. */
export function queryTierRateLimits(days: string, tier?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob4 AS tier,'}
  blob1 AS limit_type,
  blob2 AS tool_name,
  SUM(_sample_interval) AS hit_count
FROM ${DS}
WHERE index1 = 'rate_limit'${tierClause(tier, 'blob4')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'limit_type, tool_name' : 'tier, limit_type, tool_name'}
ORDER BY ${tier ? 'hit_count DESC' : 'tier, hit_count DESC'}`;
}

/** Session creation/termination per tier. */
export function queryTierSessions(days: string, tier?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob4 AS tier,'}
  blob1 AS action,
  SUM(_sample_interval) AS event_count
FROM ${DS}
WHERE index1 = 'session'${tierClause(tier, 'blob4')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'action' : 'tier, action'}
ORDER BY ${tier ? 'event_count DESC' : 'tier, event_count DESC'}`;
}

/** Unique domains scanned per tier. */
export function queryTierDomainDiversity(days: string, tier?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  COUNT(DISTINCT blob4) AS unique_domains,
  SUM(_sample_interval) AS total_calls
FROM ${DS}
WHERE index1 = 'tool_call'
  AND blob4 != 'none'${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY${tierGroupBy(tier, 'tier')}
ORDER BY ${tier ? 'total_calls DESC' : 'tier'}`;
}

/** Scan score distribution per tier (average, min, max). */
export function queryTierScoreDistribution(days: string, tier?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob7 AS tier,'}
  SUM(_sample_interval) AS scan_count,
  avg(double2) AS avg_score,
  min(double2) AS min_score,
  max(double2) AS max_score,
  quantileExactWeighted(0.50)(double2, _sample_interval) AS median_score
FROM ${DS}
WHERE index1 = 'tool_call'
  AND blob1 = 'scan_domain'
  AND double2 > 0${tierClause(tier, 'blob7')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY${tierGroupBy(tier, 'tier')}
ORDER BY ${tier ? 'scan_count DESC' : 'tier'}`;
}

/** Daily request volume trended over time, per tier. */
export function queryTierDailyTrend(days: string, tier?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT
  toStartOfDay(timestamp) AS day,${tier ? '' : '\n  blob8 AS tier,'}
  SUM(_sample_interval) AS request_count,
  COUNT(DISTINCT blob9) AS unique_sessions
FROM ${DS}
WHERE index1 = 'mcp_request'${tierClause(tier, 'blob8')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'day' : 'day, tier'}
ORDER BY day DESC${tier ? '' : ', tier'}`;
}

/** MCP client type distribution per tier. */
export function queryTierClientTypes(days: string, tier?: string): string {
	days = safeInterval(days);
	tier = safeTier(tier);
	return `SELECT${tier ? '' : '\n  blob8 AS tier,'}
  blob7 AS client_type,
  SUM(_sample_interval) AS request_count,
  COUNT(DISTINCT blob9) AS unique_sessions
FROM ${DS}
WHERE index1 = 'mcp_request'${tierClause(tier, 'blob8')}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY ${tier ? 'client_type' : 'tier, client_type'}
ORDER BY ${tier ? 'request_count DESC' : 'tier, request_count DESC'}`;
}

/** Per-API-key usage breakdown. Requires keyHash blob (blob9 in tool_call). */
export function queryKeyUsage(days: string, keyHash?: string): string {
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
FROM ${DS}
WHERE index1 = 'tool_call'${keyFilter}
  AND timestamp > NOW() - INTERVAL '${days}' DAY
GROUP BY key_hash, tier
ORDER BY call_count DESC
LIMIT 50`;
}

/** Daily tier usage digest — all tiers in one query, aggregated for the past N hours. */
export function queryTierDigest(hours: string): string {
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
FROM ${DS}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${hours}' HOUR
GROUP BY tier
ORDER BY total_calls DESC`;
}

/** Top tools per tier for digest. */
export function queryTierTopTools(hours: string): string {
	hours = safeInterval(hours);
	return `SELECT
  blob7 AS tier,
  blob1 AS tool_name,
  SUM(_sample_interval) AS call_count
FROM ${DS}
WHERE index1 = 'tool_call'
  AND timestamp > NOW() - INTERVAL '${hours}' HOUR
GROUP BY tier, tool_name
ORDER BY tier, call_count DESC`;
}
