// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared Analytics Engine SQL API client.
 *
 * Used by scheduled alerting and internal analytics endpoints
 * to query the Cloudflare Analytics Engine SQL API.
 */

export interface AnalyticsRow {
	[key: string]: string | number | undefined;
}

/**
 * Execute a SQL query against the Cloudflare Analytics Engine SQL API.
 */
export async function queryAnalyticsEngine(accountId: string, token: string, sql: string): Promise<AnalyticsRow[]> {
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/analytics_engine/sql`;
	const response = await fetch(url, {
		method: 'POST',
		headers: { Authorization: `Bearer ${token}` },
		body: sql,
		signal: AbortSignal.timeout(5_000),
		redirect: 'manual',
	});

	if (!response.ok) {
		throw new Error(`Analytics Engine query failed: ${response.status}`);
	}

	const result = (await response.json()) as { data?: AnalyticsRow[] };
	return result.data ?? [];
}
