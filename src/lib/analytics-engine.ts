// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared Analytics Engine SQL API client.
 *
 * Used by scheduled alerting and internal analytics endpoints
 * to query the Cloudflare Analytics Engine SQL API.
 */

import { readJsonResponseCapped, readTextResponseCapped } from './response-body';

export interface AnalyticsRow {
	[key: string]: string | number | undefined;
}

const ANALYTICS_ERROR_BODY_MAX_BYTES = 4 * 1024;
const ANALYTICS_RESULT_MAX_BODY_BYTES = 2 * 1024 * 1024;

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
		// The AE SQL API explains a rejection ONLY in the response body — the status
		// line is bare. Throwing the status alone made a permanently-broken alerting
		// pipeline undiagnosable: the operator alert said "analytics check could not
		// run" while the actual cause ("unknown function call: GREATEST") sat in a
		// body this client had discarded. Read it, normalise the whitespace so it
		// survives a one-line alert payload, and bound it so a pathological body
		// can't blow up the webhook. Never let this read fail the throw.
		let detail = '';
		try {
			detail = ((await readTextResponseCapped(response, ANALYTICS_ERROR_BODY_MAX_BYTES)) ?? '')
				.replace(/\s+/g, ' ')
				.trim()
				.slice(0, 300);
		} catch {
			// body already consumed/unreadable — fall through to the bare status
		}
		throw new Error(`Analytics Engine query failed: ${response.status}${detail ? ` — ${detail}` : ''}`);
	}

	const result = await readJsonResponseCapped<{ data?: AnalyticsRow[] }>(response, ANALYTICS_RESULT_MAX_BODY_BYTES);
	if (result === null) throw new Error('Analytics Engine query returned an invalid or oversized response');
	return result.data ?? [];
}
