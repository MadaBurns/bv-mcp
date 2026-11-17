// SPDX-License-Identifier: BUSL-1.1

/**
 * Daily abuse watch — the two alert-only signals (a watched declared client name,
 * and anonymous paid-tool refusals from one country), their configuration, and
 * their isolation from each other.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

const WEBHOOK = 'https://hooks.example.test/alert';
const ENV = { CF_ACCOUNT_ID: 'acct', CF_ANALYTICS_TOKEN: 'tok', ABUSE_WATCH_CLIENT_FRAGMENTS: 'alphaclient,betasync' };

interface FetchCall {
	url: string;
	body: string;
}

/** Route the AE SQL API by a marker in the SQL, and capture webhook posts. */
function stubFetch(routes: { watched: unknown; refusals: unknown }): { calls: FetchCall[]; webhookBodies: string[] } {
	const calls: FetchCall[] = [];
	const webhookBodies: string[] = [];
	vi.stubGlobal(
		'fetch',
		vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			const body = typeof init?.body === 'string' ? init.body : '';
			calls.push({ url, body });
			if (url.includes('/analytics_engine/sql')) {
				const route = body.includes("index1 = 'session'") ? routes.watched : routes.refusals;
				if (route instanceof Error) return new Response('boom', { status: 422 });
				return new Response(JSON.stringify({ data: route }), { status: 200, headers: { 'content-type': 'application/json' } });
			}
			webhookBodies.push(body);
			return new Response('ok', { status: 200 });
		}),
	);
	return { calls, webhookBodies };
}

const sqlCalls = (calls: FetchCall[]) => calls.filter((call) => call.url.includes('/analytics_engine/sql'));

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe('parseWatchedFragments', () => {
	it('is empty when unset or blank', async () => {
		const { parseWatchedFragments } = await import('../src/lib/abuse-watch');
		expect(parseWatchedFragments(undefined)).toEqual([]);
		expect(parseWatchedFragments(' , ,')).toEqual([]);
	});

	it('trims, lowercases and de-duplicates', async () => {
		const { parseWatchedFragments } = await import('../src/lib/abuse-watch');
		expect(parseWatchedFragments(' AlphaClient, betasync ,alphaclient')).toEqual(['alphaclient', 'betasync']);
	});

	it('drops anything that could act as a LIKE wildcard or break out of the string', async () => {
		const { parseWatchedFragments } = await import('../src/lib/abuse-watch');
		expect(parseWatchedFragments("ok1,a_b,%,x' OR '1'='1,with space")).toEqual(['ok1']);
	});

	it('caps the list length', async () => {
		const { parseWatchedFragments } = await import('../src/lib/abuse-watch');
		const many = Array.from({ length: 30 }, (_, i) => `name${i}`).join(',');
		expect(parseWatchedFragments(many)).toHaveLength(10);
	});
});

describe('resolveGatedRefusalThreshold', () => {
	it('uses the default for a missing, non-numeric or non-positive value', async () => {
		const { resolveGatedRefusalThreshold, DEFAULT_GATED_REFUSAL_THRESHOLD } = await import('../src/lib/abuse-watch');
		for (const raw of [undefined, '', 'abc', '0', '-5']) {
			expect(resolveGatedRefusalThreshold(raw), String(raw)).toBe(DEFAULT_GATED_REFUSAL_THRESHOLD);
		}
	});

	it('accepts a positive integer override', async () => {
		const { resolveGatedRefusalThreshold } = await import('../src/lib/abuse-watch');
		expect(resolveGatedRefusalThreshold('12')).toBe(12);
	});
});

describe('assessWatchedClients', () => {
	it('returns null when no watched client was seen', async () => {
		const { assessWatchedClients } = await import('../src/lib/abuse-watch');
		expect(assessWatchedClients([])).toBeNull();
		expect(assessWatchedClients([{ client: 'alphaclient', sessions: 0 }])).toBeNull();
		expect(assessWatchedClients([{ sessions: 4 }])).toBeNull();
	});

	it('names every watched client with its country, tier and session count', async () => {
		const { assessWatchedClients } = await import('../src/lib/abuse-watch');
		const alert = assessWatchedClients([
			{ client: 'alphaclient', country: 'AA', tier: 'anon', sessions: '3' },
			{ client: 'betasync-worker', country: 'BB', tier: 'free', sessions: 2 },
		]);
		expect(alert).not.toBeNull();
		expect(alert?.severity).toBe('warning');
		expect(alert?.title).toContain('5 session(s)');
		expect(alert?.metrics.sessions).toBe(5);
		expect(alert?.metrics.clients).toBe('alphaclient (AA, anon) x3 · betasync-worker (BB, free) x2');
	});
});

describe('assessGatedRefusals', () => {
	it('stays quiet below the threshold', async () => {
		const { assessGatedRefusals } = await import('../src/lib/abuse-watch');
		expect(assessGatedRefusals([{ country: 'AA', refusals: 9, tools: 3 }], 10)).toEqual([]);
	});

	it('alerts at the threshold and only for the countries over it', async () => {
		const { assessGatedRefusals } = await import('../src/lib/abuse-watch');
		const alerts = assessGatedRefusals(
			[
				{ country: 'AA', refusals: '10', tools: '2' },
				{ country: 'BB', refusals: 4, tools: 1 },
			],
			10,
		);
		expect(alerts).toHaveLength(1);
		expect(alerts[0].severity).toBe('warning');
		expect(alerts[0].metrics).toEqual({ country: 'AA', refusals: 10, distinct_tools: 2 });
	});

	it('escalates to critical at three times the threshold', async () => {
		const { assessGatedRefusals } = await import('../src/lib/abuse-watch');
		const [alert] = assessGatedRefusals([{ country: 'AA', refusals: 30, tools: 2 }], 10);
		expect(alert.severity).toBe('critical');
	});

	it('uses the in-code default when no threshold is passed', async () => {
		const { assessGatedRefusals, DEFAULT_GATED_REFUSAL_THRESHOLD } = await import('../src/lib/abuse-watch');
		expect(assessGatedRefusals([{ country: 'AA', refusals: DEFAULT_GATED_REFUSAL_THRESHOLD - 1 }])).toEqual([]);
		expect(assessGatedRefusals([{ country: 'AA', refusals: DEFAULT_GATED_REFUSAL_THRESHOLD }])).toHaveLength(1);
	});
});

describe('runAbuseWatch', () => {
	it('sends nothing on a quiet day but still runs both queries', async () => {
		const { runAbuseWatch } = await import('../src/lib/abuse-watch');
		const { calls, webhookBodies } = stubFetch({ watched: [], refusals: [{ country: 'BB', refusals: 3, tools: 1 }] });
		await runAbuseWatch(ENV, WEBHOOK, 'bv_dns_security_mcp', {});
		expect(sqlCalls(calls)).toHaveLength(2);
		expect(webhookBodies).toEqual([]);
	});

	it('sends one alert per signal that fired', async () => {
		const { runAbuseWatch } = await import('../src/lib/abuse-watch');
		const { webhookBodies } = stubFetch({
			watched: [{ client: 'alphaclient', country: 'AA', tier: 'anon', sessions: 2 }],
			refusals: [{ country: 'AA', refusals: 71, tools: 2 }],
		});
		await runAbuseWatch(ENV, WEBHOOK, 'bv_dns_security_mcp', {});
		expect(webhookBodies).toHaveLength(2);
		expect(webhookBodies[0]).toContain('Watched MCP client name declared');
		expect(webhookBodies[1]).toContain('refused paid tools 71 times from AA');
	});

	it('skips the watched-client query entirely when no watch list is configured', async () => {
		const { runAbuseWatch } = await import('../src/lib/abuse-watch');
		const { calls, webhookBodies } = stubFetch({
			watched: [{ client: 'alphaclient', country: 'AA', tier: 'anon', sessions: 2 }],
			refusals: [],
		});
		await runAbuseWatch({ CF_ACCOUNT_ID: 'acct', CF_ANALYTICS_TOKEN: 'tok' }, WEBHOOK, 'bv_dns_security_mcp', {});
		expect(sqlCalls(calls)).toHaveLength(1);
		expect(sqlCalls(calls)[0].body).toContain("index1 = 'rate_limit'");
		expect(webhookBodies).toEqual([]);
	});

	it('honours the configured refusal threshold', async () => {
		const { runAbuseWatch } = await import('../src/lib/abuse-watch');
		const { webhookBodies } = stubFetch({ watched: [], refusals: [{ country: 'AA', refusals: 12, tools: 2 }] });
		await runAbuseWatch({ ...ENV, ABUSE_WATCH_GATED_REFUSAL_THRESHOLD: '10' }, WEBHOOK, 'bv_dns_security_mcp', {});
		expect(webhookBodies).toHaveLength(1);
	});

	it('a failed watched-client query does not stop the refusal signal, and never throws', async () => {
		const { runAbuseWatch } = await import('../src/lib/abuse-watch');
		const { webhookBodies } = stubFetch({ watched: new Error('422'), refusals: [{ country: 'AA', refusals: 71, tools: 2 }] });
		await expect(runAbuseWatch(ENV, WEBHOOK, 'bv_dns_security_mcp', {})).resolves.toBeUndefined();
		expect(webhookBodies).toHaveLength(1);
		expect(webhookBodies[0]).toContain('refused paid tools');
	});

	it('does nothing without analytics credentials', async () => {
		const { runAbuseWatch } = await import('../src/lib/abuse-watch');
		const { calls } = stubFetch({ watched: [], refusals: [] });
		await runAbuseWatch({ ABUSE_WATCH_CLIENT_FRAGMENTS: 'alphaclient' }, WEBHOOK, 'bv_dns_security_mcp', {});
		expect(calls).toEqual([]);
	});
});

describe('abuse-watch query builders', () => {
	it('watched-client query filters created sessions on the declared-name blob', async () => {
		const { queryWatchedClientSessions } = await import('../src/lib/analytics-queries');
		const sql = queryWatchedClientSessions('24', ['alphaclient', 'betasync']);
		expect(sql).toContain("index1 = 'session'");
		expect(sql).toContain("blob1 = 'created'");
		expect(sql).toContain("(blob7 LIKE '%alphaclient%' OR blob7 LIKE '%betasync%')");
		expect(sql).toContain("INTERVAL '24' HOUR");
		expect(sql).toContain('FROM bv_dns_security_mcp');
	});

	it('drops any fragment that could act as a LIKE wildcard or break out of the string', async () => {
		const { queryWatchedClientSessions } = await import('../src/lib/analytics-queries');
		const sql = queryWatchedClientSessions('24', ['alphaclient', "x' OR '1'='1", 'a_b', 'A%', '']);
		expect(sql).toContain("(blob7 LIKE '%alphaclient%')");
		expect(sql).not.toContain("'1'='1");
		expect(sql).not.toContain('a_b');
	});

	it('matches nothing when no fragment survives validation', async () => {
		const { queryWatchedClientSessions } = await import('../src/lib/analytics-queries');
		expect(queryWatchedClientSessions('24', ['%'])).toContain('(1 = 0)');
		expect(queryWatchedClientSessions('24', [])).toContain('(1 = 0)');
	});

	it('refusal query counts anonymous gated-tool refusals by country', async () => {
		const { queryAnonGatedRefusalsByCountry } = await import('../src/lib/analytics-queries');
		const sql = queryAnonGatedRefusalsByCountry('24', 'custom_ds');
		expect(sql).toContain("index1 = 'rate_limit'");
		expect(sql).toContain("blob1 = 'gated_tool'");
		expect(sql).toContain("blob4 = 'anon'");
		expect(sql).toContain('GROUP BY country');
		expect(sql).toContain('FROM custom_ds');
	});

	it('sanitises a hostile interval', async () => {
		const { queryAnonGatedRefusalsByCountry } = await import('../src/lib/analytics-queries');
		expect(queryAnonGatedRefusalsByCountry("1' OR 1=1 --")).toContain("INTERVAL '1' HOUR");
	});
});
