// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it, vi } from 'vitest';
import { handleToolsCall } from '../src/handlers/tools';

/** Fake BV_RECON service binding: every call is recorded so a rejected input can prove it never reached it. */
function binding() {
	return {
		fetch: vi.fn(
			async () =>
				new Response(JSON.stringify({ investigationId: 'inv_ok', status: 'running' }), {
					status: 200,
					headers: { 'content-type': 'application/json' },
				}),
		),
	};
}

const HOSTILE = [
	'169.254.169.254',
	'localhost',
	'isc.org\r\nX-Evil: 1',
	'isc.org\u0000x',
	'<script>alert(1)</script>',
	"x' OR '1'='1",
	'../../etc/passwd',
	'http://169.254.169.254/',
];

type Case = { tool: string; reject: string[]; accept: string[] };

// username is the one tool whose contract charset ([A-Za-z0-9._-]{1,64}) legitimately admits a bare
// "localhost" or dotted-number token, so those are not rejection cases for it.
const USERNAME_CHARSET = /^[A-Za-z0-9._-]{1,64}$/;

const CASES: Case[] = [
	{ tool: 'osint_investigate_domain_start', reject: HOSTILE, accept: ['isc.org'] },
	{ tool: 'osint_investigate_supply_chain_start', reject: HOSTILE, accept: ['isc.org'] },
	{ tool: 'osint_investigate_infrastructure_start', reject: HOSTILE, accept: ['isc.org', '8.8.8.8', 'Acme Holdings, Inc.', 'Cloudflare'] },
	{ tool: 'osint_investigate_email_start', reject: HOSTILE, accept: ['security@blackveilsecurity.com'] },
	{ tool: 'osint_investigate_username_start', reject: HOSTILE.filter((v) => !USERNAME_CHARSET.test(v)), accept: ['blackveilsecurity'] },
];

function call(tool: string, query: string, b: ReturnType<typeof binding>) {
	return handleToolsCall({ name: tool, arguments: { query } }, undefined, {
		reconBinding: b,
		reconAuthToken: 'tok',
		authTier: 'owner',
		principalId: 'owner-a',
	});
}

describe('osint_investigate_*_start boundary validation', () => {
	for (const { tool, reject, accept } of CASES) {
		describe(tool, () => {
			it.each(reject.map((q) => [q]))('rejects %j before any bv-recon call', async (query) => {
				const b = binding();
				const result = await call(tool, query, b);
				expect(result.isError).toBe(true);
				expect(JSON.stringify(result.content)).toMatch(/Invalid query/);
				expect(b.fetch).not.toHaveBeenCalled();
			});

			it.each(accept.map((q) => [q]))('still forwards %j to bv-recon', async (query) => {
				const b = binding();
				const result = await call(tool, query, b);
				expect(result.isError).not.toBe(true);
				expect(b.fetch).toHaveBeenCalledTimes(1);
			});
		});
	}

	it('infrastructure rejects non-public IP forms and IPv6 literals', async () => {
		for (const query of ['10.0.0.1', '127.0.0.1', '192.168.1.1', '2130706433', '0x7f000001', '127.1', '::1', 'fe80::1', '2001:db8::1']) {
			const b = binding();
			const result = await call('osint_investigate_infrastructure_start', query, b);
			expect(result.isError, query).toBe(true);
			expect(b.fetch, query).not.toHaveBeenCalled();
		}
	});

	it('email rejects a missing or doubled @, a bad local part and an IP-literal domain', async () => {
		for (const query of [
			'security',
			'@isc.org',
			'a@b@isc.org',
			'a..b@isc.org',
			'.a@isc.org',
			'a b@isc.org',
			'a@169.254.169.254',
			'a@localhost',
		]) {
			const b = binding();
			const result = await call('osint_investigate_email_start', query, b);
			expect(result.isError, query).toBe(true);
			expect(b.fetch, query).not.toHaveBeenCalled();
		}
	});

	it('username rejects whitespace, control characters, markup and over-long values', async () => {
		for (const query of ['a b', 'a\nb', '<b>', "o'brien", `${'a'.repeat(65)}`]) {
			const b = binding();
			const result = await call('osint_investigate_username_start', query, b);
			expect(result.isError, query).toBe(true);
			expect(b.fetch, query).not.toHaveBeenCalled();
		}
	});

	it('rejects leading or trailing whitespace rather than forwarding it', async () => {
		const b = binding();
		const result = await call('osint_investigate_domain_start', ' isc.org ', b);
		expect(result.isError).toBe(true);
		expect(b.fetch).not.toHaveBeenCalled();
	});

	// A valid-looking target that bv-recon refuses (watchlist 403) is an ACCESS REFUSAL (isError, no
	// checkStatus 'error': that is the retryable class); a deployment with no BV_RECON binding is UNMEASURED
	// (checkStatus 'error' + verdictWithheld via the #695 chokepoint). Neither rewrites score/passed.
	describe('start that did not reach an investigation follows the unmeasured-result SSOT', () => {
		const refusing = () => ({
			fetch: vi.fn(
				async () =>
					new Response(JSON.stringify({ error: 'forbidden', code: 'target_not_authorized' }), {
						status: 403,
						headers: { 'content-type': 'application/json' },
					}),
			),
		});
		const START_CASES: Array<[string, string]> = [
			['osint_investigate_domain_start', 'isc.org'],
			['osint_investigate_infrastructure_start', 'isc.org'],
			['osint_investigate_supply_chain_start', 'isc.org'],
			['osint_investigate_email_start', 'security@blackveilsecurity.com'],
			['osint_investigate_username_start', 'blackveilsecurity'],
		];

		it.each(START_CASES)('%s: watchlist refusal is an access refusal (isError, no checkStatus)', async (tool, query) => {
			const result = await call(tool, query, refusing() as unknown as ReturnType<typeof binding>);
			expect(result.isError).toBe(true);
			const sc = result.structuredContent as Record<string, unknown>;
			expect(sc.checkStatus).toBeUndefined();
			expect(sc.verdictWithheld).toBeUndefined();
			// score/passed are NOT rewritten by this ticket's SSOT rule.
			expect(sc.passed).toBe(true);
			expect(sc.score).toBe(100);
			const findings = sc.findings as Array<{ severity: string; title: string; metadata: Record<string, unknown> }>;
			expect(findings[0].severity).toBe('info');
			expect(findings[0].title).toMatch(/could not be started/);
			expect(findings[0].metadata.targetNotAuthorized).toBe(true);
			expect(findings[0].metadata.upstreamUnavailable).toBeUndefined();
		});

		it.each(START_CASES)('%s: unprovisioned (no binding) is unmeasured via the chokepoint', async (tool, query) => {
			const result = await handleToolsCall({ name: tool, arguments: { query } }, undefined, { authTier: 'owner', principalId: 'owner-a' });
			expect(result.isError).not.toBe(true);
			const sc = result.structuredContent as Record<string, unknown>;
			expect(sc.checkStatus).toBe('error');
			expect(sc.verdictWithheld).toBe(true);
			expect(sc.passed).toBe(true);
			expect(sc.score).toBe(100);
		});
	});

	it('a >253-character query is still rejected by the schema', async () => {
		const b = binding();
		const result = await call('osint_investigate_domain_start', `${'a'.repeat(254)}.org`, b);
		expect(result.isError).toBe(true);
		expect(b.fetch).not.toHaveBeenCalled();
	});
});
