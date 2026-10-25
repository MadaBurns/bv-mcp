// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it, vi } from 'vitest';
import { handleToolsCall } from '../src/handlers/tools';

/** Fake BV_RECON service binding: every call is recorded so a rejected input can prove it never reached it. */
function binding() {
	return {
		fetch: vi.fn(
			async () =>
				new Response(JSON.stringify({ scanId: 'scan_ok', status: 'running' }), {
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
	' isc.org',
	'isc.org ',
];

function start(target: string, b: ReturnType<typeof binding>) {
	return handleToolsCall({ name: 'scan_buckets_start', arguments: { target } }, undefined, {
		reconBinding: b,
		reconAuthToken: 'tok',
		principalId: 'owner-a',
	});
}

describe('scan_buckets_start boundary validation', () => {
	it.each(HOSTILE.map((t) => [t]))('rejects %j before any bv-recon call', async (target) => {
		const b = binding();
		const result = await start(target, b);
		expect(result.isError).toBe(true);
		expect(JSON.stringify(result.content)).toMatch(/Invalid target/);
		expect(b.fetch).not.toHaveBeenCalled();
	});

	it('still forwards a valid domain to bv-recon', async () => {
		const b = binding();
		const result = await start('isc.org', b);
		expect(result.isError).not.toBe(true);
		expect(b.fetch).toHaveBeenCalledTimes(1);
	});

	// The watchlist refuses the target (403) or no BV_RECON binding exists: the scan never started, so the
	// result abstains (checkStatus 'error', no score 100 / passed true) and stays a normal non-error result.
	it('watchlist refusal carries the abstention shape and stays a non-error result', async () => {
		const refusing = {
			fetch: vi.fn(
				async () =>
					new Response(JSON.stringify({ error: 'forbidden', code: 'target_not_authorized' }), {
						status: 403,
						headers: { 'content-type': 'application/json' },
					}),
			),
		};
		const result = await start('isc.org', refusing as unknown as ReturnType<typeof binding>);
		expect(result.isError).not.toBe(true);
		const sc = result.structuredContent as Record<string, unknown>;
		expect(sc.checkStatus).toBe('error');
		expect(sc.passed).toBe(false);
		expect(sc.score).not.toBe(100);
		expect(sc.score).toBe(0);
		expect((sc.findings as Array<{ severity: string }>)[0].severity).toBe('info');
	});

	it('unprovisioned (no binding) carries the abstention shape', async () => {
		const result = await handleToolsCall({ name: 'scan_buckets_start', arguments: { target: 'isc.org' } }, undefined, {
			principalId: 'owner-a',
		});
		expect(result.isError).not.toBe(true);
		const sc = result.structuredContent as Record<string, unknown>;
		expect(sc.checkStatus).toBe('error');
		expect(sc.passed).toBe(false);
		expect(sc.score).toBe(0);
	});

	it('a >253-character target is still rejected by the schema', async () => {
		const b = binding();
		const result = await start(`${'a'.repeat(254)}.org`, b);
		expect(result.isError).toBe(true);
		expect(b.fetch).not.toHaveBeenCalled();
	});
});
