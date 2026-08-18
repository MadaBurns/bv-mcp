// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi, afterEach } from 'vitest';

import type { BindingDegradationSink, ReconBinding, ReconFailureReason, ReconOutcome } from '../src/lib/recon-binding';

afterEach(() => vi.restoreAllMocks());

function binding(body: unknown, status = 200) {
	// Params are declared (rather than a bare `async () =>`) so `fetch.mock.calls[0]`
	// types as a 2-tuple instead of `[]` — otherwise every URL/init assertion below
	// is a typecheck error against test/tsconfig.json.
	return {
		fetch: vi.fn(
			async (_input: RequestInfo | URL, _init?: RequestInit) =>
				new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
		),
	};
}

/** A binding whose fetch throws — `name` selects the BindingDegradationKind mapping. */
function throwingBinding(errorName?: string) {
	return {
		fetch: vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
			const e = new Error('connection refused');
			if (errorName) e.name = errorName;
			throw e;
		}),
	};
}

/** Narrow an outcome to its payload, failing loudly (with the reason) when it is not ok. */
function dataOf<T>(outcome: ReconOutcome<T>): T {
	if (!outcome.ok) throw new Error(`expected an ok outcome, got reason=${outcome.reason}`);
	return outcome.data;
}

/**
 * Every async (ReconOutcome-returning) entry point, invoked with a caller-supplied
 * binding + telemetry sink. Used by the sweeps below so a discriminant is proven on
 * ALL six functions rather than on one lucky representative.
 */
async function asyncCalls(): Promise<
	{ name: string; invoke: (b: ReconBinding | undefined, sink: BindingDegradationSink) => Promise<ReconOutcome<unknown>> }[]
> {
	const m = await import('../src/lib/recon-binding');
	return [
		{
			name: 'callReconInvestigateStart',
			invoke: (b, sink) => m.callReconInvestigateStart(b, 'tok', 'domain', 'example.com', undefined, undefined, sink),
		},
		{ name: 'callReconInvestigationStatus', invoke: (b, sink) => m.callReconInvestigationStatus(b, 'tok', 'inv_1', undefined, sink) },
		{ name: 'callReconInvestigationReport', invoke: (b, sink) => m.callReconInvestigationReport(b, 'tok', 'inv_1', undefined, sink) },
		{
			name: 'callReconBucketScanStart',
			invoke: (b, sink) => m.callReconBucketScanStart(b, 'tok', { target: 'example.com' }, undefined, sink),
		},
		{ name: 'callReconBucketScanStatus', invoke: (b, sink) => m.callReconBucketScanStatus(b, 'tok', 'scan_1', undefined, sink) },
		{ name: 'callReconBucketFindings', invoke: (b, sink) => m.callReconBucketFindings(b, 'tok', 'scan_1', undefined, sink) },
	];
}

describe('recon async proxies', () => {
	it('callReconInvestigateStart reports `unbound` when the binding is absent', async () => {
		const { callReconInvestigateStart } = await import('../src/lib/recon-binding');
		expect(await callReconInvestigateStart(undefined, 't', 'domain', 'example.com')).toEqual({ ok: false, reason: 'unbound' });
	});
	it('callReconInvestigateStart POSTs the type path with bearer + body and parses id', async () => {
		const { callReconInvestigateStart } = await import('../src/lib/recon-binding');
		const b = binding({ investigationId: 'inv_1', workflowId: 'wf_1', status: 'running', pollUrl: '/api/investigation/inv_1' });
		const out = await callReconInvestigateStart(b, 'tok', 'deep_infrastructure', 'example.com');
		const [url, init] = b.fetch.mock.calls[0];
		expect(String(url)).toContain('/osint/api/investigate/deep_infrastructure');
		expect((init as RequestInit).method).toBe('POST');
		expect((init as RequestInit).headers).toMatchObject({ Authorization: 'Bearer tok' });
		expect(out.ok).toBe(true);
		expect(dataOf(out).investigationId).toBe('inv_1');
	});
	it('callReconInvestigationStatus GETs by id and reports `not_found` on 404', async () => {
		const { callReconInvestigationStatus } = await import('../src/lib/recon-binding');
		const b = binding({ error: 'x' }, 404);
		const out = await callReconInvestigationStatus(b, 'tok', 'inv_1');
		expect(String(b.fetch.mock.calls[0][0])).toContain('/osint/api/investigation/inv_1');
		expect(out).toEqual({ ok: false, reason: 'not_found', status: 404 });
	});
	it('callReconBucketScanStart POSTs trigger and parses scanId', async () => {
		const { callReconBucketScanStart } = await import('../src/lib/recon-binding');
		const b = binding({ scanId: 'scan_1', status: 'running' });
		const out = await callReconBucketScanStart(b, 'tok', { target: 'example.com' });
		expect(String(b.fetch.mock.calls[0][0])).toContain('/buckets/api/scan/trigger');
		expect(dataOf(out).scanId).toBe('scan_1');
	});
	it('callReconBucketScanStatus reports `upstream_status` (with the status) on 500', async () => {
		const { callReconBucketScanStatus } = await import('../src/lib/recon-binding');
		expect(await callReconBucketScanStatus(binding({}, 500), 'tok', 'scan_1')).toEqual({
			ok: false,
			reason: 'upstream_status',
			status: 500,
		});
	});
});

// ---------------------------------------------------------------------------
// The behavior change that motivated the discriminated ReconOutcome (#695):
// a 404 on an async recon call is a DATA MISS (unknown/expired investigation or
// scan id, or a poll racing its own *_start), not a binding failure. It used to
// fall into `!resp.ok` and record `binding_5xx`, so every poll of an unknown id
// fired a FALSE operator degradation alert.
//
// This is not a new contract, only a newly-honored one: the doc comment on
// `BindingDegradationKind` in src/lib/binding-degradation.ts already states the
// kind set "deliberately excludes ... the benign recon 404" — until now only
// `callReconScan` (the sync path) actually honored it.
// ---------------------------------------------------------------------------
describe('recon async 404 is a silent data miss, not a degradation', () => {
	it('returns not_found AND does NOT invoke the degradation sink or log a degradation', async () => {
		const { callReconInvestigationStatus } = await import('../src/lib/recon-binding');
		const sink = vi.fn();
		const warn = vi.spyOn(console, 'log').mockImplementation(() => {});
		const out = await callReconInvestigationStatus(binding({ error: 'unknown id' }, 404), 'tok', 'expired_inv', undefined, sink);
		expect(out).toEqual({ ok: false, reason: 'not_found', status: 404 });
		expect(sink).not.toHaveBeenCalled();
		expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).not.toContain('binding_degradation');
	});

	it('holds for ALL six async entry points', async () => {
		const sink = vi.fn();
		const warn = vi.spyOn(console, 'log').mockImplementation(() => {});
		for (const { name, invoke } of await asyncCalls()) {
			const out = await invoke(binding({ error: 'not found' }, 404), sink);
			expect(out, name).toEqual({ ok: false, reason: 'not_found', status: 404 });
		}
		expect(sink).not.toHaveBeenCalled();
		expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).not.toContain('binding_degradation');
	});
});

describe('ReconOutcome failure discriminants', () => {
	it('unbound: absent binding is silent on ALL six entry points (BSL self-host, expected)', async () => {
		const sink = vi.fn();
		const warn = vi.spyOn(console, 'log').mockImplementation(() => {});
		for (const { name, invoke } of await asyncCalls()) {
			expect(await invoke(undefined, sink), name).toEqual({ ok: false, reason: 'unbound' });
		}
		expect(sink).not.toHaveBeenCalled();
		expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).not.toContain('binding_degradation');
	});

	it('unauthorized: 401 records a degradation and carries the status', async () => {
		const { callReconInvestigationReport } = await import('../src/lib/recon-binding');
		const sink = vi.fn();
		const warn = vi.spyOn(console, 'log').mockImplementation(() => {});
		const out = await callReconInvestigationReport(binding({ error: 'no' }, 401), 'bad-tok', 'inv_1', undefined, sink);
		expect(out).toEqual({ ok: false, reason: 'unauthorized', status: 401 });
		expect(sink).toHaveBeenCalledWith(expect.objectContaining({ degradationType: 'binding_5xx', component: 'recon' }));
		expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).toContain('binding_degradation');
	});

	it('unauthorized: 403 is the same discriminant as 401', async () => {
		const { callReconBucketFindings } = await import('../src/lib/recon-binding');
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const out = await callReconBucketFindings(binding({ error: 'forbidden' }, 403), 'bad-tok', 'scan_1', undefined, sink);
		expect(out).toEqual({ ok: false, reason: 'unauthorized', status: 403 });
		expect(sink).toHaveBeenCalledWith(expect.objectContaining({ degradationType: 'binding_5xx', component: 'recon' }));
	});

	it('upstream_status: a 502 records a degradation and carries the status', async () => {
		const { callReconInvestigateStart } = await import('../src/lib/recon-binding');
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const out = await callReconInvestigateStart(binding({ error: 'boom' }, 502), 'tok', 'username', 'someone', undefined, undefined, sink);
		expect(out).toEqual({ ok: false, reason: 'upstream_status', status: 502 });
		expect(sink).toHaveBeenCalledWith(expect.objectContaining({ degradationType: 'binding_5xx', component: 'recon' }));
	});

	it('malformed: a 200 whose body fails the schema is contract drift, NOT a degradation', async () => {
		const { callReconInvestigateStart } = await import('../src/lib/recon-binding');
		const sink = vi.fn();
		const warn = vi.spyOn(console, 'log').mockImplementation(() => {});
		// InvestigationStartSchema requires `investigationId`.
		const out = await callReconInvestigateStart(binding({ status: 'running' }), 'tok', 'domain', 'example.com', undefined, undefined, sink);
		expect(out).toEqual({ ok: false, reason: 'malformed', status: 200 });
		// The upstream answered fine — this is neither an outage nor an auth failure,
		// so recordReconDegradation is deliberately NOT called on this branch.
		expect(sink).not.toHaveBeenCalled();
		expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).not.toContain('binding_degradation');
	});

	it('malformed: a 200 scalar body fails the opaque-object schema (rejects non-objects)', async () => {
		const { callReconBucketScanStatus } = await import('../src/lib/recon-binding');
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const out = await callReconBucketScanStatus(binding('not-an-object'), 'tok', 'scan_1', undefined, sink);
		expect(out).toEqual({ ok: false, reason: 'malformed', status: 200 });
		expect(sink).not.toHaveBeenCalled();
	});

	it('transport: a thrown fetch reports transport (no status) + binding_unavailable', async () => {
		const { callReconInvestigationStatus } = await import('../src/lib/recon-binding');
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const out = await callReconInvestigationStatus(throwingBinding(), 'tok', 'inv_1', undefined, sink);
		expect(out).toEqual({ ok: false, reason: 'transport' });
		expect(out).not.toHaveProperty('status');
		expect(sink).toHaveBeenCalledWith(expect.objectContaining({ degradationType: 'binding_unavailable', component: 'recon' }));
	});

	it('transport: a TimeoutError maps to binding_timeout but the same discriminant', async () => {
		const { callReconBucketScanStart } = await import('../src/lib/recon-binding');
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const out = await callReconBucketScanStart(throwingBinding('TimeoutError'), 'tok', { target: 'x.com' }, undefined, sink);
		expect(out).toEqual({ ok: false, reason: 'transport' });
		expect(sink).toHaveBeenCalledWith(expect.objectContaining({ degradationType: 'binding_timeout', component: 'recon' }));
	});

	it('malformed: a 200 with a non-JSON body is contract drift, NOT an outage', async () => {
		// A 2xx whose body is not even JSON (HTML error page, truncated response) must be
		// `malformed` and SILENT. `reconJson` guards `resp.json()` with `.catch(() => null)`,
		// matching `callReconScan`; without that guard the parse throw escapes to the outer
		// catch and is reported as `transport` WITH a `binding_unavailable` degradation — a
		// false operator alert, the same defect class as the benign 404 (see above).
		const { callReconInvestigationStatus } = await import('../src/lib/recon-binding');
		const sink = vi.fn();
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const b = { fetch: vi.fn(async () => new Response('<html>not json</html>', { status: 200 })) };
		const out = await callReconInvestigationStatus(b, 'tok', 'inv_1', undefined, sink);
		expect(out).toEqual({ ok: false, reason: 'malformed', status: 200 });
		expect(sink).not.toHaveBeenCalled();
	});

	it('a thrown sink never breaks the fail-soft contract on the async path', async () => {
		const { callReconInvestigationStatus } = await import('../src/lib/recon-binding');
		vi.spyOn(console, 'log').mockImplementation(() => {});
		const sink = vi.fn(() => {
			throw new Error('sink boom');
		});
		expect(await callReconInvestigationStatus(binding({}, 500), 'tok', 'inv_1', undefined, sink)).toEqual({
			ok: false,
			reason: 'upstream_status',
			status: 500,
		});
	});
});

describe('isRetryableReconFailure', () => {
	it('is true only for the transient reasons (upstream_status, transport, not_found)', async () => {
		const { isRetryableReconFailure } = await import('../src/lib/recon-binding');
		const expected: Record<ReconFailureReason, boolean> = {
			unbound: false,
			not_found: true,
			unauthorized: false,
			upstream_status: true,
			malformed: false,
			transport: true,
		};
		for (const [reason, want] of Object.entries(expected) as [ReconFailureReason, boolean][]) {
			expect(isRetryableReconFailure(reason), reason).toBe(want);
		}
	});
});
