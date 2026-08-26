// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #725 — the post-deploy verifier must assert the CONTROL PREDICATE, not just HTTP 200.
 *
 * #705/#706 replaced `check.passed` with `isSatisfiedControl()` in `map_compliance` and
 * `compare_baseline`. The fix merged, the issue auto-closed, and prod kept serving the
 * pre-fix false affirmative: `compare_baseline` with `require_caa: true` returned PASS for
 * a domain with no CAA record. A merge-closes-issue workflow cannot catch a deploy that
 * never ran, so `scripts/ci/verify-deploy.mjs` now fails closed on that exact case.
 *
 * These are the gate's own guard-rails. Two properties matter more than any single case:
 *
 *   1. FAIL CLOSED on a stale build — a verified-absent control that yields no violation
 *      must fail the verifier, or the gate is decorative.
 *   2. NEVER FAIL a correct build — a transient DNS/transport failure, or a probe domain
 *      that has since published CAA, must degrade to a loud skip. A flaky gate gets
 *      disabled, which is strictly worse than no gate.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { classifyControlProbe, classifyBaselineVerdict, runControlPredicateSmoke } from '../scripts/ci/verify-deploy.mjs';

const realFetch = globalThis.fetch;
afterEach(() => {
	globalThis.fetch = realFetch;
	vi.restoreAllMocks();
});

describe('classifyControlProbe — only an UNREBUTTED, MEASURED absence licenses the assertion', () => {
	it('recordPresent:false with no affirmative controlPresent is a definitive absence', () => {
		expect(classifyControlProbe({ category: 'caa', recordPresent: false, controlPresent: false }).state).toBe('absent');
		// controlPresent omitted entirely (undefined) still counts — only `true` rebuts.
		expect(classifyControlProbe({ category: 'caa', recordPresent: false }).state).toBe('absent');
	});

	it('an affirmative controlPresent REBUTS absence for split-signal or legacy results', () => {
		// Current DNSSEC results require AD + DNSKEY + DS, but the generic verifier also
		// accepts persisted/external results with independent affirmative evidence.
		expect(classifyControlProbe({ recordPresent: false, controlPresent: true }).state).toBe('present');
	});

	it('a published record means the probe domain is no longer usable — skip, do not assert', () => {
		expect(classifyControlProbe({ recordPresent: true, controlPresent: true }).state).toBe('present');
	});

	it('an errored or timed-out check measured nothing and is never read as a verdict', () => {
		expect(classifyControlProbe({ checkStatus: 'error', recordPresent: false }).state).toBe('unmeasured');
		expect(classifyControlProbe({ checkStatus: 'timeout', recordPresent: false }).state).toBe('unmeasured');
	});

	it('an unreported recordPresent is not evidence of absence', () => {
		expect(classifyControlProbe({ category: 'caa' }).state).toBe('unmeasured');
		expect(classifyControlProbe(undefined).state).toBe('unmeasured');
	});

	it('checkStatus "completed" is accepted alongside the omitted form buildCheckResult emits', () => {
		expect(classifyControlProbe({ checkStatus: 'completed', recordPresent: false }).state).toBe('absent');
	});
});

describe('classifyBaselineVerdict — a verified-absent control that does not violate is a STALE deploy', () => {
	it('the rule appearing in violations is the pass condition', () => {
		const verdict = classifyBaselineVerdict({
			passed: false,
			violations: [{ rule: 'require_caa', message: 'CAA is required…', expected: true, actual: false }],
			inconclusiveRules: [],
		});
		expect(verdict.state).toBe('violated');
	});

	it('passed:true is the #706 false affirmative → stale', () => {
		const verdict = classifyBaselineVerdict({ passed: true, violations: [], inconclusiveRules: [] });
		expect(verdict.state).toBe('stale');
		expect(verdict.reason).toMatch(/#706/);
	});

	it('a FAIL driven by some OTHER rule is still stale — the probed rule was evaluated and passed', () => {
		// The exact live 2026-08-20 shape: ten rules checked, the sole violation was
		// max_high_findings, and require_caa passed on a domain with no CAA.
		const verdict = classifyBaselineVerdict({
			passed: false,
			violations: [{ rule: 'max_high_findings', message: 'too many', expected: 0, actual: 3 }],
			inconclusiveRules: [],
		});
		expect(verdict.state).toBe('stale');
	});

	it('an unevaluatable rule is indeterminate, never stale', () => {
		expect(classifyBaselineVerdict({ passed: null, violations: [], inconclusiveRules: ['require_caa'] }).state).toBe('indeterminate');
		// `passed: null` alone (the poisoned-verdict channel) is enough.
		expect(classifyBaselineVerdict({ passed: null, violations: [], inconclusiveRules: [] }).state).toBe('indeterminate');
	});

	it('no structured payload is indeterminate, never stale', () => {
		expect(classifyBaselineVerdict(undefined).state).toBe('indeterminate');
	});

	it('asserts on the rule key only — never on the reason prose', () => {
		// `unsatisfiedReason` picks between an "absent" and a "present-but-deficient"
		// wording; a medium-severity CAA-absence finding legitimately routes to the
		// latter. A gate pinned to prose would fail on a correct deploy.
		const deficient = classifyBaselineVerdict({
			passed: false,
			violations: [
				{
					rule: 'require_caa',
					message: 'CAA is required, and this scan flags it at medium severity or worse',
					expected: true,
					actual: false,
				},
			],
			inconclusiveRules: [],
		});
		expect(deficient.state).toBe('violated');
	});
});

/** A fake MCP endpoint: `initialize` mints a session, `tools/call` is dispatched by tool name. */
function mockMcp(handlers: Record<string, (args: Record<string, unknown>) => unknown>) {
	const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
	globalThis.fetch = vi.fn(async (_input: unknown, init?: RequestInit) => {
		const body = JSON.parse(String(init?.body ?? '{}'));
		if (body.method === 'initialize') {
			return new Response(
				JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { serverInfo: { name: 'blackveil-dns', version: '9.9.9' } } }),
				{
					headers: { 'content-type': 'application/json', 'mcp-session-id': 'a'.repeat(64) },
				},
			);
		}
		const name = body.params?.name as string;
		const args = (body.params?.arguments ?? {}) as Record<string, unknown>;
		calls.push({ name, args });
		const handler = handlers[name];
		if (!handler) throw new Error(`unexpected tool ${name}`);
		const outcome = handler(args);
		if (outcome instanceof Error) throw outcome;
		return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { structuredContent: outcome } }), {
			headers: { 'content-type': 'application/json' },
		});
	}) as unknown as typeof fetch;
	return calls;
}

const ABSENT_CAA = { category: 'caa', passed: true, score: 85, recordPresent: false, controlPresent: false, findings: [] };
const PRESENT_CAA = { category: 'caa', passed: true, score: 100, recordPresent: true, controlPresent: true, findings: [] };

describe('runControlPredicateSmoke — end to end against a faked live deployment', () => {
	const silent = () => undefined;

	it('a build that applies the predicate passes', async () => {
		const calls = mockMcp({
			check_caa: () => ABSENT_CAA,
			compare_baseline: () => ({ passed: false, violations: [{ rule: 'require_caa' }], inconclusiveRules: [], notApplicableRules: [] }),
		});
		const result = await runControlPredicateSmoke('https://example.invalid/mcp', 'tok', ['probe.test'], silent);
		expect(result.state).toBe('violated');
		expect(result.domain).toBe('probe.test');
		// The baseline carries require_caa ONLY — any extra rule can go inconclusive and
		// poison `passed` to null, turning a decisive gate into a shrug.
		const baselineCall = calls.find((c) => c.name === 'compare_baseline');
		expect(baselineCall?.args.baseline).toEqual({ require_caa: true });
	});

	it('FAILS CLOSED on the stale deploy #725 observed in prod', async () => {
		mockMcp({
			check_caa: () => ABSENT_CAA,
			compare_baseline: () => ({ passed: true, violations: [], inconclusiveRules: [], notApplicableRules: [] }),
		});
		const result = await runControlPredicateSmoke('https://example.invalid/mcp', 'tok', ['probe.test'], silent);
		expect(result.state).toBe('stale');
	});

	it('does NOT fail when the probe domain has published CAA — it skips and tries the next', async () => {
		mockMcp({
			check_caa: (args) => (args.domain === 'gained-caa.test' ? PRESENT_CAA : ABSENT_CAA),
			compare_baseline: () => ({ passed: false, violations: [{ rule: 'require_caa' }], inconclusiveRules: [], notApplicableRules: [] }),
		});
		const result = await runControlPredicateSmoke('https://example.invalid/mcp', 'tok', ['gained-caa.test', 'probe.test'], silent);
		expect(result.state).toBe('violated');
		expect(result.domain).toBe('probe.test');
	});

	it('does NOT fail on a transient transport error — it degrades to indeterminate', async () => {
		mockMcp({
			check_caa: () => new Error('network unreachable'),
			compare_baseline: () => ({ passed: true, violations: [], inconclusiveRules: [], notApplicableRules: [] }),
		});
		const result = await runControlPredicateSmoke('https://example.invalid/mcp', 'tok', ['probe.test'], silent);
		expect(result.state).toBe('indeterminate');
		expect(result.reason).toMatch(/transient/);
	});

	it('does NOT fail when the control probe itself could not measure', async () => {
		mockMcp({
			check_caa: () => ({ category: 'caa', checkStatus: 'error', findings: [] }),
			compare_baseline: () => ({ passed: true, violations: [], inconclusiveRules: [], notApplicableRules: [] }),
		});
		const result = await runControlPredicateSmoke('https://example.invalid/mcp', 'tok', ['probe.test'], silent);
		expect(result.state).toBe('indeterminate');
	});

	it('exhausting every candidate reports each skip reason so the warning is actionable', async () => {
		mockMcp({
			check_caa: () => PRESENT_CAA,
			compare_baseline: () => ({ passed: true, violations: [], inconclusiveRules: [], notApplicableRules: [] }),
		});
		const result = await runControlPredicateSmoke('https://example.invalid/mcp', 'tok', ['a.test', 'b.test'], silent);
		expect(result.state).toBe('indeterminate');
		expect(result.reason).toMatch(/a\.test/);
		expect(result.reason).toMatch(/b\.test/);
	});

	it('never runs compare_baseline against a domain whose control it could not verify absent', async () => {
		const calls = mockMcp({
			check_caa: () => PRESENT_CAA,
			compare_baseline: () => ({ passed: false, violations: [{ rule: 'require_caa' }], inconclusiveRules: [], notApplicableRules: [] }),
		});
		await runControlPredicateSmoke('https://example.invalid/mcp', 'tok', ['a.test'], silent);
		expect(calls.some((c) => c.name === 'compare_baseline')).toBe(false);
	});
});
