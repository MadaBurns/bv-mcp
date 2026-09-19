// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';

/**
 * SQ-67 tripwire — the four per-tool policy gates (internal-only, auth-required,
 * paid-only, contract-flag) used to be referenced ONLY inside
 * `src/mcp/execute.ts`, while `src/internal.ts` imported `handleToolsCall`
 * straight from `src/handlers/tools.ts` and dispatched without them. Nothing
 * failed: the `/internal/*` network guard and the capability bearer held the
 * line, so the *policy* invariant was unenforced AND untested, free to drift.
 *
 * No behavioural test can catch that class, because the defect is the ABSENCE
 * of a call in a file nobody thought to look at. This audit reads the sources
 * and pins the census: every module that reaches tool dispatch is either a
 * request-facing entry point that consults the shared chokepoint, or trusted
 * server-side orchestration that picks the tool itself. A NEW caller fails the
 * exact-set assertion until someone writes down which of the two it is.
 */

const SOURCES = import.meta.glob('../src/**/*.ts', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;

/** The chokepoint itself. */
const POLICY_MODULE = '../src/lib/config.ts';

/** Where `handleToolsCall` is defined — not a caller. */
const DISPATCH_MODULE = '../src/handlers/tools.ts';

/**
 * Every module permitted to call `handleToolsCall`, with the reason its calls
 * are policed. `policyLayer` names the module that evaluates
 * `evaluateToolPolicy` before dispatch; `trusted` records why no request-derived
 * tool name reaches dispatch there.
 */
const PERMITTED_DISPATCH_CALLERS: Record<string, { policyLayer: string } | { trusted: string }> = {
	// Public `/mcp`: executeMcpRequest gates, then hands off to dispatchMcpMethod.
	'../src/mcp/dispatch.ts': { policyLayer: '../src/mcp/execute.ts' },
	// `/internal/tools/{call,batch}`: gates inline, after its principal allowlists.
	'../src/internal.ts': { policyLayer: '../src/internal.ts' },
	// Queue consumer for async job records the Worker itself enqueued.
	'../src/index.ts': { trusted: 'scheduled/queue orchestration; tool name is server-selected, not request-derived' },
	// Tenant scan pipeline: fixed `scan_domain` behind the tenant bearer.
	'../src/tenants/routes.ts': { trusted: 'tenant orchestrator; fixed scan_domain behind the dedicated tenant capability' },
	'../src/tenants/queue-consumer.ts': { trusted: 'tenant scan queue; fixed scan_domain from a Worker-enqueued message' },
};

const isComment = (text: string) => /^\s*(\/\/|\/\*|\*)/.test(text);

/** Modules with a real (non-comment) `handleToolsCall(` call site. */
const dispatchCallers = Object.entries(SOURCES)
	.filter(([path]) => path !== DISPATCH_MODULE)
	.filter(([, source]) => source.split('\n').some((line) => /\bhandleToolsCall\s*\(/.test(line) && !isComment(line)))
	.map(([path]) => path)
	.sort();

describe('per-tool policy chokepoint census (SQ-67)', () => {
	it('positive control: the source glob can see the worker sources at all', () => {
		// A zero here would make every assertion below vacuously green.
		expect(Object.keys(SOURCES).length).toBeGreaterThan(50);
		expect(SOURCES[DISPATCH_MODULE]).toContain('export async function handleToolsCall');
		expect(dispatchCallers.length).toBeGreaterThan(0);
	});

	it('every module that reaches tool dispatch is a declared entry point', () => {
		expect(
			dispatchCallers,
			'A new handleToolsCall caller must be declared in PERMITTED_DISPATCH_CALLERS as either policy-bearing ' +
				'(it calls evaluateToolPolicy first) or trusted server-side orchestration. Adding a request-facing ' +
				'entry point without the policy layer is the SQ-67 defect.',
		).toEqual(Object.keys(PERMITTED_DISPATCH_CALLERS).sort());
	});

	it('every policy-bearing entry point actually evaluates the shared chokepoint', () => {
		const missing = Object.entries(PERMITTED_DISPATCH_CALLERS)
			.filter((entry): entry is [string, { policyLayer: string }] => 'policyLayer' in entry[1])
			.filter(([, { policyLayer }]) => !(SOURCES[policyLayer] ?? '').includes('evaluateToolPolicy('))
			.map(([path, { policyLayer }]) => `${path} → ${policyLayer}`);

		expect(missing, 'A declared policy layer that no longer calls evaluateToolPolicy is the gate silently deleted.').toEqual([]);
	});

	it('both request-facing surfaces gate before dispatch', () => {
		// Named explicitly so deleting either call site fails here even if the census
		// above is edited to match.
		expect(SOURCES['../src/mcp/execute.ts']).toContain('evaluateToolPolicy(');
		expect(SOURCES['../src/internal.ts']).toContain('evaluateToolPolicy(');
	});

	it('the four gates are reached through the chokepoint, not re-forked per surface', () => {
		// Direct predicate calls in an entry point are how the fork happened the first
		// time: one surface updated its copy, the other never had one.
		const forked = ['../src/mcp/execute.ts', '../src/internal.ts'].flatMap((path) =>
			(SOURCES[path] ?? '')
				.split('\n')
				.map((text, index) => ({ text, line: index + 1 }))
				.filter(({ text }) => !isComment(text))
				.filter(({ text }) => /\b(isInternalOnlyTool|isAuthRequiredTool|isGatedPaidOnlyTool|contractFlagBlocks)\s*\(/.test(text))
				.map(({ line, text }) => `${path}:${line}  ${text.trim()}`),
		);

		expect(forked, 'Call evaluateToolPolicy() instead of a gate predicate directly — that is what keeps the surfaces in step.').toEqual([]);
	});

	it('the chokepoint still consults all four gates', () => {
		// Guards the other direction: keeping the NAME while hollowing out the body
		// would make every assertion above pass while re-opening the hole.
		const policySource = SOURCES[POLICY_MODULE] ?? '';
		const body = policySource.slice(policySource.indexOf('export function evaluateToolPolicy'));
		expect(body).not.toBe('');
		for (const gate of ['isInternalOnlyTool(', 'isAuthRequiredTool(', 'isGatedPaidOnlyTool(', 'contractFlagBlocks(']) {
			expect(body, `evaluateToolPolicy no longer consults ${gate}`).toContain(gate);
		}
	});
});
