// SPDX-License-Identifier: BUSL-1.1
//
// Audit test: every binding-backed field on BrandAuditPipelineDeps that has an
// env-sourced runtime option must be forwarded by BOTH call sites — the
// synchronous brand_audit_single execute closure in src/handlers/tools.ts AND
// the queue-consumer's processBrandAuditMessage in src/queue/brand-audit-consumer.ts.
//
// History: two latent forwarding gaps shipped silently because no test pinned
// this parity — `certstream` (fixed in PR #185) and `brandAuditQueue` (fixed in
// this PR). Both followed the same pattern: dep declared on the pipeline,
// declared on ToolRuntimeOptions and/or BrandAuditConsumerDeps, populated by
// src/index.ts from env, but never spread into the deps object actually passed
// to brandAuditSingle / runBrandAuditPipeline. Each gap produced an asymmetric
// runtime behavior (sync vs queued audits, or single vs batch) that was
// invisible to type-checking and required production-evidence debugging to find.
//
// This audit catches the next instance at unit-test time by enumerating the
// required deps and grepping both source files. It's source-text grep — fragile
// to renames but cheap to update and stronger than nothing.
//
// Runs in the Cloudflare Workers test pool, so we use Vite's `?raw` source-file
// imports rather than node:fs (which the Workers runtime doesn't expose).
//
// Per testing-methodology.md principle 4 — audit tests replace review checklists.

import { describe, it, expect } from 'vitest';
import queueSource from '../../src/queue/brand-audit-consumer.ts?raw';
import handlerSource from '../../src/handlers/tools.ts?raw';

/**
 * Each entry: a field on BrandAuditPipelineDeps that is sourced from a
 * Cloudflare binding / env variable at request or queue dispatch time.
 *
 * `queuePattern` matches the line in src/queue/brand-audit-consumer.ts's
 * processBrandAuditMessage where the dep is conditionally spread into
 * singleDeps. The shape is `...(deps.<name> ? { <name>: deps.<name> } : {}),`.
 *
 * `handlerPattern` matches the line in src/handlers/tools.ts's brand_audit_single
 * execute closure where the dep is passed into brandAuditSingle's deps arg.
 * Two shapes accepted because the closure mixes both styles:
 *   - `<name>: ro?.<name>` (unconditional pass-through, used for certstream/whois)
 *   - `...(ro?.<name> ? { <name>: ro.<name> } : {})` (conditional spread, tier closures)
 */
const REQUIRED_DEPS: Array<{ name: string; queuePattern: RegExp; handlerPattern: RegExp }> = [
	{
		name: 'certstream',
		queuePattern: /\.\.\.\(deps\.certstream\s*\?\s*\{\s*certstream:\s*deps\.certstream\s*\}\s*:\s*\{\}\),?/,
		handlerPattern: /certstream:\s*ro\?\.certstream/,
	},
	{
		name: 'whoisBinding',
		queuePattern: /\.\.\.\(deps\.whoisBinding\s*\?\s*\{\s*whoisBinding:\s*deps\.whoisBinding\s*\}\s*:\s*\{\}\),?/,
		handlerPattern: /whoisBinding:\s*ro\?\.whoisBinding/,
	},
	{
		name: 'tier0Lookup',
		queuePattern: /\.\.\.\(deps\.tier0Lookup\s*\?\s*\{\s*tier0Lookup:\s*deps\.tier0Lookup\s*\}\s*:\s*\{\}\),?/,
		handlerPattern: /\.\.\.\(ro\?\.tier0Lookup\s*\?\s*\{\s*tier0Lookup:\s*ro\.tier0Lookup\s*\}\s*:\s*\{\}\),?/,
	},
	{
		name: 'tier1Lookup',
		queuePattern: /\.\.\.\(deps\.tier1Lookup\s*\?\s*\{\s*tier1Lookup:\s*deps\.tier1Lookup\s*\}\s*:\s*\{\}\),?/,
		handlerPattern: /\.\.\.\(ro\?\.tier1Lookup\s*\?\s*\{\s*tier1Lookup:\s*ro\.tier1Lookup\s*\}\s*:\s*\{\}\),?/,
	},
	{
		name: 'tier2Lookup',
		queuePattern: /\.\.\.\(deps\.tier2Lookup\s*\?\s*\{\s*tier2Lookup:\s*deps\.tier2Lookup\s*\}\s*:\s*\{\}\),?/,
		handlerPattern: /\.\.\.\(ro\?\.tier2Lookup\s*\?\s*\{\s*tier2Lookup:\s*ro\.tier2Lookup\s*\}\s*:\s*\{\}\),?/,
	},
	{
		name: 'brandAuditQueue',
		queuePattern: /\.\.\.\(deps\.brandAuditQueue\s*\?\s*\{\s*brandAuditQueue:\s*deps\.brandAuditQueue\s*\}\s*:\s*\{\}\),?/,
		handlerPattern: /\.\.\.\(ro\?\.brandAuditQueue\s*\?\s*\{\s*brandAuditQueue:\s*ro\.brandAuditQueue\s*\}\s*:\s*\{\}\),?/,
	},
];

describe('brand-audit pipeline deps-surface parity audit', () => {
	for (const dep of REQUIRED_DEPS) {
		it(`forwards \`${dep.name}\` from the queue consumer's singleDeps construction`, () => {
			expect(queueSource).toMatch(dep.queuePattern);
		});

		it(`forwards \`${dep.name}\` from the brand_audit_single handler's deps arg`, () => {
			expect(handlerSource).toMatch(dep.handlerPattern);
		});
	}

	it('queue consumer hasSingleDeps gate includes every required dep', () => {
		// The 2-arg vs 3-arg call decision in processBrandAuditMessage is keyed on
		// `hasSingleDeps`. Missing a dep here means a deploy with ONLY that dep
		// would fall through to the 2-arg call and drop the dep silently.
		const hasSingleDepsLine = queueSource.match(/const\s+hasSingleDeps\s*=\s*([^;]+);/);
		expect(hasSingleDepsLine, 'could not locate hasSingleDeps declaration').toBeTruthy();
		const gateExpr = hasSingleDepsLine![1];
		for (const dep of REQUIRED_DEPS) {
			expect(gateExpr, `hasSingleDeps must include deps.${dep.name}`).toMatch(new RegExp(`deps\\.${dep.name}\\b`));
		}
	});
});
