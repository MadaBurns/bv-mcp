// SPDX-License-Identifier: BUSL-1.1
//
// #363 item 2 — tool-overload mitigation for the 79-tool surface.
//
// All tools stay in tools/list; a curated "starter set" is tagged with the
// additive `_meta.recommended: true` flag so a client that implements filtering
// can render a lean view. This does NOT reduce what a naive client shows the
// model — it adds the server-side SIGNAL for client-side curation.
//
// The flag is coupled to the `initialize` instructions string (the channel that
// DOES reach the model): every recommended tool must be named there. If the
// starter set grows, expand BOTH together.

import { describe, it, expect } from 'vitest';
import { TOOLS } from '../src/schemas/tool-definitions';
import { handleToolsList } from '../src/handlers/tools';
import { SERVER_INSTRUCTIONS } from '../src/mcp/server-instructions';

// The curated starter set — mirrors the named tools in SERVER_INSTRUCTIONS.
const RECOMMENDED = ['scan_domain', 'explain_finding', 'compare_baseline'];

describe('_meta.recommended starter-set flag', () => {
	it('flags exactly the curated starter set in TOOL_DEFS', () => {
		const flagged = TOOLS.filter((t) => t.recommended).map((t) => t.name).sort();
		expect(flagged).toEqual([...RECOMMENDED].sort());
	});

	it('emits _meta.recommended === true on tools/list for the starter set', () => {
		const { tools } = handleToolsList();
		for (const name of RECOMMENDED) {
			const wire = tools.find((t) => t.name === name);
			expect(wire, `${name} should be on the wire`).toBeDefined();
			expect(wire!._meta.recommended, `${name} should be flagged recommended`).toBe(true);
		}
	});

	it('omits the recommended field entirely for non-starter tools (lean, like tier)', () => {
		const { tools } = handleToolsList();
		const sample = ['check_spf', 'cymru_asn', 'osint_investigate_domain_start', 'check_dmarc'];
		for (const name of sample) {
			const wire = tools.find((t) => t.name === name);
			expect(wire, `${name} should be on the wire`).toBeDefined();
			expect(wire!._meta.recommended, `${name} must not carry recommended`).toBeUndefined();
		}
	});

	it('is purely additive — every tool is still listed', () => {
		const { tools } = handleToolsList();
		expect(tools.length).toBe(TOOLS.length);
	});

	it('keeps the flag coupled to the instructions string — each recommended tool is named there', () => {
		for (const name of RECOMMENDED) {
			expect(SERVER_INSTRUCTIONS, `${name} must be named in SERVER_INSTRUCTIONS`).toContain(name);
		}
	});
});
