// SPDX-License-Identifier: BUSL-1.1
//
// Selection-steering descriptions: scan-included check_* tools carry a factual
// reference to scan_domain so an LLM can pick scan_domain for a full audit and
// the individual check_* tools for a single control — without prescriptive /
// injection-style language (which the directory-review audit bans).
//
// The steering is DESCRIPTIVE, not prescriptive: it states a fact ("Part of the
// scan_domain audit.") rather than instructing the model how to behave. The last
// `it` block re-asserts the prescriptive-phrase gate against the emitted TOOLS so
// a future edit to the suffix can't silently reintroduce banned language.

import { describe, it, expect } from 'vitest';
import { TOOLS } from '../src/schemas/tool-definitions';

const SCAN_AUDIT_SUFFIX = ' Part of the scan_domain audit.';

// Copied verbatim from test/audits/tool-annotations.audit.test.ts so this guard
// tracks the actual gate rather than a paraphrase of it.
const PRESCRIPTIVE_PHRASES = [
	'use this when',
	'use this to',
	'start here',
	'whenever',
	'you must',
	'you should',
	'make sure to',
	'be sure to',
	'ignore previous',
	'ignore the',
	'disregard',
	'system prompt',
	'system instruction',
];

describe('tool selection-steering descriptions', () => {
	it('every scan-included tool references scan_domain in its description', () => {
		const scanIncluded = TOOLS.filter((t) => t.scanIncluded);
		expect(scanIncluded.length).toBeGreaterThan(0);
		for (const tool of scanIncluded) {
			expect(tool.description, `${tool.name} should reference scan_domain`).toContain('scan_domain');
		}
	});

	it('only scan-included tools carry the scan_domain audit suffix', () => {
		for (const tool of TOOLS) {
			if (tool.scanIncluded) continue;
			expect(tool.description, `${tool.name} (not scan-included) must not carry the suffix`).not.toContain(SCAN_AUDIT_SUFFIX);
		}
	});

	it('representative non-scan-included tools do not carry the suffix', () => {
		const sample = ['scan_domain', 'generate_dmarc_record', 'osint_investigate_domain_start', 'cymru_asn'];
		for (const name of sample) {
			const tool = TOOLS.find((t) => t.name === name);
			expect(tool, `${name} should exist`).toBeDefined();
			expect(tool!.description, `${name} must not carry the suffix`).not.toContain(SCAN_AUDIT_SUFFIX);
		}
	});

	it('scan_domain still conveys breadth', () => {
		const scanDomain = TOOLS.find((t) => t.name === 'scan_domain');
		expect(scanDomain).toBeDefined();
		const desc = scanDomain!.description;
		expect(desc).toContain('check_');
		expect(/audit|broadest/i.test(desc), 'scan_domain should mention audit/breadth').toBe(true);
	});

	it('no emitted description contains prescriptive / injection-style language', () => {
		for (const tool of TOOLS) {
			const lower = tool.description.toLowerCase();
			const hits = PRESCRIPTIVE_PHRASES.filter((p) => lower.includes(p));
			expect(hits, `${tool.name} description steers with: ${hits.join(', ')}`).toEqual([]);
		}
	});
});
