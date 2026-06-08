// SPDX-License-Identifier: BUSL-1.1
//
// Audit test: every MCP tool satisfies the Anthropic Directory review criteria
// for annotations, naming, and description hygiene.
//
// Background: https://claude.com/docs/connectors/building/review-criteria makes
// the following pass/fail requirements for tools exposed over MCP:
//   - tool names must be <= 64 characters
//   - every tool must carry a `title` and the `readOnlyHint`/`destructiveHint`
//     annotations (they drive auto-permissions in the host)
//   - read and destructive operations must live in separate tools, and a
//     destructive tool must advertise `destructiveHint: true`
//   - descriptions must describe behaviour, not steer Claude's behaviour
//     ("use this whenever…", "you must…", "start here…") — prescriptive
//     language is treated as prompt injection at review time
//
// Per testing-methodology.md principle 4 — audit tests replace review
// checklists. Without this lock, a new tool can silently ship a missing
// annotation or an injection-flavoured description that only surfaces when a
// human reviewer rejects the directory submission.

import { describe, it, expect } from 'vitest';
import { TOOLS } from '../../src/schemas/tool-definitions';

/**
 * Case-insensitive phrases that instruct Claude how to behave rather than
 * describe what the tool does. Factual cross-references ("poll with
 * brand_audit_status", "returns …") are intentionally NOT matched.
 */
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

describe('tool annotations & description hygiene (directory review criteria)', () => {
	it('every tool has a non-empty title annotation', () => {
		for (const tool of TOOLS) {
			expect(tool.annotations?.title, `${tool.name} is missing annotations.title`).toBeTruthy();
		}
	});

	it('every tool name is <= 64 characters', () => {
		for (const tool of TOOLS) {
			expect(tool.name.length, `${tool.name} exceeds the 64-char limit`).toBeLessThanOrEqual(64);
		}
	});

	it('every tool defines readOnlyHint and destructiveHint as booleans', () => {
		for (const tool of TOOLS) {
			expect(typeof tool.annotations?.readOnlyHint, `${tool.name}.readOnlyHint`).toBe('boolean');
			expect(typeof tool.annotations?.destructiveHint, `${tool.name}.destructiveHint`).toBe('boolean');
		}
	});

	it('a destructive tool is never also read-only', () => {
		for (const tool of TOOLS) {
			if (tool.annotations?.destructiveHint) {
				expect(tool.annotations.readOnlyHint, `${tool.name} is both destructive and read-only`).toBe(false);
			}
		}
	});

	it('no tool description contains prescriptive / injection-style language', () => {
		for (const tool of TOOLS) {
			const lower = tool.description.toLowerCase();
			const hits = PRESCRIPTIVE_PHRASES.filter((p) => lower.includes(p));
			expect(hits, `${tool.name} description steers Claude with: ${hits.join(', ')}`).toEqual([]);
		}
	});

	// F5: a delete-by-id is idempotent (deleting the same id twice yields the
	// same end state). idempotentHint must NOT be derived blindly as `!mutating`
	// — destructive-but-idempotent deletes have to advertise idempotentHint:true.
	it('delete_brand_audit_watch (destructive delete-by-id) advertises idempotentHint:true', () => {
		const tool = TOOLS.find((t) => t.name === 'delete_brand_audit_watch')!;
		expect(tool.annotations?.destructiveHint, 'delete_brand_audit_watch should still be destructive').toBe(true);
		expect(tool.annotations?.idempotentHint, 'delete-by-id is idempotent').toBe(true);
	});
});
