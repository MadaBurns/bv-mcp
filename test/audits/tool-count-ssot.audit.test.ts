// SPDX-License-Identifier: BUSL-1.1

/**
 * Single source-of-truth tripwire for the MCP tool-surface size.
 *
 * This is the ONE place that hardcodes the tool count. It is a deliberate
 * human-acknowledgment gate: when you add or remove a tool in TOOL_DEFS, this
 * assertion fails, forcing a conscious confirmation that the public surface
 * changed (and a prompt to update the README/docs prose — enforced separately
 * by `readme-tool-surface.audit.test.ts` against `TOOLS.length`).
 *
 * Everywhere else, counts and partitions DERIVE from TOOLS / TOOL_DEFS rather
 * than repeating this number — see the relational assertions in
 * `tool-schemas.spec.ts`, `tool-output-schema.spec.ts`, and
 * `schemas/tool-args.spec.ts`. Do NOT re-introduce a hardcoded tool count
 * there; bump it here only.
 */

import { describe, it, expect } from 'vitest';
import { TOOLS } from '../../src/schemas/tool-definitions';

const EXPECTED_TOOL_COUNT = 81;

describe('tool-count SSOT', () => {
	it(`exposes exactly ${EXPECTED_TOOL_COUNT} tools (intentional acknowledgment gate)`, () => {
		expect(TOOLS).toHaveLength(EXPECTED_TOOL_COUNT);
	});
});
