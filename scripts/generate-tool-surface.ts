// SPDX-License-Identifier: BUSL-1.1

/**
 * Propagates the PUBLIC tool count into every piece of customer-facing prose
 * that advertises it.
 *
 * Before this existed, adding or removing a tool meant hand-editing 13 count
 * tokens across 6 files and hoping you found them all. The audits pinned most
 * of them as literal `.toContain` strings, so a miss surfaced as a CI failure
 * rather than as a fix — and several occurrences were pinned so loosely they
 * could go stale silently (README's ASCII header was satisfied by a different
 * line entirely).
 *
 * Deliberately NOT generated: `EXPECTED_TOOL_COUNT` in
 * `test/audits/tool-count-ssot.audit.test.ts`. That is the one intentional
 * human-acknowledgement gate on a tool-surface change; auto-bumping it would
 * delete the only forcing function that makes someone look at the change.
 *
 * The token table lives in `scripts/tool-surface-tokens.ts` (pure, no `node:*`)
 * so the audit can share it. Mirrors `scripts/generate-wasm-permissions.ts`:
 * run bare to write, with `--check` to verify.
 *
 * Usage:
 *   npm run generate:tool-surface
 *   npm run check:tool-surface
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { applyToken, CHECK_TOOL_COUNT, PUBLIC_TOOL_COUNT, TOOL_SURFACE_TOKENS } from './tool-surface-tokens';

function main(): void {
	const checkOnly = process.argv.includes('--check');
	const buffers = new Map<string, string>();
	const drift: string[] = [];

	for (const token of TOOL_SURFACE_TOKENS) {
		const path = resolve(token.file);
		const content = buffers.get(token.file) ?? readFileSync(path, 'utf8');
		const { next, current } = applyToken(content, token);

		if (current === null) {
			drift.push(`${token.file}: pattern for "${token.label}" did not match — the prose changed shape; update the token table`);
			continue;
		}
		if (current !== token.expected) {
			drift.push(`${token.file}: "${token.label}" says ${current}, expected ${token.expected}`);
		}
		buffers.set(token.file, next);
	}

	if (checkOnly) {
		if (drift.length > 0) {
			console.error(`Tool-surface prose is stale (${drift.length} issue(s)). Run: npm run generate:tool-surface\n`);
			for (const line of drift) console.error(`  - ${line}`);
			process.exit(1);
		}
		console.log(`Tool-surface prose is current: ${PUBLIC_TOOL_COUNT} public tools, ${CHECK_TOOL_COUNT} check_* tools.`);
		return;
	}

	let written = 0;
	for (const [file, content] of buffers) {
		// Fail loudly on a regex that corrupted structured content, before writing.
		if (file.endsWith('.json')) JSON.parse(content);
		const path = resolve(file);
		if (readFileSync(path, 'utf8') === content) continue;
		writeFileSync(path, content);
		written += 1;
	}

	console.log(`Tool surface: ${PUBLIC_TOOL_COUNT} public tools, ${CHECK_TOOL_COUNT} check_* tools. Updated ${written} file(s).`);
	// A shape-drift entry cannot be auto-fixed — surface it even on a write run.
	for (const line of drift) console.warn(`  ! ${line}`);
}

main();
