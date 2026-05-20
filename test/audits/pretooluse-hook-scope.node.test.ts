// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: Claude Code PreToolUse Bash hook scope.
 *
 * Regression test for a false-positive where the `Force push blocked` hook fired
 * against `npm run report:qa -- $(...)` even though the command contained no
 * `git push --force`. Root cause: the hook was matching too broadly (or the
 * `if:` clause was ignored entirely, causing every PreToolUse hook to fire on
 * every Bash command). The fix is a standalone shell script that extracts
 * `.tool_input.command` from the JSON payload on stdin via `jq` and matches
 * the command-word position only.
 *
 * Contract:
 *   - exit 2  => block (Claude Code stops continuation)
 *   - exit 0  => allow
 *   - stderr  => human-readable block reason (Claude Code surfaces it)
 *
 * The hook MUST only read `.tool_input.command` — never script content or
 * arbitrary text. The Claude Code Bash tool always supplies that key.
 */

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const HOOK_PATH = join(process.cwd(), '.claude/hooks/block-force-push.sh');

function runHook(payload: unknown): { status: number; stderr: string } {
	const result = spawnSync(HOOK_PATH, [], {
		input: JSON.stringify(payload),
		encoding: 'utf8',
	});
	return { status: result.status ?? -1, stderr: result.stderr ?? '' };
}

describe('Claude Code PreToolUse Bash hook: block-force-push.sh', () => {
	it('exists and is executable', () => {
		expect(existsSync(HOOK_PATH)).toBe(true);
		// Smoke test: empty stdin should not crash. Exit 0 (no command => allow).
		const result = spawnSync(HOOK_PATH, [], { input: '{}', encoding: 'utf8' });
		expect(result.status).toBe(0);
	});

	describe('BLOCKS (exit 2) for real force pushes', () => {
		it('git push --force origin main', () => {
			const { status, stderr } = runHook({
				tool_name: 'Bash',
				tool_input: { command: 'git push --force origin main' },
			});
			expect(status).toBe(2);
			expect(stderr).toMatch(/[Ff]orce push/);
		});

		it('git push --force-with-lease', () => {
			// --force-with-lease still rewrites history; block by design.
			const { status } = runHook({
				tool_name: 'Bash',
				tool_input: { command: 'git push --force-with-lease' },
			});
			expect(status).toBe(2);
		});

		it('git push -f origin main (short flag)', () => {
			const { status } = runHook({
				tool_name: 'Bash',
				tool_input: { command: 'git push -f origin main' },
			});
			expect(status).toBe(2);
		});

		it('git push origin main --force (flag at end)', () => {
			const { status } = runHook({
				tool_name: 'Bash',
				tool_input: { command: 'git push origin main --force' },
			});
			expect(status).toBe(2);
		});

		it('git   push   --force (extra whitespace)', () => {
			const { status } = runHook({
				tool_name: 'Bash',
				tool_input: { command: 'git   push   --force' },
			});
			expect(status).toBe(2);
		});
	});

	describe('ALLOWS (exit 0) for benign commands', () => {
		it('npm run report:qa with command substitution', () => {
			// This is the exact false-positive that motivated the regression test.
			const { status } = runHook({
				tool_name: 'Bash',
				tool_input: {
					command:
						"npm run report:qa -- $(ls reports/*-discovery-report.json | sed 's|reports/||;s|-discovery-report.json||' | tr '\\n' ' ') 2>&1 | tail -40",
				},
			});
			expect(status).toBe(0);
		});

		it('echo "force push" (phrase appears but no git push)', () => {
			const { status } = runHook({
				tool_name: 'Bash',
				tool_input: { command: 'echo "force push"' },
			});
			expect(status).toBe(0);
		});

		it('echo "git push --force" (mention only, not invocation)', () => {
			const { status } = runHook({
				tool_name: 'Bash',
				tool_input: { command: 'echo "git push --force"' },
			});
			expect(status).toBe(0);
		});

		it('git push (without --force)', () => {
			const { status } = runHook({
				tool_name: 'Bash',
				tool_input: { command: 'git push origin main' },
			});
			expect(status).toBe(0);
		});

		it('git status', () => {
			const { status } = runHook({
				tool_name: 'Bash',
				tool_input: { command: 'git status' },
			});
			expect(status).toBe(0);
		});

		it('grep --force-overwrite something (unrelated --force flag in another tool)', () => {
			const { status } = runHook({
				tool_name: 'Bash',
				tool_input: { command: 'rsync --force /tmp/a /tmp/b' },
			});
			expect(status).toBe(0);
		});

		it('non-Bash tools are ignored', () => {
			const { status } = runHook({
				tool_name: 'Read',
				tool_input: { file_path: '/tmp/foo.txt' },
			});
			expect(status).toBe(0);
		});
	});
});
