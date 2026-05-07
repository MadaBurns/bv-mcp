// Audit test: GitHub Actions workflows must fail-fast when a required secret
// is missing, not warn-and-skip.
//
// Background: in May 2026, npm publishes for v2.10.2-v2.10.6 silently dropped
// off the registry because publish.yml used a warn-and-skip pattern:
//   if [ -z "$NPM_TOKEN" ]; then
//     echo "::warning::NPM_TOKEN not configured — skipping npm publish"
//     echo "skip=true" >> "$GITHUB_ENV"
//   fi
// The downstream steps were gated `if: env.skip != 'true'`, so the job exited
// success with nothing published. The MCP Registry job and GitHub Release ran
// fine (different secrets) and the workflow looked green for five releases.
//
// Catch this regression at test time: any token-check step that writes
// `skip=true` to $GITHUB_ENV is forbidden. Use `exit 1` instead.
//
// Per testing-methodology.md principle 4 — audit tests replace review checklists.

import { describe, it, expect } from 'vitest';

// Glob `*.yml` only — disabled workflows (`*.yml.disabled`) don't run, so
// auditing their secret-check patterns is irrelevant. Renaming to
// `.disabled` (operational pause) or back to `.yml` (re-enable) just shifts
// which files get scanned, no static-import edits required.
const workflowModules = import.meta.glob('../../.github/workflows/*.yml', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const WORKFLOWS: ReadonlyArray<readonly [string, string]> = Object.entries(workflowModules)
	.map(([path, content]) => [path.split('/').pop()!, content] as const)
	.sort(([a], [b]) => a.localeCompare(b));

describe('workflow secret-check audit', () => {
	it('no workflow uses the warn-and-skip anti-pattern (`skip=true` written to $GITHUB_ENV)', () => {
		// `skip=true >> "$GITHUB_ENV"` is the smoking gun — when paired with downstream
		// `if: env.skip != 'true'`, it lets the job exit success while publishing nothing.
		const offenders: { file: string; line: number; text: string }[] = [];
		for (const [name, content] of WORKFLOWS) {
			const lines = content.split('\n');
			lines.forEach((text, idx) => {
				if (/skip=true.*GITHUB_ENV/.test(text)) {
					offenders.push({ file: name, line: idx + 1, text: text.trim() });
				}
			});
		}
		expect(offenders, `Warn-and-skip detected. Replace with \`exit 1\`:\n${offenders.map((o) => `  ${o.file}:${o.line}  ${o.text}`).join('\n')}`).toEqual([]);
	});

	it('every secret-presence guard ends with `exit 1` on the missing branch', () => {
		// A "secret-presence guard" is a shell `if [ -z "$SOME_TOKEN" ]; then ... fi`.
		// We grep each workflow for those blocks and assert `exit 1` appears inside.
		const offenders: { file: string; line: number }[] = [];
		for (const [name, content] of WORKFLOWS) {
			const lines = content.split('\n');
			for (let i = 0; i < lines.length; i++) {
				// Match secret-presence guards by suffix: _TOKEN / _KEY / _SECRET.
				// Other `[ -z "$VAR" ]` checks are typically graceful defaults (e.g.
				// CHANGELOG body fallback) and don't represent silent-skip risk.
				const m = lines[i].match(/if\s+\[\s+-z\s+"\$([A-Z_][A-Z0-9_]*(_TOKEN|_KEY|_SECRET))"/);
				if (!m) continue;
				// Look ahead until `fi` or 10 lines (whichever first) for an exit/fail signal.
				let foundExit = false;
				for (let j = i; j < Math.min(i + 10, lines.length); j++) {
					if (/exit\s+[1-9]/.test(lines[j])) {
						foundExit = true;
						break;
					}
					if (/^\s*fi\s*$/.test(lines[j])) break;
				}
				if (!foundExit) {
					offenders.push({ file: name, line: i + 1 });
				}
			}
		}
		expect(offenders, `Secret-presence guards must \`exit 1\` when missing:\n${offenders.map((o) => `  ${o.file}:${o.line}`).join('\n')}`).toEqual([]);
	});
});
