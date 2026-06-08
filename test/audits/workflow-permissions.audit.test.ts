// Audit test: GitHub Actions least-privilege permissions + supply-chain pinning.
//
// FINDING F10 — OIDC must never reach untrusted-code jobs.
//   publish.yml previously granted `contents: write` + `id-token: write` at the
//   WORKFLOW scope, so every job (including `validate`, which runs `npm ci` /
//   build / test over third-party code) inherited token-minting capability.
//   OIDC (`id-token: write`) and `contents: write` must be elevated per-job
//   ONLY where needed, on top of a read-only workflow default.
//   Expected layout:
//     workflow-level:  permissions: { contents: read }
//     id-token: write  -> ONLY publish-npm  (npm provenance / OIDC)
//     contents: write  -> ONLY version-bump (push bump) + github-release (gh release create)
//
// FINDING F11 — actions must be SHA-pinned (40-hex), not tag-pinned, so a
//   re-tagged upstream action can't silently change executed code.
//
// No `js-yaml` is available in the dep tree, so we parse the relevant slices of
// the workflow YAML with a small indentation-aware walker. Workflows are read
// via `?raw` (matching the other workflow audits — they run in the Workers pool
// where `fs` is unavailable).

import { describe, it, expect } from 'vitest';

const workflowModules = import.meta.glob('../../.github/workflows/*.yml', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

function workflowByName(name: string): string {
	const entry = Object.entries(workflowModules).find(([p]) => p.endsWith(`/${name}`));
	if (!entry) throw new Error(`workflow not found: ${name}`);
	return entry[1];
}

const ACTIVE_WORKFLOWS: ReadonlyArray<readonly [string, string]> = Object.entries(workflowModules)
	.map(([path, content]) => [path.split('/').pop()!, content] as const)
	.sort(([a], [b]) => a.localeCompare(b));

// --- Minimal indentation-aware YAML slicing -------------------------------
// We only need two things, both keyed on top-level `jobs:`:
//   1. the workflow-level `permissions:` mapping (top-level key, 0 indent)
//   2. each job's `permissions:` mapping (under jobs.<name>, 2-space indent)

function indentOf(line: string): number {
	return line.length - line.replace(/^ */, '').length;
}

/** Collect the indented child lines of a `key:` block at a given parent indent. */
function blockBody(lines: string[], startIdx: number, keyIndent: number): string[] {
	const body: string[] = [];
	for (let i = startIdx + 1; i < lines.length; i++) {
		const raw = lines[i];
		if (raw.trim() === '' || raw.trim().startsWith('#')) continue;
		if (indentOf(raw) <= keyIndent) break;
		body.push(raw);
	}
	return body;
}

/** Top-level (0-indent) `permissions:` mapping → record of scope→value. null if absent. */
function topLevelPermissions(content: string): Record<string, string> | null {
	const lines = content.split('\n');
	for (let i = 0; i < lines.length; i++) {
		if (/^permissions:\s*$/.test(lines[i])) {
			return parseScalarMap(blockBody(lines, i, 0));
		}
		// inline form: `permissions: read-all` / `permissions: {}`
		const inline = lines[i].match(/^permissions:\s+(\S.*)$/);
		if (inline) return { __inline__: inline[1].trim() };
	}
	return null;
}

function parseScalarMap(body: string[]): Record<string, string> {
	const out: Record<string, string> = {};
	for (const line of body) {
		const m = line.trim().match(/^([A-Za-z0-9_-]+):\s*(\S.*)$/);
		if (m) out[m[1]] = m[2].trim();
	}
	return out;
}

interface Job {
	name: string;
	permissions: Record<string, string> | null;
}

/** Parse `jobs:` and return each job key + its (optional) `permissions:` map. */
function parseJobs(content: string): Job[] {
	const lines = content.split('\n');
	const jobsIdx = lines.findIndex((l) => /^jobs:\s*$/.test(l));
	if (jobsIdx === -1) return [];
	const jobs: Job[] = [];
	for (let i = jobsIdx + 1; i < lines.length; i++) {
		const raw = lines[i];
		if (raw.trim() === '' || raw.trim().startsWith('#')) continue;
		const ind = indentOf(raw);
		if (ind === 0) break; // left the jobs block
		// Job keys live at exactly 2-space indent: `  <jobname>:`
		const m = raw.match(/^ {2}([A-Za-z0-9_-]+):\s*$/);
		if (ind === 2 && m) {
			const jobBody = blockBody(lines, i, 2);
			// find a `permissions:` at the job's child indent (4 spaces)
			let permissions: Record<string, string> | null = null;
			for (let j = 0; j < jobBody.length; j++) {
				if (/^ {4}permissions:\s*$/.test(jobBody[j])) {
					// blockBody over the original lines for correct lookahead
					const absoluteIdx = lines.indexOf(jobBody[j], i);
					permissions = parseScalarMap(blockBody(lines, absoluteIdx, 4));
					break;
				}
				const inline = jobBody[j].match(/^ {4}permissions:\s+(\S.*)$/);
				if (inline) {
					permissions = { __inline__: inline[1].trim() };
					break;
				}
			}
			jobs.push({ name: m[1], permissions });
		}
	}
	return jobs;
}

// A per-job block grants write to `scope` either explicitly (`scope: write`)
// or via an inline `permissions: write-all`, which the parser stores under the
// synthetic `__inline__` key. The latter would otherwise slip past the
// id-token / contents per-job checks (it never sets `perms[scope]`).
const hasWrite = (perms: Record<string, string> | null, scope: string): boolean =>
	perms?.[scope] === 'write' || perms?.__inline__ === 'write-all';

describe('workflow permissions audit (F10 — least-privilege OIDC)', () => {
	const publish = workflowByName('publish.yml');
	const top = topLevelPermissions(publish);
	const jobs = parseJobs(publish);
	const jobNames = jobs.map((j) => j.name).sort();

	it('publish.yml workflow-level permissions are read-only (no contents/id-token write at workflow scope)', () => {
		// The block MUST be present AND read-only. If a future PR deletes the
		// top-level `permissions: contents: read`, every job (incl. `validate`,
		// which runs `npm ci` / build / test over third-party code) falls back to
		// the repo-default token permissions — that IS the F10 regression. So we
		// require the block to exist, not merely "be read-only if present".
		expect(top, 'publish.yml must declare a read-only workflow-level permissions block').not.toBeNull();
		expect(top!.contents ?? 'read', 'workflow-level contents must not be write').not.toBe('write');
		expect(top!['id-token'] ?? 'none', 'workflow-level id-token must not be write').not.toBe('write');
		expect(top!.__inline__, 'workflow-level permissions must not be write-all').not.toBe('write-all');
	});

	it('parsed all six publish.yml jobs', () => {
		expect(jobNames).toEqual(['deploy-cloudflare', 'github-release', 'publish-npm', 'publish-registry', 'validate', 'version-bump']);
	});

	it('id-token: write appears ONLY in the publish-npm job (OIDC must not reach untrusted-code jobs)', () => {
		const withIdToken = jobs.filter((j) => hasWrite(j.permissions, 'id-token')).map((j) => j.name);
		expect(withIdToken).toEqual(['publish-npm']);
	});

	it('contents: write appears ONLY in version-bump and github-release jobs', () => {
		const withContentsWrite = jobs
			.filter((j) => hasWrite(j.permissions, 'contents'))
			.map((j) => j.name)
			.sort();
		expect(withContentsWrite).toEqual(['github-release', 'version-bump']);
	});

	it('the untrusted-code job (validate) has no write permission', () => {
		const validate = jobs.find((j) => j.name === 'validate');
		expect(validate, 'validate job present').toBeTruthy();
		// Either no block (inherits read-only default) or an explicit read-only
		// block. Reject both per-scope `write` and the inline `write-all` grant
		// (`read-all` is acceptable = read-only). The literal 'write-all' string
		// is !== 'write', so a bare `.not.toContain('write')` would let it slip.
		if (validate!.permissions) {
			const values = Object.values(validate!.permissions);
			expect(values, 'validate job must not grant any write permission').not.toContain('write');
			expect(values, 'validate job must not grant inline write-all').not.toContain('write-all');
		}
	});
});

describe('workflow supply-chain pinning audit (F11 — SHA-pinned actions)', () => {
	// Every `uses:` referencing a remote action (owner/repo[/path]@ref) must pin
	// to a 40-char commit SHA, with a trailing `# vX.Y.Z` comment for humans.
	const USES_RE = /uses:\s*([^\s]+)/;
	const SHA_RE = /^[0-9a-f]{40}$/;

	it('all active-workflow actions are pinned to a 40-hex commit SHA', () => {
		const offenders: { file: string; line: number; ref: string }[] = [];
		for (const [name, content] of ACTIVE_WORKFLOWS) {
			content.split('\n').forEach((text, idx) => {
				const m = text.match(USES_RE);
				if (!m) return;
				const usesValue = m[1].replace(/['"]/g, '');
				// Skip local/reusable references (./… or no @ref like reusable workflow calls handled separately)
				if (usesValue.startsWith('./') || usesValue.startsWith('.github/')) return;
				const at = usesValue.lastIndexOf('@');
				if (at === -1) return; // not a versioned ref
				const ref = usesValue.slice(at + 1);
				if (!SHA_RE.test(ref)) {
					offenders.push({ file: name, line: idx + 1, ref: usesValue });
				}
			});
		}
		expect(offenders, `Actions must be SHA-pinned (40-hex). Tag-pinned refs found:\n${offenders.map((o) => `  ${o.file}:${o.line}  ${o.ref}`).join('\n')}`).toEqual([]);
	});

	it('every SHA-pinned action carries a trailing version comment', () => {
		const offenders: { file: string; line: number }[] = [];
		for (const [name, content] of ACTIVE_WORKFLOWS) {
			content.split('\n').forEach((text, idx) => {
				const m = text.match(/uses:\s*([^\s]+@[0-9a-f]{40})/);
				if (!m) return;
				if (!/#\s*v\d/.test(text)) offenders.push({ file: name, line: idx + 1 });
			});
		}
		expect(offenders, `SHA-pinned actions must carry a \`# vX.Y.Z\` comment:\n${offenders.map((o) => `  ${o.file}:${o.line}`).join('\n')}`).toEqual([]);
	});
});
