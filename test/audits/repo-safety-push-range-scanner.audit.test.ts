/** @vitest-environment node */
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';

const scannerPath = join(process.cwd(), 'scripts/repo-safety/scan-push-range-sensitive-surface.mjs');
const prePushPath = join(process.cwd(), '.githooks/pre-push');
const zeroSha = '0000000000000000000000000000000000000000';
const missingRemoteSha = '1111111111111111111111111111111111111111';

function git(cwd: string, args: string[]): string {
	return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function makeRepo(): string {
	const repo = mkdtempSync(join(tmpdir(), 'bv-mcp-push-range-'));
	git(repo, ['init', '--quiet']);
	git(repo, ['branch', '-M', 'main']);
	git(repo, ['config', 'user.email', 'dev@example.test']);
	git(repo, ['config', 'user.name', 'Repo Safety Test']);
	return repo;
}

function commitFile(repo: string, file: string, body: string): string {
	writeFileSync(join(repo, file), body);
	git(repo, ['add', file]);
	git(repo, ['commit', '--quiet', '-m', `add ${file}`]);
	return git(repo, ['rev-parse', 'HEAD']);
}

describe('repo safety push-range scanner', () => {
	it('blocks forbidden paths when the pushed remote sha no longer exists locally', () => {
		const repo = makeRepo();
		try {
			mkdirSync(join(repo, 'reports'), { recursive: true });
			const head = commitFile(repo, 'reports/example.com-discovery-report.md', '# generated report\n');

			const result = spawnSync('node', [scannerPath], {
				cwd: repo,
				input: `refs/heads/main ${head} refs/heads/main ${missingRemoteSha}\n`,
				encoding: 'utf8',
			});

			expect(result.status).toBe(1);
			expect(result.stderr).toContain('Repo safety push-range scanner blocked sensitive history:');
			expect(result.stderr).toContain('reports/example.com-discovery-report.md forbidden-path (reports/) [redacted]');
			expect(result.stderr).not.toContain('Invalid revision range');
		} finally {
			rmSync(repo, { recursive: true, force: true });
		}
	});

	it('does not rescan history already on a remote-tracking ref when the remote sha is unknown (non-fast-forward)', () => {
		const repo = makeRepo();
		try {
			// History the remote already holds, containing content the scanner would flag.
			mkdirSync(join(repo, 'reports'), { recursive: true });
			const published = commitFile(repo, 'reports/example.com-discovery-report.md', '# generated report\n');
			git(repo, ['update-ref', 'refs/remotes/origin/main', published]);
			// One new local commit; the remote tip (e.g. a merge added by `gh pr update-branch`) is not local.
			const head = commitFile(repo, 'README.md', '# synthetic fixture\n');

			const result = spawnSync('node', [scannerPath], {
				cwd: repo,
				input: `refs/heads/main ${head} refs/heads/main ${missingRemoteSha}\n`,
				encoding: 'utf8',
			});

			expect(result.status).toBe(0);
			expect(result.stdout).toContain('Repo safety push-range scanner found no sensitive history.');
			expect(result.stderr).toContain('is not known locally');
			expect(result.stderr).toContain('fetch and rebase first');
			expect(result.stderr).not.toContain('reports/example.com-discovery-report.md');
		} finally {
			rmSync(repo, { recursive: true, force: true });
		}
	});

	it('still blocks new unpublished commits when the remote sha is unknown and remotes exist', () => {
		const repo = makeRepo();
		try {
			const published = commitFile(repo, 'README.md', '# synthetic fixture\n');
			git(repo, ['update-ref', 'refs/remotes/origin/main', published]);
			mkdirSync(join(repo, 'reports'), { recursive: true });
			const head = commitFile(repo, 'reports/example.com-discovery-report.md', '# generated report\n');

			const result = spawnSync('node', [scannerPath], {
				cwd: repo,
				input: `refs/heads/main ${head} refs/heads/main ${missingRemoteSha}\n`,
				encoding: 'utf8',
			});

			expect(result.status).toBe(1);
			expect(result.stderr).toContain('reports/example.com-discovery-report.md forbidden-path (reports/) [redacted]');
		} finally {
			rmSync(repo, { recursive: true, force: true });
		}
	});

	it('pre-push range_for_push excludes remote-tracking history when the remote sha is unknown', () => {
		const repo = makeRepo();
		try {
			const published = commitFile(repo, 'README.md', '# synthetic fixture\n');
			git(repo, ['update-ref', 'refs/remotes/origin/main', published]);
			const head = commitFile(repo, 'NOTES.md', '# notes\n');

			// Load only the function under test from the hook (bash 3.2 compatible: no `source <(...)`).
			const hookSource = readFileSync(prePushPath, 'utf8');
			const fn = hookSource.match(/^range_for_push\(\) \{[\s\S]*?^\}$/m)?.[0];
			expect(fn).toBeTruthy();
			const rangeFor = (remote: string): string =>
				execFileSync('bash', ['-c', `ZERO_SHA=${zeroSha}\n${fn}\nrange_for_push "$1" "$2"`, 'range', head, remote], {
					cwd: repo,
					encoding: 'utf8',
				}).trim();

			const unknownRange = rangeFor(missingRemoteSha);
			expect(unknownRange).toBe(`${head} --not --remotes`);
			// gitleaks splits --log-opts on spaces; the same tokens must select only the new commit.
			expect(git(repo, ['rev-list', ...unknownRange.split(' ')])).toBe(head);

			expect(rangeFor(published)).toBe(`${published}..${head}`);
		} finally {
			rmSync(repo, { recursive: true, force: true });
		}
	});

	it('allows safe pushed ranges', () => {
		const repo = makeRepo();
		try {
			const head = commitFile(repo, 'README.md', '# synthetic fixture\n');

			const result = spawnSync('node', [scannerPath], {
				cwd: repo,
				input: `refs/heads/main ${head} refs/heads/main ${zeroSha}\n`,
				encoding: 'utf8',
			});

			expect(result.status).toBe(0);
			expect(result.stdout).toContain('Repo safety push-range scanner found no sensitive history.');
		} finally {
			rmSync(repo, { recursive: true, force: true });
		}
	});
});
