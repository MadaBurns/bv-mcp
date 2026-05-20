/** @vitest-environment node */
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';

const scannerPath = join(process.cwd(), 'scripts/repo-safety/scan-push-range-sensitive-surface.mjs');
const zeroSha = '0000000000000000000000000000000000000000';
const missingRemoteSha = '1111111111111111111111111111111111111111';

function git(cwd: string, args: string[]): string {
	return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function makeRepo(): string {
	const repo = mkdtempSync(join(tmpdir(), 'bv-mcp-push-range-'));
	git(repo, ['init', '--quiet']);
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
