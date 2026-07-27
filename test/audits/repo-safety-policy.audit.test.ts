import { describe, expect, it } from 'vitest';
import gitignore from '../../.gitignore?raw';
import preCommit from '../../.githooks/pre-commit?raw';
import commitMsg from '../../.githooks/commit-msg?raw';
import prePush from '../../.githooks/pre-push?raw';
import repoHygiene from '../../.github/workflows/repo-hygiene.yml?raw';

const REPO_SAFETY_FILES = import.meta.glob('/scripts/repo-safety/*', { query: '?raw', eager: true });

function rawBody(mod: unknown): string {
	return typeof (mod as { default?: unknown }).default === 'string' ? String((mod as { default: string }).default) : '';
}

function repoSafetyFile(name: string): string | undefined {
	const match = Object.entries(REPO_SAFETY_FILES).find(([path]) => path.endsWith(`/${name}`));
	return match ? rawBody(match[1]) : undefined;
}

describe('repo safety policy coverage', () => {
	it('keeps forbidden artifact paths consistent across gitignore, hooks, workflow, and scanner policy', () => {
		const policyText = repoSafetyFile('policy.json');
		expect(policyText, 'scripts/repo-safety/policy.json must define the shared forbidden path policy').toBeDefined();
		const policy = JSON.parse(policyText ?? '{}') as { forbiddenPaths?: string[] };
		const forbiddenPaths = policy.forbiddenPaths ?? [];

		expect(forbiddenPaths).toEqual(
			expect.arrayContaining([
				// No trailing slash on directory-shaped patterns (`.dev`, `reports`,
				// `.reports`) — a trailing "/" here mirrors the .gitignore
				// directory-only bypass (see .gitignore's own header comment and
				// #576/#579): `pathMatchesPattern()` in scanner-core.mjs treats the
				// slash and no-slash forms identically for a bare directory name
				// (`file === pattern.replace(/\/$/, '') || file.startsWith(...)`),
				// so dropping it doesn't change scanner behavior, only keeps this
				// policy consistent with the corrected .gitignore convention.
				'.dev',
				'.dev.vars',
				'.mcp-registry-key.pem',
				'wrangler.production.jsonc',
				'reports',
				'.reports',
				'*.pdf',
				'*.env',
				'scripts/tranco-*.json',
			]),
		);

		for (const pattern of forbiddenPaths) {
			expect(gitignore, `.gitignore must include ${pattern}`).toContain(pattern);
			expect(preCommit, `.githooks/pre-commit must include ${pattern}`).toContain(pattern);
			expect(repoHygiene, `.github/workflows/repo-hygiene.yml must include ${pattern}`).toContain(pattern);
		}
	});

	it('ships a repo safety scanner CLI that consumes the shared policy', () => {
		const scanner = repoSafetyFile('scan-sensitive-surface.mjs');
		expect(scanner, 'scripts/repo-safety/scan-sensitive-surface.mjs must exist').toBeDefined();
		expect(scanner).toContain('policy.json');
		expect(scanner).toContain('git ls-files');
	});

	it('scans commit messages before commit and pushed history ranges', () => {
		const commitMessageScanner = repoSafetyFile('scan-commit-message.mjs');
		const pushRangeScanner = repoSafetyFile('scan-push-range-sensitive-surface.mjs');

		expect(commitMessageScanner, 'scripts/repo-safety/scan-commit-message.mjs must exist').toBeDefined();
		expect(commitMessageScanner).toContain('scanCommitMessage');
		expect(commitMsg).toContain('scan-commit-message.mjs');
		expect(prePush).toContain('scan-push-range-sensitive-surface.mjs');
		expect(pushRangeScanner).toContain('scanCommitMessage');
	});
});
