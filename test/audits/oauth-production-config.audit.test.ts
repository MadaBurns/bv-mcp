import { describe, expect, it } from 'vitest';

const wranglerSource = (
	import.meta.glob('../../wrangler.jsonc', { query: '?raw', import: 'default', eager: true }) as Record<string, string>
)['../../wrangler.jsonc'];
const deployWorkflowSource = (
	import.meta.glob('../../.github/workflows/deploy-hook.yml', {
		query: '?raw',
		import: 'default',
		eager: true,
	}) as Record<string, string>
)['../../.github/workflows/deploy-hook.yml'];
const releaseWorkflowSource = (
	import.meta.glob('../../.github/workflows/publish.yml', {
		query: '?raw',
		import: 'default',
		eager: true,
	}) as Record<string, string>
)['../../.github/workflows/publish.yml'];

const config = JSON.parse(wranglerSource) as {
	vars?: Record<string, string>;
	services?: Array<{ binding?: string; service?: string }>;
};

describe('production OAuth configuration audit', () => {
	it('keeps customer OAuth enabled and legacy owner consent disabled', () => {
		expect(config.vars?.ENABLE_OAUTH).toBe('true');
		expect(config.vars?.ENABLE_OWNER_OAUTH).toBe('false');
	});

	it('deploys the customer consent redirect URL required by /oauth/authorize', () => {
		expect(config.vars?.BV_WEB_OAUTH_CONSENT_URL).toBe(
			'https://www.blackveilsecurity.com/oauth/mcp/consent',
		);
	});

	it('binds bv-mcp to bv-web through the service binding', () => {
		expect(config.services).toContainEqual(
			expect.objectContaining({
				binding: 'BV_WEB',
				service: 'bv-web-prod',
			}),
		);
	});

	it('does not commit production secrets as Worker vars', () => {
		const committedVars = config.vars ?? {};
		expect(committedVars).not.toHaveProperty('OAUTH_SIGNING_SECRET');
		expect(committedVars).not.toHaveProperty('BV_API_KEY');
		expect(committedVars).not.toHaveProperty('BV_WEB_INTERNAL_KEY');
	});

	it('deployment verification probes OAuth token health and customer-consent redirect', () => {
		for (const workflowSource of [deployWorkflowSource, releaseWorkflowSource]) {
			expect(workflowSource).toContain('python3 scripts/oauth/prod-probe.py --mode=smoke');
			expect(workflowSource).toContain('python3 scripts/oauth/prod-probe.py --mode=redirect');
		}
	});
});
