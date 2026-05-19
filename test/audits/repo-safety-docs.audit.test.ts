import { describe, expect, it } from 'vitest';
import security from '../../SECURITY.md?raw';
import contributing from '../../CONTRIBUTING.md?raw';
import agents from '../../AGENTS.md?raw';

const DOCS = import.meta.glob('/docs/*.md', { query: '?raw', eager: true });

function doc(name: string): string | undefined {
	const match = Object.entries(DOCS).find(([path]) => path.endsWith(`/${name}`));
	const body = match ? (match[1] as { default?: unknown }).default : undefined;
	return typeof body === 'string' ? body : undefined;
}

describe('repo safety documentation', () => {
	it('documents synthetic fixture rules and the ban on real customer data', () => {
		for (const [name, body] of Object.entries({ 'CONTRIBUTING.md': contributing, 'AGENTS.md': agents })) {
			expect(body, `${name} must mention synthetic fixtures`).toMatch(/synthetic fixtures/i);
			expect(body, `${name} must ban real customer data`).toMatch(/no real customer data/i);
			expect(body, `${name} must recommend reserved domains`).toMatch(/example\.test|example\.com|RFC 5737/i);
		}
	});

	it('documents exposure response for history, PR refs, caches, and forks', () => {
		expect(security).toMatch(/rotate/i);
		expect(security).toMatch(/rewrite/i);
		expect(security).toMatch(/GitHub Support/i);
		expect(security).toMatch(/PR refs/i);
		expect(security).toMatch(/fork/i);
	});

	it('documents required GitHub-side protections', () => {
		const githubSettings = doc('github-settings.md');
		expect(githubSettings, 'docs/github-settings.md must exist').toBeDefined();
		expect(githubSettings).toMatch(/push protection/i);
		expect(githubSettings).toMatch(/custom secret patterns/i);
		expect(githubSettings).toMatch(/branch protection/i);
		expect(githubSettings).toMatch(/required checks/i);
		expect(githubSettings).toMatch(/secret scanning/i);
	});
});
