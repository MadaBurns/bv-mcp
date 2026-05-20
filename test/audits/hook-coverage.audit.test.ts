import { describe, expect, it } from 'vitest';
import preCommit from '../../.githooks/pre-commit?raw';

const HOOKS = import.meta.glob('/.githooks/*', { query: '?raw', eager: true });

function hook(name: string): string | undefined {
	const match = Object.entries(HOOKS).find(([path]) => path.endsWith(`/${name}`));
	const body = match ? (match[1] as { default?: unknown }).default : undefined;
	return typeof body === 'string' ? body : undefined;
}

describe('git hook safety coverage', () => {
	it('pre-push runs gitleaks and the repo safety scanner before upload', () => {
		const prePush = hook('pre-push');
		expect(prePush, '.githooks/pre-push must exist').toBeDefined();
		expect(prePush).toContain('gitleaks');
		expect(prePush).toContain('scripts/repo-safety/scan-push-range-sensitive-surface.mjs');
		expect(prePush).toContain('scripts/repo-safety/scan-sensitive-surface.mjs');
	});

	it('pre-commit and pre-push use full gitleaks redaction', () => {
		const prePush = hook('pre-push') ?? '';
		expect(preCommit).toContain('--redact=100');
		expect(prePush).toContain('--redact=100');
	});
});
