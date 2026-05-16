import { describe, expect, it } from 'vitest';
import readme from '../../README.md?raw';
import contributing from '../../CONTRIBUTING.md?raw';
import claude from '../../CLAUDE.md?raw';
import scanOrchestrationInstructions from '../../.github/instructions/scan-orchestration.instructions.md?raw';
import license from '../../LICENSE?raw';
import packageJsonText from '../../package.json?raw';
import scoringConfig from '../../packages/dns-checks/src/scoring/config.ts?raw';

const packageJson = JSON.parse(packageJsonText) as { license?: string };

describe('BUSL positioning audit', () => {
	it('retains BUSL-1.1 package licensing', () => {
		expect(packageJson.license).toBe('BUSL-1.1');
		expect(license).toContain('Business Source License 1.1');
		expect(license).toContain('Change License:       MIT License');
	});

	it('does not market the current BUSL release as open source', () => {
		expect(readme).toContain('Source-available DNS & email security scanner');
		const checkedSources = {
			'README.md': readme,
			'CONTRIBUTING.md': contributing,
			'CLAUDE.md': claude,
			'.github/instructions/scan-orchestration.instructions.md': scanOrchestrationInstructions,
			'packages/dns-checks/src/scoring/config.ts': scoringConfig,
		};
		const offenders = Object.entries(checkedSources)
			.filter(([, source]) => /\bopen[- ]source\b/i.test(source))
			.map(([file]) => file);
		expect(offenders).toEqual([]);
	});
});
