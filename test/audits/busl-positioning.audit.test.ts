import { describe, expect, it } from 'vitest';
import readme from '../../README.md?raw';
import contributing from '../../CONTRIBUTING.md?raw';
import claude from '../../CLAUDE.md?raw';
import agents from '../../AGENTS.md?raw';
import scanOrchestrationInstructions from '../../.github/instructions/scan-orchestration.instructions.md?raw';
import license from '../../LICENSE?raw';
import dnsChecksLicense from '../../packages/dns-checks/LICENSE?raw';
import vscodeLicense from '../../extensions/vscode/LICENSE?raw';
import packageJsonText from '../../package.json?raw';
import dnsChecksPackageJsonText from '../../packages/dns-checks/package.json?raw';
import bvWhoisPackageJsonText from '../../packages/bv-whois/package.json?raw';
import vscodePackageJsonText from '../../extensions/vscode/package.json?raw';
import dnsChecksReadme from '../../packages/dns-checks/README.md?raw';
import scoringConfig from '../../packages/dns-checks/src/scoring/config.ts?raw';

const packageJson = JSON.parse(packageJsonText) as { license?: string };

// Every hand-authored package manifest in the workspace, keyed by path for
// legible failure output.
const WORKSPACE_MANIFESTS: Record<string, string> = {
	'package.json': packageJsonText,
	'packages/dns-checks/package.json': dnsChecksPackageJsonText,
	'packages/bv-whois/package.json': bvWhoisPackageJsonText,
	'extensions/vscode/package.json': vscodePackageJsonText,
};

// The canonical copyright line. All three LICENSE files and every source
// header must agree on this exact holder + range (drift guard).
const CANONICAL_COPYRIGHT = '(c) 2023-2026 BLACKVEIL Security';

describe('BUSL positioning audit', () => {
	it('retains BUSL-1.1 package licensing', () => {
		expect(packageJson.license).toBe('BUSL-1.1');
		expect(license).toContain('Business Source License 1.1');
		expect(license).toContain('Change License:       MIT License');
	});

	it('declares BUSL-1.1 in every workspace package manifest', () => {
		const offenders = Object.entries(WORKSPACE_MANIFESTS)
			.filter(([, text]) => (JSON.parse(text) as { license?: string }).license !== 'BUSL-1.1')
			.map(([path]) => path);
		expect(offenders).toEqual([]);
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

	it('keeps all three LICENSE files byte-identical', () => {
		// Divergent LICENSE text (stale version pins, mismatched copyright years)
		// is the exact drift this guard exists to catch. One canonical grant.
		expect(dnsChecksLicense).toBe(license);
		expect(vscodeLicense).toBe(license);
	});

	it('pins no package version and uses the canonical copyright in LICENSE', () => {
		// A hardcoded "Blackveil DNS vX.Y.Z" goes stale on every release.
		expect(license).not.toMatch(/Blackveil DNS v\d+\.\d+\.\d+/i);
		expect(license).toContain(CANONICAL_COPYRIGHT);
	});

	it('names the copyright holder consistently (no "Ltd." drift)', () => {
		const checked = {
			'LICENSE': license,
			'packages/dns-checks/LICENSE': dnsChecksLicense,
			'extensions/vscode/LICENSE': vscodeLicense,
			'packages/dns-checks/README.md': dnsChecksReadme,
		};
		const offenders = Object.entries(checked)
			.filter(([, text]) => /BlackVeil Security Ltd\.?/i.test(text))
			.map(([file]) => file);
		expect(offenders).toEqual([]);
	});

	it('uses the canonical "BUSL-1.1" abbreviation, never "BSL", when naming the license', () => {
		// "BSL self-host" (deployment idiom) is fine; naming the LICENSE "BSL 1.1"
		// is not — SPDX only recognises BUSL-1.1.
		const dnsChecksReadmeLicenseNaming = /\bBSL[- ]?1\.1\b/i.test(dnsChecksReadme);
		expect(dnsChecksReadmeLicenseNaming, 'packages/dns-checks/README.md names the license "BSL 1.1"').toBe(false);
		expect(/\bthe license is BSL\b/i.test(agents), 'AGENTS.md names the license "BSL"').toBe(false);
		expect(agents).toMatch(/BUSL-1\.1/);
	});

	it('documents the BUSL Change Date + non-commercial grant in the dns-checks README', () => {
		expect(dnsChecksReadme).toMatch(/BUSL-1\.1/);
		expect(dnsChecksReadme).toContain('2030-03-17');
		expect(dnsChecksReadme).toMatch(/non-commercial/i);
	});
});
