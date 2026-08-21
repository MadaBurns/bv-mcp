import { describe, expect, it } from 'vitest';
import { scanCommitMessage, scanFileContent, scanTextForSensitiveSurface, formatFindings } from '../../scripts/repo-safety/scanner-core.mjs';

const clientDomainPolicy = {
	forbiddenClientDomains: ['brand-eta.com', 'brand-beta.com.au', 'brand-kappa.com', 'brand-theta.com'],
};

describe('repo safety scanner helper', () => {
	it('flags BV key shapes without printing the raw key', () => {
		const secret = 'bv_' + 'Kx8eZ2rdtUPfdzR8e_JfSCIVZ_UsdLQn3NOqwICW0HA';
		const findings = scanTextForSensitiveSurface('src/example.ts', `const token = "${secret}";`);
		const output = formatFindings(findings);

		expect(findings.map((finding) => finding.ruleId)).toContain('blackveil-api-key');
		expect(output).not.toContain(secret);
		expect(output).toContain('src/example.ts:1');
		expect(output).toContain('blackveil-api-key');
	});

	it('flags private key headers without printing the raw header', () => {
		const header = '-----BEGIN PRIVATE KEY-----';
		const findings = scanTextForSensitiveSurface('fixtures/key.pem', `${header}\nredacted\n-----END PRIVATE KEY-----`);
		const output = formatFindings(findings);

		expect(findings.map((finding) => finding.ruleId)).toContain('private-key-header');
		expect(output).not.toContain(header);
	});

	it('flags real public IPv4 addresses while allowing documentation ranges', () => {
		expect(scanTextForSensitiveSurface('src/ip.ts', 'const host = "8.8.8.8";').map((finding) => finding.ruleId)).toContain(
			'public-ipv4',
		);
		expect(scanTextForSensitiveSurface('docs/example.md', 'Use 192.0.2.10 or 203.0.113.8 in examples.')).toEqual([]);
		expect(scanTextForSensitiveSurface('docs/example.md', 'Use private 10.0.0.10 and loopback 127.0.0.1.')).toEqual([]);
	});

	it('allows reserved fixture domains and placeholder emails', () => {
		expect(scanTextForSensitiveSurface('test/fixture.ts', 'admin@example.test scans tenant-001.example.test')).toEqual([]);
		expect(scanTextForSensitiveSurface('docs/fixture.md', 'contact@example.com is the RFC placeholder contact')).toEqual([]);
	});

	// GitHub writes these trailers into every squash merge it performs server-side,
	// which bypasses local hooks — so they only reach the scanner via a push range
	// that merged main, failing a push for history the developer did not author.
	it('allows GitHub-generated squash-merge trailer addresses', () => {
		const trailers = [
			'Signed-off-by: dependabot[bot] <support@github.com>',
			'Co-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>',
			'Co-authored-by: Blackveil <83378247+MadaBurns@users.noreply.github.com>',
		].join('\n');

		expect(scanCommitMessage(trailers).filter((finding) => finding.ruleId === 'real-email')).toEqual([]);
	});

	// The allowlist is exact-address/noreply-only, NOT the github.com domain — a real
	// github.com address in source must still be caught.
	it('still flags a non-trailer github.com address', () => {
		const findings = scanTextForSensitiveSurface('src/example.ts', 'const owner = "security@github.com";');
		expect(findings.map((finding) => finding.ruleId)).toContain('real-email');
	});

	it('flags real email addresses and customer/tenant markers', () => {
		const findings = scanTextForSensitiveSurface('docs/private.md', 'Customer Acme Corp uses admin@customer.invalid for tenant-pilot-1.');
		expect(findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining(['real-email', 'customer-marker', 'tenant-marker']));
	});

	it('flags real client benchmark domains that belong in private fixtures', () => {
		const findings = scanTextForSensitiveSurface(
			'src/example.ts',
			'const demoTargets = ["brand-kappa.com", "brand-eta.com", "brand-theta.com"];',
			clientDomainPolicy,
		);

		expect(findings.map((finding) => finding.ruleId)).toEqual(['client-domain', 'client-domain', 'client-domain']);
	});

	it('flags sensitive commit-message wording before public pushes', () => {
		const findings = scanCommitMessage(
			'Verified against brand-beta.com.au during a CSC pilot brands production audit.',
			clientDomainPolicy,
		);

		expect(findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining(['client-domain', 'client-context']));
	});

	it('flags Megalodon-style workflow injection indicators even when .github is otherwise allowlisted', () => {
		const workflow = [
			'name: build',
			'on: [push]',
			'jobs:',
			'  build:',
			'    runs-on: ubuntu-latest',
			'    steps:',
			'      - run: echo Q0I9Imh0dHA6Ly8yMTYu | base64 -d | bash',
			'        env:',
			'          BUILD_EMAIL: build-system@noreply.dev',
		].join('\n');
		const findings = scanFileContent('.github/workflows/build.yml', workflow, { allowedPathPrefixes: ['.github/'] });

		expect(findings.map((finding) => finding.ruleId)).toEqual(
			expect.arrayContaining(['github-actions-megalodon-indicator', 'github-actions-encoded-shell-exec']),
		);
	});

	it('flags remote shell installers in workflow files', () => {
		const findings = scanFileContent(
			'.github/workflows/ci.yml',
			'run: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh',
			{ allowedPathPrefixes: ['.github/'] },
		);

		expect(findings.map((finding) => finding.ruleId)).toContain('github-actions-remote-shell-exec');
	});
});
