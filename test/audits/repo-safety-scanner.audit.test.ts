import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
	BUILTIN_CLIENT_CONTEXT_PHRASES_SHA256,
	scanCommitMessage,
	scanFileContent,
	scanPathForForbiddenSurface,
	scanTextForSensitiveSurface,
	formatFindings,
} from '../../scripts/repo-safety/scanner-core.mjs';

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
		const findings = scanCommitMessage('Verified against brand-beta.com.au during a production audit.', clientDomainPolicy);

		expect(findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining(['client-domain', 'client-context']));
	});

	it('flags hashed client-context phrases without the plaintext living in the repo', () => {
		// The phrase is hashed at runtime here; in production the hash is built into
		// scanner-core.mjs so the commit-msg hook (which scans without policy.json)
		// still enforces it. Matching is case-insensitive and whitespace-normalised.
		const phrase = 'northwind rollout cohort';
		const hashedPolicy = { forbiddenClientContextPhrasesSha256: [createHash('sha256').update(phrase).digest('hex')] };
		const findings = scanCommitMessage('Verified during the   Northwind   ROLLOUT cohort walkthrough.', hashedPolicy);

		expect(findings.map((finding) => finding.ruleId)).toEqual(['client-context']);
		expect(findings[0].column).toBe('Verified during the   '.length + 1);
		expect(scanCommitMessage('Verified during the northwind rollout walkthrough.', hashedPolicy)).toEqual([]);
	});

	it('keeps the original client-context phrase gated by its built-in hash', () => {
		// SHA-256 of the lowercased, single-spaced original phrase. The plaintext
		// deliberately appears nowhere in the repo; verify by hashing it in a
		// scratch shell if this ever needs re-derivation.
		expect(BUILTIN_CLIENT_CONTEXT_PHRASES_SHA256).toContain('ef6b9b94f52b435a826c9558de024878508fb0b151ea98d387c8de54eb03f09a');
		for (const hash of BUILTIN_CLIENT_CONTEXT_PHRASES_SHA256) expect(hash).toMatch(/^[0-9a-f]{64}$/);
	});

	it('unions policy-supplied phrase hashes with the built-in list instead of replacing it', () => {
		const policyPhrase = 'northwind rollout cohort';
		const policy = { forbiddenClientContextPhrasesSha256: [createHash('sha256').update(policyPhrase).digest('hex')] };
		// A policy that supplies its own hashes must not disable the built-in gate:
		// probe with a synthetic phrase whose hash we splice into the built-in list.
		const builtinProbe = 'contoso pilot cohort';
		const builtinHash = createHash('sha256').update(builtinProbe).digest('hex');
		BUILTIN_CLIENT_CONTEXT_PHRASES_SHA256.push(builtinHash);
		try {
			expect(scanCommitMessage(`note: ${builtinProbe} and ${policyPhrase}`, policy).map((finding) => finding.ruleId)).toEqual([
				'client-context',
				'client-context',
			]);
		} finally {
			BUILTIN_CLIENT_CONTEXT_PHRASES_SHA256.splice(BUILTIN_CLIENT_CONTEXT_PHRASES_SHA256.indexOf(builtinHash), 1);
		}
	});

	it('forbids promoted brand-report pairs by output shape in any directory', () => {
		const policy = { forbiddenPaths: ['.client-reports/', '*-discovery-report.json', '*-discovery-report.pdf', '*.pdf'] };
		expect(scanPathForForbiddenSurface('.some-local-dir/example.com-discovery-report.json', policy).map((f) => f.detail)).toEqual([
			'*-discovery-report.json',
		]);
		expect(scanPathForForbiddenSurface('.client-reports/notes.md', policy).map((f) => f.detail)).toEqual(['.client-reports/']);
		expect(scanPathForForbiddenSurface('src/tools/discovery-report.ts', policy)).toEqual([]);
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
