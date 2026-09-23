import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
	BUILTIN_CLIENT_CONTEXT_PHRASES_SHA256,
	BUILTIN_TENANT_MARKERS_SHA256,
	containsTenantMarker,
	CLIENT_RULE_SELF_TEST_PATHS,
	scanCommitMessage,
	scanFileContent,
	scanPathForClientDomainSurface,
	scanPathForForbiddenSurface,
	scanTextForSensitiveSurface,
	formatFindings,
} from '../../scripts/repo-safety/scanner-core.mjs';

const clientDomainPolicy = {
	forbiddenClientDomains: ['brand-eta.com', 'brand-beta.com.au', 'brand-kappa.com', 'brand-theta.com'],
};

// A domain that is not a real client of ours, used only to prove the gate-bypass
// mechanics without putting any real client domain in this repo. Injected as a
// SHA-256 hash, same as production `forbiddenClientDomainsSha256` entries.
const SYNTHETIC_DOMAIN = 'synthetic-client.test';
const syntheticDomainHash = createHash('sha256').update(SYNTHETIC_DOMAIN).digest('hex');
const syntheticDomainPolicy = { forbiddenClientDomainsSha256: [syntheticDomainHash] };

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
		const findings = scanTextForSensitiveSurface('docs/private.md', 'Customer Acme Corp uses admin@customer.invalid for tenant-pilot-7.');
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
		const phrase = 'contoso pilot cohort';
		const policy = { ...clientDomainPolicy, forbiddenClientContextPhrasesSha256: [createHash('sha256').update(phrase).digest('hex')] };
		const findings = scanCommitMessage(`Verified against brand-beta.com.au during a ${phrase}.`, policy);

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

	// The 2026-09 history rewrite replaced the plaintext tenant markers and three
	// client-context phrases with placeholders, which broke the scanner's regexes.
	// They are now matched by hash; these tests pin that mechanism with synthetic
	// values spliced into the built-in lists, never the real ones.
	it('keeps the rewritten tenant markers and context phrases gated by their built-in hashes', () => {
		expect(BUILTIN_TENANT_MARKERS_SHA256).toHaveLength(3);
		expect(BUILTIN_CLIENT_CONTEXT_PHRASES_SHA256).toEqual(
			expect.arrayContaining([
				'7b7c3036e1e205272ccbad0b074810ab4f6337c49edaa7f85a707f066e65ac81',
				'bb6db9412fb5f91edb31e6be5dbf08e8b49aece55c72529122f78d33ee949c06',
				'792d2b227b53c09bb9a55bf33f4364e633d856deb737e0e8c7f2a5554e65bdac',
			]),
		);
		for (const hash of BUILTIN_TENANT_MARKERS_SHA256) expect(hash).toMatch(/^[0-9a-f]{64}$/);
	});

	it('flags a hashed tenant marker as a whole token, inside a hyphenated token, and as a hyphen-ending prefix', () => {
		const marker = 'fabrikam-pod';
		const prefixMarker = 'fabrikam-db-';
		const added = [marker, prefixMarker].map((value) => createHash('sha256').update(value).digest('hex'));
		BUILTIN_TENANT_MARKERS_SHA256.push(...added);
		try {
			const rules = (text: string, file = 'docs/private.md') => scanTextForSensitiveSurface(file, text).map((finding) => finding.ruleId);
			expect(rules('routed to fabrikam-pod today')).toEqual(['tenant-marker']);
			expect(rules('routed to FABRIKAM-POD-2 today')).toEqual(['tenant-marker']);
			expect(rules('routed to east-fabrikam-pod today')).toEqual(['tenant-marker']);
			expect(rules('created fabrikam-db-7')).toEqual(['tenant-marker']);
			expect(rules('the fabrikam pod rollout')).toEqual([]);
			expect(rules('routed to fabrikam-pod today', 'test/fixture.ts')).toEqual(['tenant-marker']);
			expect(containsTenantMarker('line one\ncreated fabrikam-db-7')).toBe(true);
			expect(containsTenantMarker('the fabrikam pod rollout')).toBe(false);
		} finally {
			BUILTIN_TENANT_MARKERS_SHA256.splice(-added.length, added.length);
		}
	});

	it('flags a hashed client-context phrase glued to a neighbour by a hyphen, once per occurrence', () => {
		const phrase = 'northwind rollout';
		const policy = { forbiddenClientContextPhrasesSha256: [createHash('sha256').update(phrase).digest('hex')] };
		const rules = (text: string) => scanCommitMessage(text, policy).map((finding) => finding.ruleId);
		expect(rules('during the northwind rollout-2 review')).toEqual(['client-context']);
		expect(rules('during the pre-northwind rollout review')).toEqual(['client-context']);
		expect(rules('during the northwind rollout review')).toEqual(['client-context']);
		expect(rules('during the northwind-rollout review')).toEqual([]);
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

	describe('client-domain and client-context bypass allowedPaths/allowedPathPrefixes', () => {
		it('flags a hashed client domain inside test/ content even though test/ is an allowed path prefix', () => {
			const findings = scanTextForSensitiveSurface(
				'test/foo.spec.ts',
				`const target = "${SYNTHETIC_DOMAIN}";`,
				{ ...syntheticDomainPolicy, allowedPathPrefixes: ['test/'] },
			);

			expect(findings.map((finding) => finding.ruleId)).toContain('client-domain');
		});

		it('flags a hashed client domain inside an allowedPaths file (CHANGELOG.md)', () => {
			const findings = scanTextForSensitiveSurface(
				'CHANGELOG.md',
				`Investigated the ${SYNTHETIC_DOMAIN} incident.`,
				{ ...syntheticDomainPolicy, allowedPaths: ['CHANGELOG.md'] },
			);

			expect(findings.map((finding) => finding.ruleId)).toContain('client-domain');
		});

		it('still allows fixture IPs/emails under an allowed test/ prefix (other rules keep old semantics)', () => {
			// Same content would trip real-email + public-ipv4 outside an allowed path
			// (fixture.example is not in allowedEmailDomains, 8.8.8.8 is a real public IP).
			const findings = scanTextForSensitiveSurface(
				'test/fixture-real.spec.ts',
				'Contact ops@fixture.example about the probe at 8.8.8.8.',
				{ allowedPathPrefixes: ['test/'] },
			);

			expect(findings).toEqual([]);
		});

		it('flags a client domain hidden in a dash-joined filename regardless of allowedPaths', () => {
			const path = 'test/fixtures/x/synthetic-client-test-fast.golden.json';
			const findings = scanPathForClientDomainSurface(path, { ...syntheticDomainPolicy, allowedPathPrefixes: ['test/'] });

			expect(findings.map((finding) => finding.ruleId)).toEqual(['client-domain']);
		});

		it('flags a client domain hidden in a dotted filename segment regardless of allowedPaths', () => {
			const path = `test/fixtures/x/${SYNTHETIC_DOMAIN}.notes.md`;
			const findings = scanPathForClientDomainSurface(path, { ...syntheticDomainPolicy, allowedPathPrefixes: ['test/'] });

			expect(findings.map((finding) => finding.ruleId)).toEqual(['client-domain']);
		});

		it('does not flag an ordinary hyphenated filename with no matching hashed domain', () => {
			const findings = scanPathForClientDomainSurface('src/tools/check-subdomain-takeover.ts', syntheticDomainPolicy);
			expect(findings).toEqual([]);
		});

		it('keeps a filename-level client-domain finding free of the plaintext domain', () => {
			const path = `test/fixtures/x/${SYNTHETIC_DOMAIN}.notes.md`;
			const findings = scanPathForClientDomainSurface(path, syntheticDomainPolicy);
			const output = formatFindings(findings);

			// The path itself (which the caller already has) still appears via `file`,
			// but no extra field (e.g. `detail`) may carry the matched domain string.
			expect(findings[0]).not.toHaveProperty('detail');
			expect(output).toContain('client-domain');
		});

		it('exempts exactly the two self-test files from the client-context hashed-phrase rule', () => {
			const phrase = 'contoso rollout waypoint';
			const hash = createHash('sha256').update(phrase).digest('hex');
			const policy = { forbiddenClientContextPhrasesSha256: [hash] };

			for (const file of CLIENT_RULE_SELF_TEST_PATHS) {
				const findings = scanTextForSensitiveSurface(file, `Notes: ${phrase} recap.`, policy);
				expect(findings.map((finding) => finding.ruleId)).not.toContain('client-context');
			}

			// Sanity: the same hashed phrase is still caught everywhere else.
			const elsewhere = scanTextForSensitiveSurface('docs/other.md', `Notes: ${phrase} recap.`, policy);
			expect(elsewhere.map((finding) => finding.ruleId)).toContain('client-context');
		});
	});
});
