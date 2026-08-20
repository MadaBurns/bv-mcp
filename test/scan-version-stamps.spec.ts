import { describe, expect, it } from 'vitest';
import { buildStructuredScanResult, formatScanReport } from '../src/tools/scan/format-report';
import { batchScan, compactBatchScanResults } from '../src/tools/batch-scan';
import type { ScanDomainResult } from '../src/tools/scan-domain';
import { SCORING_MODEL_VERSION } from '../src/lib/scoring-version';
import { DNS_CHECKS_PACKAGE_VERSION } from '../src/lib/dns-checks-version';
// The engine package's own manifest — the ultimate source of truth for its version,
// and deliberately a DIFFERENT file from anything the production code reads. Anchoring
// the assertions here is what makes this spec fail on drift instead of tautologically
// re-asserting whatever constant the code happens to import.
import dnsChecksManifest from '../packages/dns-checks/package.json';

/**
 * Issue #707 — `scan_domain`/`batch_scan` stamped only `scoringModelVersion`, a
 * semver-shaped value in the same numeric range as the `@blackveil/dns-checks`
 * package version. Twice (2026-08-12: package 1.15.0 vs model 1.8.0; 2026-08-19:
 * package 1.18.0 vs model 1.10.0) a consuming project read one as the other and
 * opened a false "engine version gap" investigation. Both namespaces are now
 * emitted side by side.
 *
 * These assertions read each version from ITS OWN source, so wiring
 * `dnsChecksPackageVersion` to `SCORING_MODEL_VERSION` (or vice versa) fails here.
 * No literal version numbers appear in this file — it must not need editing on a
 * release.
 */
function nonResolvingResult(domain: string): ScanDomainResult {
	return {
		domain,
		score: {
			overall: null,
			grade: null,
			categoryScores: {} as ScanDomainResult['score']['categoryScores'],
			findings: [],
			summary: `${domain} does not resolve (NXDOMAIN).`,
			evidence: { attempted: 0, completed: 0, ratio: 0 },
		},
		checks: [],
		maturity: { stage: 0, label: 'Does not resolve', description: 'no posture', nextStep: 'Confirm the domain is registered.' },
		context: { profile: 'mail_enabled', signals: [], weights: {} as never, detectedProvider: null },
		cached: false,
		timestamp: '2026-08-20T00:00:00.000Z',
		scoringNote: null,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
		resolves: false,
	};
}

describe('scan version stamps (#707)', () => {
	it('sources dnsChecksPackageVersion from the engine package manifest, not from a worker-side literal', () => {
		expect(DNS_CHECKS_PACKAGE_VERSION).toBe(dnsChecksManifest.version);
	});

	it('emits BOTH version stamps on a structured scan result, each from its own source', () => {
		const structured = buildStructuredScanResult(nonResolvingResult('example.invalid'));

		// Scoring POLICY semver — lib/scoring-version.ts.
		expect(structured.scoringModelVersion).toBe(SCORING_MODEL_VERSION);
		// Engine PACKAGE semver — @blackveil/dns-checks' own manifest.
		expect(structured.dnsChecksPackageVersion).toBe(dnsChecksManifest.version);
		// And the reproducibility anchor consumers should actually record.
		expect(structured.scoringConfigHash).toEqual(expect.any(String));
	});

	it('keeps the two stamps distinct whenever their sources are distinct', () => {
		// Guard against the specific regression the issue describes: someone wiring the
		// new field to `SCORING_MODEL_VERSION`, which would make both stamps agree while
		// the two upstream sources disagree. Conditional (never flaky) — if the policy
		// version and the package version ever legitimately coincide, this leg simply
		// cannot discriminate and stands down; the two assertions above still hold.
		if (SCORING_MODEL_VERSION !== dnsChecksManifest.version) {
			const structured = buildStructuredScanResult(nonResolvingResult('example.invalid'));
			expect(structured.dnsChecksPackageVersion).not.toBe(structured.scoringModelVersion);
		}
	});

	it('names both stamps, labelled by what they track, in the full-format report prose', () => {
		const report = formatScanReport(nonResolvingResult('example.invalid'), 'full');
		expect(report).toContain(`Scoring model: v${SCORING_MODEL_VERSION}`);
		expect(report).toContain(`dns-checks package: v${dnsChecksManifest.version}`);
	});

	it('carries both stamps on a batch_scan error placeholder and on the compact batch payload', async () => {
		// An invalid domain never reaches the network: `batchScan` short-circuits to its
		// `emptyResult` placeholder, the other producer of these fields.
		const results = await batchScan(['not a domain!!']);
		expect(results).toHaveLength(1);
		expect(results[0].error).toBeDefined();
		expect(results[0].scoringModelVersion).toBe(SCORING_MODEL_VERSION);
		expect(results[0].dnsChecksPackageVersion).toBe(dnsChecksManifest.version);

		// The compact payload hoists the stamps once per batch rather than repeating them.
		const compact = compactBatchScanResults(results);
		expect(compact.scoringModelVersion).toBe(SCORING_MODEL_VERSION);
		expect(compact.dnsChecksPackageVersion).toBe(dnsChecksManifest.version);

		// Fallback branch: an empty batch has no item to hoist from and must still stamp
		// the two versions from their own sources.
		const empty = compactBatchScanResults([]);
		expect(empty.scoringModelVersion).toBe(SCORING_MODEL_VERSION);
		expect(empty.dnsChecksPackageVersion).toBe(dnsChecksManifest.version);
	});
});
