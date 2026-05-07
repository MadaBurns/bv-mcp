// Audit tests for the fuzzing-detection feature.
//
// Per testing-methodology.md principle 4: "Audit tests replace review checklists."
// These invariants would otherwise need to be remembered at every PR.
//
// Runs in the Cloudflare Workers test pool, so we use Vite's `?raw` source-file
// imports rather than node:fs (which the Workers runtime doesn't expose).

import { describe, it, expect } from 'vitest';
import { FUZZ_THRESHOLDS } from '../../src/lib/config';
import { FuzzingAlertSchema } from '../../src/schemas/alerting';
import detectorSource from '../../src/lib/fuzzing-detector.ts?raw';
import counterSource from '../../src/lib/fuzzing-counter.ts?raw';
import alertingSource from '../../src/schemas/alerting.ts?raw';

describe('fuzzing-config audit', () => {
	it('FUZZ_THRESHOLDS has all four kinds + windowSeconds and is the single source of truth', () => {
		expect(FUZZ_THRESHOLDS).toMatchObject({
			windowSeconds: expect.any(Number),
			unknown_tool: expect.any(Number),
			unknown_method: expect.any(Number),
			zod_arg: expect.any(Number),
			auth_fail: expect.any(Number),
		});
	});

	// Lock the exact numeric values so any drift (loosening or unannounced
	// tightening) requires an explicit audit-test update + PR review note.
	// Per CLAUDE.md: "v1 defaults are 3× the plan values to stay silent for one
	// week of baseline collection before lowering."
	it('FUZZ_THRESHOLDS values match the locked v1 baseline', () => {
		expect(FUZZ_THRESHOLDS).toEqual({
			windowSeconds: 60,
			unknown_tool: 30,
			unknown_method: 15,
			zod_arg: 60,
			auth_fail: 90,
		});
	});

	it('detector + counter + alerting modules do not redeclare FUZZ_THRESHOLDS', () => {
		// `const FUZZ_THRESHOLDS = ...` would be the offending shape; importing the
		// type or the value from config.ts is fine (we're only forbidding redeclaration).
		for (const [name, source] of [
			['fuzzing-detector.ts', detectorSource],
			['fuzzing-counter.ts', counterSource],
			['alerting.ts', alertingSource],
		] as const) {
			expect(/const\s+FUZZ_THRESHOLDS\s*=/.test(source), `${name} must not redeclare FUZZ_THRESHOLDS`).toBe(false);
		}
	});

	it('FuzzingAlertSchema kind enum accepts every member of the FuzzKind union plus "mixed"', () => {
		// Parse the union literal text from the detector source so the audit catches
		// "added a new kind but forgot to update the schema" drift directly.
		const unionMatch = detectorSource.match(/export type FuzzKind\s*=\s*([^;]+);/);
		expect(unionMatch, 'FuzzKind union literal must exist').toBeTruthy();
		const kinds = unionMatch![1]
			.split('|')
			.map((s) => s.trim().replace(/^['"`]|['"`]$/g, ''))
			.filter(Boolean);

		for (const k of [...kinds, 'mixed']) {
			const candidate = {
				type: 'fuzzing_suspected',
				principalKind: 'ip',
				principalIdHash: '0123456789abcdef',
				kind: k,
				count: 1,
				windowSeconds: 60,
				observedAt: '2026-05-07T00:00:00.000Z',
			};
			expect(() => FuzzingAlertSchema.parse(candidate), `kind=${k} must parse against the schema`).not.toThrow();
		}
	});
});
