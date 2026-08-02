// SPDX-License-Identifier: BUSL-1.1

/**
 * Wiring guard: the marker the `ns` check EMITS and the marker the scoring gate READS
 * must be the same thing.
 *
 * The non-resolving gate's derived floor works by reading a structured metadata key off
 * the `ns` check\'s own no-NS-and-no-A determination. Those two live in different modules
 * (`checks/ns-analysis.ts` and `scoring/resolution.ts`), and nothing in the type system
 * couples them: if the check stops emitting the key, or renames it, the gate does not
 * break loudly — it silently stops firing and dead domains start scoring again. That is
 * the precise failure mode this whole change exists to remove, so it gets a test that
 * fails instead.
 */

import { describe, it, expect } from 'vitest';
import { getNsVisibilityFinding } from '../../checks/ns-analysis';
import { deriveResolutionState, DOMAIN_RESOLVES_METADATA_KEY } from '../../scoring/resolution';
import { buildCheckResult } from '../../check-utils';

describe('non-resolving guard wiring', () => {
	it('the ns check emits the structured marker when the domain does not resolve', () => {
		const finding = getNsVisibilityFinding('example.invalid', false);
		expect(finding.metadata?.[DOMAIN_RESOLVES_METADATA_KEY]).toBe(false);
	});

	it('the scoring gate DERIVES non-resolution from that exact finding, unmodified', () => {
		// End-to-end tie: the real emitter\'s output fed to the real reader, with no hand-built
		// fixture in between — a fixture is what lets the two drift apart unnoticed.
		const finding = getNsVisibilityFinding('example.invalid', false);
		expect(deriveResolutionState([buildCheckResult('ns', [finding])])).toBe('unresolvable');
	});

	it('DISCRIMINATES: the resolving branch emits no such marker and does not trigger the gate', () => {
		// `domainResolves: true` is the "NS not directly visible, but the domain resolves"
		// case (delegation-only zones like govt.nz). It must never read as non-resolution.
		const finding = getNsVisibilityFinding('example.invalid', true);
		expect(finding.metadata?.[DOMAIN_RESOLVES_METADATA_KEY]).not.toBe(false);
		expect(deriveResolutionState([buildCheckResult('ns', [finding])])).toBeUndefined();
	});
});
