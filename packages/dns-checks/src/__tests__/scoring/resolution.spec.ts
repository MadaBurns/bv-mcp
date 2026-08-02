// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import {
	buildUnresolvableNote,
	deriveResolutionState,
	isMeasurableDomain,
	normalizeResolutionSignal,
	resolveScanResolutionState,
	DOMAIN_RESOLVES_METADATA_KEY,
} from '../../scoring/resolution';
import { buildCheckResult, createFinding } from '../../check-utils';
import type { CheckResult } from '../../types';

/** An `ns` result carrying the check's own non-resolution determination. */
function nsNonResolving(checkStatus?: 'timeout' | 'error'): CheckResult {
	const result = buildCheckResult('ns', [
		createFinding('ns', 'No NS records found', 'critical', 'Without NS records, the domain cannot resolve.', {
			missingControl: true,
			[DOMAIN_RESOLVES_METADATA_KEY]: false,
		}),
	]);
	return checkStatus ? { ...result, checkStatus } : result;
}

describe('normalizeResolutionSignal', () => {
	it('accepts the orchestrator tri-state verbatim', () => {
		// bv-mcp's ScanDomainResult.resolves is `boolean | 'broken'`. Accepting it without a
		// mapping layer is deliberate: a mapping layer is one more place to forget.
		expect(normalizeResolutionSignal(true)).toBe('resolves');
		expect(normalizeResolutionSignal(false)).toBe('nxdomain');
		expect(normalizeResolutionSignal('broken')).toBe('unresolvable');
	});

	it('accepts the package-native spellings', () => {
		expect(normalizeResolutionSignal('resolves')).toBe('resolves');
		expect(normalizeResolutionSignal('nxdomain')).toBe('nxdomain');
		expect(normalizeResolutionSignal('unresolvable')).toBe('unresolvable');
	});

	it('treats a missing signal as UNKNOWN, not as a claim that the domain resolves', () => {
		expect(normalizeResolutionSignal(undefined)).toBeUndefined();
	});

	it('treats an out-of-union value as unknown rather than asserting health', () => {
		// A version-skewed producer or an unvalidated cache re-read can supply a string
		// outside the union. Falling through to the derived floor is safe; silently
		// reading it as "resolves" would disable the guard.
		expect(normalizeResolutionSignal('yes' as never)).toBeUndefined();
		expect(normalizeResolutionSignal(1 as never)).toBeUndefined();
	});
});

describe('deriveResolutionState', () => {
	it('reads the ns check structured marker', () => {
		expect(deriveResolutionState([nsNonResolving()])).toBe('unresolvable');
	});

	it('never claims NXDOMAIN — this evidence cannot distinguish absent from broken', () => {
		expect(deriveResolutionState([nsNonResolving()])).not.toBe('nxdomain');
	});

	it('ignores the marker on an UNMEASURED ns check (inconclusive is not proof)', () => {
		// "The failure earns the exemption" in reverse: an errored check must not be able to
		// assert a fact either.
		expect(deriveResolutionState([nsNonResolving('error')])).toBeUndefined();
		expect(deriveResolutionState([nsNonResolving('timeout')])).toBeUndefined();
	});

	it('returns unknown for a roster with no ns check — a coverage gap is not health', () => {
		expect(deriveResolutionState([buildCheckResult('spf', [])])).toBeUndefined();
		expect(deriveResolutionState([])).toBeUndefined();
	});

	it('does not fire for an ns check that found nameservers', () => {
		const healthy = buildCheckResult('ns', [createFinding('ns', 'Nameservers properly configured', 'info', '2 found')]);
		expect(deriveResolutionState([healthy])).toBeUndefined();
	});

	it('is not vetoed by positive evidence from another check', () => {
		// The located incident: the dead domain's `ssl` carried controlPresent:true because a
		// parking origin answered on the HTTPS path, while the name itself was NXDOMAIN. A
		// DNS-level determination outranks an HTTP-level observation.
		const sslPresent = buildCheckResult('ssl', [createFinding('ssl', 'HTTPS reachable', 'info', 'ok')], true);
		expect(deriveResolutionState([nsNonResolving(), sslPresent])).toBe('unresolvable');
	});
});

describe('resolveScanResolutionState', () => {
	it('prefers the explicit signal over the derived floor', () => {
		expect(resolveScanResolutionState([nsNonResolving()], true)).toBe('resolves');
	});

	it('falls back to the derived floor when no signal is supplied', () => {
		expect(resolveScanResolutionState([nsNonResolving()], undefined)).toBe('unresolvable');
	});
});

describe('isMeasurableDomain', () => {
	it('treats unknown as measurable (fail-open) but both failure states as not', () => {
		expect(isMeasurableDomain(undefined)).toBe(true);
		expect(isMeasurableDomain('resolves')).toBe(true);
		expect(isMeasurableDomain('nxdomain')).toBe(false);
		expect(isMeasurableDomain('unresolvable')).toBe(false);
	});
});

describe('buildUnresolvableNote', () => {
	it('frames both states as a measurement gap, never a security verdict', () => {
		for (const state of ['nxdomain', 'unresolvable'] as const) {
			const note = buildUnresolvableNote(state);
			expect(note).toMatch(/not a security verdict/i);
			expect(note).not.toMatch(/Grade: [A-F]/);
		}
	});

	it('names the distinct causes so a report can explain which one applies', () => {
		expect(buildUnresolvableNote('nxdomain')).toMatch(/NXDOMAIN/);
		expect(buildUnresolvableNote('unresolvable')).toMatch(/nameservers/i);
	});
});
