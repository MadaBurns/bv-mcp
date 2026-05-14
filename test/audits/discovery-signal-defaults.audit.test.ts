// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: per-signal default confidences must match the values their modules
 * actually emit. A drift between the orchestrator's fallback and the module's
 * supplied value is a code smell — readers see one number, runtime uses
 * another. Pre-Slice-5 this surfaced as `dmarc_rua: 0.8` while the miner
 * always supplied `0.6`.
 *
 * Ref: v2.14.0 audit, LR-5 (dead constant).
 */

import { describe, it, expect } from 'vitest';
import { DEFAULT_SIGNAL_CONFIDENCE } from '../../src/tools/discover-brand-domains';

describe('DEFAULT_SIGNAL_CONFIDENCE matches module-emitted values', () => {
	it('dmarc_rua default equals the miner-emitted `related` confidence (0.6)', () => {
		// dmarc-rua-miner.ts emits `confidence: 0.6` for classification='related'
		// (the only case that reaches the orchestrator's addObservation path).
		// The DEFAULT here is never actually used at runtime, so it must
		// document the truth rather than mislead.
		expect(DEFAULT_SIGNAL_CONFIDENCE.dmarc_rua).toBe(0.6);
	});
});
