// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit test (T7 / Task 7 Step 4): no silent drops.
 *
 * Every candidate that enters `discoverBrandDomains`' aggregator and does NOT
 * surface as a finding MUST be accounted for under a structured drop reason
 * from the closed `DiscoveryDropReason` enum. Adding a new drop site without
 * extending the enum fails this audit.
 */

import { describe, it, expect } from 'vitest';
import { DISCOVERY_DROP_REASONS, type DiscoveryDropReason } from '../../src/tools/discover-brand-domains';

const CANONICAL_DROP_REASONS = [
	'cap',
	'seedOrSubdomain',
	'infrastructureProvider',
	'corroborationGate',
	'belowConfidence',
	'optOutRedacted',
] as const satisfies readonly DiscoveryDropReason[];

describe('brand-discovery drop-reasons audit (closed enum)', () => {
	it('exports the canonical drop-reasons enum', () => {
		expect(DISCOVERY_DROP_REASONS.slice().sort()).toEqual(CANONICAL_DROP_REASONS.slice().sort());
	});

	it('source code records every drop site under a canonical reason', async () => {
		const source = (
			await import('../../src/tools/discover-brand-domains.ts?raw')
		).default as string;
		const referencedReasons = new Set<string>();
		const regex = /dropCounts\.([A-Za-z_][A-Za-z0-9_]*)/g;
		let match: RegExpExecArray | null;
		while ((match = regex.exec(source)) !== null) {
			referencedReasons.add(match[1]);
		}
		const offenders = Array.from(referencedReasons).filter(
			(reason) => !CANONICAL_DROP_REASONS.includes(reason as DiscoveryDropReason),
		);
		expect(
			offenders,
			`Drop-counter property referenced in source that is not in the canonical DiscoveryDropReason enum: ${offenders.join(', ')}.`,
		).toEqual([]);
	});
});
