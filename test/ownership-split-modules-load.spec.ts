// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';

// Each ownership/ leaf module must load on its own (fresh module graph) without
// reading a not-yet-initialised binding across an import cycle (TDZ at Worker
// start-up), and the original path must keep re-exporting the same bindings.
describe('ownership-attribution split modules load', () => {
	it('loads ownership/types on its own', async () => {
		vi.resetModules();
		const mod = await import('../src/lib/ownership/types');
		expect(mod.MIN_ATTRIBUTION_LABEL_LENGTH).toBeDefined();
	});

	it('loads ownership/hosts on its own', async () => {
		vi.resetModules();
		const mod = await import('../src/lib/ownership/hosts');
		expect(mod.isInBailiwick).toBeDefined();
	});

	it('loads ownership/seed-matching on its own', async () => {
		vi.resetModules();
		const mod = await import('../src/lib/ownership/seed-matching');
		expect(mod.seedInfrastructureMatch).toBeDefined();
	});

	it('loads ownership/gate on its own', async () => {
		vi.resetModules();
		const mod = await import('../src/lib/ownership/gate');
		expect(mod.capAttributionSeverity).toBeDefined();
	});

	it('loads the ownership-attribution barrel on its own and keeps classifyOwnership', async () => {
		vi.resetModules();
		const mod = await import('../src/lib/ownership-attribution');
		expect(mod.classifyOwnership).toBeDefined();
	});

	it('re-exports the leaf bindings from the original path (same identity)', async () => {
		vi.resetModules();
		const barrel = await import('../src/lib/ownership-attribution');
		const hosts = await import('../src/lib/ownership/hosts');
		const seed = await import('../src/lib/ownership/seed-matching');
		const gate = await import('../src/lib/ownership/gate');
		const types = await import('../src/lib/ownership/types');
		expect(barrel.isInBailiwick).toBe(hosts.isInBailiwick);
		expect(barrel.PROVIDER_CUSTOMER_NS_NAMESPACES).toBe(hosts.PROVIDER_CUSTOMER_NS_NAMESPACES);
		expect(barrel.seedLabelCohortMatch).toBe(seed.seedLabelCohortMatch);
		expect(barrel.DMARC_REPORT_PROCESSOR_APEXES).toBe(seed.DMARC_REPORT_PROCESSOR_APEXES);
		expect(barrel.buildNonOwnedGateFinding).toBe(gate.buildNonOwnedGateFinding);
		expect(barrel.MIN_LABEL_COHORT_SIBLINGS).toBe(types.MIN_LABEL_COHORT_SIBLINGS);
	});
});
