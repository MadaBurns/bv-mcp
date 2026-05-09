// SPDX-License-Identifier: BUSL-1.1

/**
 * Contract test for the tenant cycle-diff alert webhook payload.
 *
 * The Zod schema in src/schemas/tenant-alerts.ts is the inter-service contract
 * between the worker (producer = `computeCycleDiff`) and the Slack/Discord
 * webhook (consumer). This test asserts:
 *   - producer-consumer alignment: real diff output parses against the schema
 *   - severity enum exhaustiveness across the 5 levels
 *   - .passthrough() forward-compat: future fields do NOT break parsing
 *
 * Schema unit tests live in test/schemas/tenant-alerts.test.ts; diff logic tests
 * live in test/tenants/alerts/diff.test.ts. This file deliberately re-asserts
 * neither — its job is the wire shape.
 */

import { describe, it, expect } from 'vitest';
import { computeCycleDiff, type FindingRow, type ComputeCycleDiffOptions } from '../../src/tenants/alerts/diff';
import {
	TenantCycleAlertSchema,
	TENANT_SEVERITY_LEVELS,
	type TenantSeverity,
} from '../../src/schemas/tenant-alerts';

const opts: ComputeCycleDiffOptions = {
	currentCycleId: 'cyc-current',
	baselineCycleId: 'cyc-prior',
	superTenantId: 'super-acme',
	subTenantId: 'sub-prod',
	domainsScanned: 5,
	scanAt: 1_715_000_000_000,
	emittedAt: 1_715_000_001_000,
	webhookUrl: 'https://hooks.slack.com/services/T0/B0/secret',
};

describe('Tenant alerts producer-consumer contract', () => {
	it('a real computeCycleDiff output parses against TenantCycleAlertSchema', () => {
		const baseline: FindingRow[] = [
			{ domain: 'a.com', category: 'dmarc', severity: 'medium', title: 'DMARC weak' },
			{ domain: 'b.com', category: 'spf', severity: 'low', title: 'SPF too permissive' },
		];
		const current: FindingRow[] = [
			{ domain: 'a.com', category: 'dmarc', severity: 'high', title: 'DMARC weakened further' },
			{ domain: 'c.com', category: 'dnssec', severity: 'critical', title: 'DNSSEC missing' },
		];
		const out = computeCycleDiff(current, baseline, opts);
		// computeCycleDiff already calls .parse internally; re-assert here so the
		// contract test owns the wire-shape claim independently.
		expect(() => TenantCycleAlertSchema.parse(out)).not.toThrow();
	});

	it('every TENANT_SEVERITY_LEVELS value round-trips through the schema', () => {
		for (const sev of TENANT_SEVERITY_LEVELS) {
			const current: FindingRow[] = [{ domain: 'x.com', category: 'dmarc', severity: sev, title: `sev=${sev}` }];
			const out = computeCycleDiff(current, [], opts);
			const parsed = TenantCycleAlertSchema.parse(out);
			expect(parsed.highlights[0].severity satisfies TenantSeverity).toBe(sev);
		}
	});

	it('payload with future-unknown field still parses (passthrough)', () => {
		const out = computeCycleDiff([], [], opts);
		const withFutureField = { ...out, future_field_v2: { unknown: true } } as unknown;
		const parsed = TenantCycleAlertSchema.parse(withFutureField) as Record<string, unknown>;
		expect(parsed.future_field_v2).toEqual({ unknown: true });
	});

	it('payload serialises to JSON (no circular refs / unsupported types)', () => {
		const baseline: FindingRow[] = [{ domain: 'a.com', category: 'dmarc', severity: 'medium', title: 'DMARC' }];
		const current: FindingRow[] = [{ domain: 'a.com', category: 'dmarc', severity: 'high', title: 'DMARC' }];
		const out = computeCycleDiff(current, baseline, opts);
		const json = JSON.stringify(out);
		expect(json.length).toBeGreaterThan(0);
		// And round-trip via JSON parse + schema parse — proves it survives the wire.
		const reparsed = TenantCycleAlertSchema.parse(JSON.parse(json));
		expect(reparsed.totals.deltas).toBe(out.totals.deltas);
	});
});
