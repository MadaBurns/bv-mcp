// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for src/schemas/tenant-alerts.ts.
 *
 * The Zod schemas here are the inter-service contract between the worker
 * (producer) and the Slack/Discord webhook (consumer). These tests own the
 * wire shape; downstream contract tests in test/contracts/ assert
 * producer-consumer alignment with `computeCycleDiff`.
 */

import { describe, it, expect } from 'vitest';
import {
	TenantCycleAlertSchema,
	TenantFindingDeltaSchema,
	hashWebhookUrl,
	type TenantCycleAlert,
	type TenantFindingDelta,
} from '../../src/schemas/tenant-alerts';

const baseDelta: TenantFindingDelta = {
	domain: 'example.com',
	category: 'dmarc',
	severity: 'high',
	title: 'DMARC policy weakened',
	delta: 'severity_changed',
	previous_severity: 'medium',
	cycle_id: 'cyc-2026-05-09-001',
	scan_at: 1_715_241_600_000,
};

function makeAlert(overrides: Partial<TenantCycleAlert> = {}): TenantCycleAlert {
	return {
		type: 'tenant_cycle_diff',
		emitted_at: 1_715_241_700_000,
		super_tenant_id: 'super-acme',
		sub_tenant_id: 'sub-prod',
		current_cycle_id: 'cyc-2026-05-09-001',
		baseline_cycle_id: 'cyc-2026-05-08-001',
		totals: {
			domains_scanned: 12,
			deltas: 3,
			by_severity: { critical: 0, high: 1, medium: 1, low: 1, info: 0 },
		},
		highlights: [baseDelta],
		webhook_url_hash: 'a1b2c3d4e5f60718',
		...overrides,
	};
}

describe('TenantCycleAlertSchema', () => {
	it('parses a valid payload', () => {
		expect(() => TenantCycleAlertSchema.parse(makeAlert())).not.toThrow();
	});

	it('rejects missing required field', () => {
		const bad = makeAlert();
		// @ts-expect-error intentional drop
		delete bad.super_tenant_id;
		expect(() => TenantCycleAlertSchema.parse(bad)).toThrow();
	});

	it('rejects a webhook_url_hash that is not 16 lowercase hex chars', () => {
		expect(() => TenantCycleAlertSchema.parse(makeAlert({ webhook_url_hash: 'not-hex' }))).toThrow();
		expect(() => TenantCycleAlertSchema.parse(makeAlert({ webhook_url_hash: 'A1B2C3D4E5F60718' }))).toThrow();
		expect(() => TenantCycleAlertSchema.parse(makeAlert({ webhook_url_hash: 'a1b2c3d4e5f6071' }))).toThrow();
	});

	it('caps highlights at 20 entries', () => {
		const bigHighlights = Array.from({ length: 21 }, () => ({ ...baseDelta }));
		expect(() => TenantCycleAlertSchema.parse(makeAlert({ highlights: bigHighlights }))).toThrow();
	});

	it('passes through unknown future fields', () => {
		const withExtra = { ...makeAlert(), some_future_field: 'forward-compat' } as unknown;
		const parsed = TenantCycleAlertSchema.parse(withExtra) as TenantCycleAlert & { some_future_field?: string };
		expect(parsed.some_future_field).toBe('forward-compat');
	});

	it('accepts a null baseline_cycle_id (first-ever cycle)', () => {
		expect(() => TenantCycleAlertSchema.parse(makeAlert({ baseline_cycle_id: null }))).not.toThrow();
	});
});

describe('TenantFindingDeltaSchema', () => {
	it('normalises severity case-insensitively', () => {
		const out = TenantFindingDeltaSchema.parse({ ...baseDelta, severity: 'HIGH' });
		expect(out.severity).toBe('high');
	});

	it('rejects a title longer than 200 chars', () => {
		const longTitle = 'x'.repeat(201);
		expect(() => TenantFindingDeltaSchema.parse({ ...baseDelta, title: longTitle })).toThrow();
	});

	it('strips control chars from title', () => {
		const out = TenantFindingDeltaSchema.parse({ ...baseDelta, title: 'A\x00B\x01C\nD' });
		expect(out.title).toBe('A B C D');
	});

	it('accepts gained / lost / severity_changed only', () => {
		expect(() => TenantFindingDeltaSchema.parse({ ...baseDelta, delta: 'gained' })).not.toThrow();
		expect(() => TenantFindingDeltaSchema.parse({ ...baseDelta, delta: 'lost' })).not.toThrow();
		// @ts-expect-error invalid literal
		expect(() => TenantFindingDeltaSchema.parse({ ...baseDelta, delta: 'maybe' })).toThrow();
	});
});

describe('hashWebhookUrl', () => {
	it('returns 16 lowercase hex chars', () => {
		const h = hashWebhookUrl('https://hooks.slack.com/services/T0/B0/secret');
		expect(h).toMatch(/^[a-f0-9]{16}$/);
	});

	it('is deterministic for the same input', () => {
		const a = hashWebhookUrl('https://example.com/hook');
		const b = hashWebhookUrl('https://example.com/hook');
		expect(a).toBe(b);
	});

	it('differs for different inputs', () => {
		const a = hashWebhookUrl('https://example.com/hook-a');
		const b = hashWebhookUrl('https://example.com/hook-b');
		expect(a).not.toBe(b);
	});
});
