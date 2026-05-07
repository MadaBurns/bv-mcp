// Contract test for the fuzzing-suspected webhook payload.
//
// The Zod schema in src/schemas/alerting.ts is the inter-service contract between
// the worker (producer) and the Slack/Discord webhook (consumer). This test owns
// the wire shape — unit tests in fuzzing-detector own the verdict logic, and the
// E2E test in test/fuzzing-e2e.integration.test.ts proves the wiring; neither
// re-asserts the JSON shape.

import { describe, it, expect } from 'vitest';
import { buildFuzzingAlertPayload, FuzzingAlertSchema } from '../../src/schemas/alerting';
import type { FuzzVerdict } from '../../src/lib/fuzzing-detector';

const verdict: FuzzVerdict = {
	suspected: true,
	kind: 'unknown_tool',
	count: 12,
	windowSeconds: 60,
};

describe('FuzzingAlertSchema (producer side)', () => {
	it('builds a payload that parses against the schema', () => {
		const payload = buildFuzzingAlertPayload(verdict, {
			principalKind: 'ip',
			principalIdHash: '0123456789abcdef',
			observedAt: '2026-05-07T01:23:45.000Z',
		});
		expect(() => FuzzingAlertSchema.parse(payload)).not.toThrow();
	});

	it('refuses to include a raw IP — only the truncated hash is allowed', () => {
		expect(() =>
			buildFuzzingAlertPayload(verdict, {
				principalKind: 'ip',
				// 16 hex chars is the only allowed shape; "143.44.164.31" is invalid
				principalIdHash: '143.44.164.31' as unknown as string,
				observedAt: '2026-05-07T01:23:45.000Z',
			}),
		).toThrow();
	});

	it('echoes the verdict windowSeconds into the payload', () => {
		const payload = buildFuzzingAlertPayload({ ...verdict, windowSeconds: 120 }, {
			principalKind: 'keyHash',
			principalIdHash: 'fedcba9876543210',
			observedAt: '2026-05-07T01:23:45.000Z',
		});
		expect(payload.windowSeconds).toBe(120);
	});

	it('serialises to ≤ 4 KB (Slack/Discord webhook payload cap)', () => {
		const payload = buildFuzzingAlertPayload(verdict, {
			principalKind: 'ip',
			principalIdHash: '0123456789abcdef',
			observedAt: '2026-05-07T01:23:45.000Z',
		});
		expect(JSON.stringify(payload).length).toBeLessThanOrEqual(4096);
	});
});
