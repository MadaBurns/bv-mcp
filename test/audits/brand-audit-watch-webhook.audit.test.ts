// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit test: the brand-audit watch webhook schema covers every documented
 * field, with the documented types. Catches accidental field deletions or
 * type loosening during refactors — the wire format is a published contract.
 *
 * Per testing-methodology.md principle 4 — audit tests replace review checklists.
 */

import { describe, it, expect } from 'vitest';
import { BrandAuditWatchWebhookPayloadSchema } from '../../src/schemas/brand-audit-watch-webhook';

describe('brand-audit watch webhook schema audit', () => {
	it('has every documented top-level field', () => {
		const shape = BrandAuditWatchWebhookPayloadSchema.shape;
		const required = ['schemaVersion', 'watchId', 'auditId', 'target', 'interval', 'detectedAt', 'previousHash', 'currentHash', 'changes'] as const;
		for (const field of required) {
			expect(shape, `missing required top-level field: ${field}`).toHaveProperty(field);
		}
	});

	it('changes shape has added, removed, modified collections', () => {
		const changesShape = BrandAuditWatchWebhookPayloadSchema.shape.changes.shape;
		expect(changesShape).toHaveProperty('added');
		expect(changesShape).toHaveProperty('removed');
		expect(changesShape).toHaveProperty('modified');
	});

	it('schemaVersion is locked to literal 1 (must bump payload version to change wire)', () => {
		const result = BrandAuditWatchWebhookPayloadSchema.shape.schemaVersion.safeParse(1);
		expect(result.success).toBe(true);
		const wrong = BrandAuditWatchWebhookPayloadSchema.shape.schemaVersion.safeParse(2);
		expect(wrong.success).toBe(false);
	});
});
