// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: brand-audit watch webhook payload shape.
 *
 * Downstream consumers (customer webhook receivers, bv-web alert UI) parse
 * this payload. The schema is the source of truth for the wire format —
 * publishing any field-name or type change requires a `schemaVersion` bump.
 *
 * Per testing-methodology.md principle 3: Zod schemas ARE the inter-service contract.
 */

import { describe, it, expect } from 'vitest';
import {
	BrandAuditWatchWebhookPayloadSchema,
	type BrandAuditWatchWebhookPayload,
} from '../../src/schemas/brand-audit-watch-webhook';

const validPayload: BrandAuditWatchWebhookPayload = {
	schemaVersion: 1,
	watchId: 'w-1',
	auditId: 'aud-1',
	target: 'apple.com',
	interval: 'weekly',
	detectedAt: 1_750_000_000_000,
	previousHash: 'a'.repeat(64),
	currentHash: 'b'.repeat(64),
	changes: {
		added: [{ domain: 'apple-new.com', bucket: 'consolidated' }],
		removed: [{ domain: 'apple-old.com', bucket: 'shadowIt' }],
		modified: [{ domain: 'apple-shift.com', bucket: 'consolidated', previousBucket: 'shadowIt' }],
	},
};

describe('BrandAuditWatchWebhookPayloadSchema contract', () => {
	it('accepts a well-formed payload', () => {
		const parsed = BrandAuditWatchWebhookPayloadSchema.safeParse(validPayload);
		expect(parsed.success).toBe(true);
	});

	it('accepts previousHash=null (first-ever delivery)', () => {
		const parsed = BrandAuditWatchWebhookPayloadSchema.safeParse({ ...validPayload, previousHash: null });
		expect(parsed.success).toBe(true);
	});

	it('rejects payloads missing schemaVersion (mandatory for forward-compat)', () => {
		const { schemaVersion, ...rest } = validPayload;
		void schemaVersion;
		const parsed = BrandAuditWatchWebhookPayloadSchema.safeParse(rest);
		expect(parsed.success).toBe(false);
	});

	it('rejects schemaVersion != 1 (must use new payload version when wire changes)', () => {
		const parsed = BrandAuditWatchWebhookPayloadSchema.safeParse({ ...validPayload, schemaVersion: 2 });
		expect(parsed.success).toBe(false);
	});

	it('rejects non-hex / wrong-length hash values', () => {
		const bad = BrandAuditWatchWebhookPayloadSchema.safeParse({ ...validPayload, currentHash: 'not-hex' });
		expect(bad.success).toBe(false);
		const tooShort = BrandAuditWatchWebhookPayloadSchema.safeParse({ ...validPayload, currentHash: 'a'.repeat(63) });
		expect(tooShort.success).toBe(false);
	});

	it('rejects unknown bucket values', () => {
		const bad = BrandAuditWatchWebhookPayloadSchema.safeParse({
			...validPayload,
			changes: { ...validPayload.changes, added: [{ domain: 'x.com', bucket: 'unknown' as 'consolidated' }] },
		});
		expect(bad.success).toBe(false);
	});

	it('requires all three change collections (added/removed/modified) — even if empty', () => {
		const partial = BrandAuditWatchWebhookPayloadSchema.safeParse({
			...validPayload,
			changes: { added: [], removed: [] },
		});
		expect(partial.success).toBe(false);
	});
});
