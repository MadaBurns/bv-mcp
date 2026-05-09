import { describe, it, expect } from 'vitest';
import { AuditEventSchema } from '../../src/schemas/audit';

/**
 * Unit tests for the AuditEventSchema (Phase 6 cross-tenant audit log foundation).
 *
 * The schema is the input contract to `recordAuditEvent()` and is also
 * implicitly the wire contract for any future cross-service audit forwarder.
 * Locking required fields, allowed enums, and rejection of unknown shapes
 * keeps the audit ledger tamper-resistant by construction.
 */

const minimalValid = {
	actorPrincipal: 'k_abc123',
	actorTier: 'developer' as const,
	action: 'portfolio.upsert',
	resourceType: 'domain',
	outcome: 'success' as const,
};

describe('AuditEventSchema — required fields', () => {
	it('accepts a minimal valid event', () => {
		const result = AuditEventSchema.safeParse(minimalValid);
		expect(result.success).toBe(true);
	});

	it('rejects missing actorPrincipal', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, actorPrincipal: undefined });
		expect(result.success).toBe(false);
	});

	it('rejects missing actorTier', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, actorTier: undefined });
		expect(result.success).toBe(false);
	});

	it('rejects missing action', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, action: undefined });
		expect(result.success).toBe(false);
	});

	it('rejects missing resourceType', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, resourceType: undefined });
		expect(result.success).toBe(false);
	});

	it('rejects missing outcome', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, outcome: undefined });
		expect(result.success).toBe(false);
	});
});

describe('AuditEventSchema — actorTier enum', () => {
	const tiers = ['free', 'agent', 'developer', 'enterprise', 'partner', 'owner'] as const;
	for (const tier of tiers) {
		it(`accepts actorTier=${tier}`, () => {
			const result = AuditEventSchema.safeParse({ ...minimalValid, actorTier: tier });
			expect(result.success).toBe(true);
		});
	}

	it('rejects unknown actorTier', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, actorTier: 'admin' });
		expect(result.success).toBe(false);
	});

	it('rejects non-string actorTier', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, actorTier: 5 });
		expect(result.success).toBe(false);
	});
});

describe('AuditEventSchema — outcome enum', () => {
	for (const outcome of ['success', 'denied', 'error'] as const) {
		it(`accepts outcome=${outcome}`, () => {
			const result = AuditEventSchema.safeParse({ ...minimalValid, outcome });
			expect(result.success).toBe(true);
		});
	}

	it('rejects unknown outcome', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, outcome: 'partial' });
		expect(result.success).toBe(false);
	});
});

describe('AuditEventSchema — optional fields', () => {
	it('accepts superTenantId and subTenantId', () => {
		const result = AuditEventSchema.safeParse({
			...minimalValid,
			superTenantId: 'st_1',
			subTenantId: 'sb_1',
		});
		expect(result.success).toBe(true);
	});

	it('accepts requestId and cfRay', () => {
		const result = AuditEventSchema.safeParse({
			...minimalValid,
			requestId: 'r_abc',
			cfRay: '12345-DFW',
		});
		expect(result.success).toBe(true);
	});

	it('accepts ipHash with i_ prefix', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, ipHash: 'i_deadbeef' });
		expect(result.success).toBe(true);
	});

	it('accepts blob as record', () => {
		const result = AuditEventSchema.safeParse({
			...minimalValid,
			blob: { domain: 'example.com', count: 3 },
		});
		expect(result.success).toBe(true);
	});

	it('accepts resourceId', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, resourceId: 'res_1' });
		expect(result.success).toBe(true);
	});
});

describe('AuditEventSchema — string bounds', () => {
	it('rejects empty action', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, action: '' });
		expect(result.success).toBe(false);
	});

	it('rejects empty actorPrincipal', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, actorPrincipal: '' });
		expect(result.success).toBe(false);
	});

	it('rejects empty resourceType', () => {
		const result = AuditEventSchema.safeParse({ ...minimalValid, resourceType: '' });
		expect(result.success).toBe(false);
	});
});
