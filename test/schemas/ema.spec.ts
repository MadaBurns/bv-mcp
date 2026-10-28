import { describe, expect, it } from 'vitest';
import { EmaTenantRecordSchema, EmaTenantUpsertRequestSchema } from '../../src/schemas/ema';

// SQ-435: `token_epoch` is a server-managed field of the STORED tenant record. The upsert request
// body must never be able to set it, or an operator payload could resurrect revoked tokens.

const record = {
	tenant_id: 'acme-corp',
	name: 'Acme Corp',
	issuer: 'https://acme.okta.com',
	jwks_uri: 'https://acme.okta.com/oauth2/v1/keys',
	tier: 'developer',
	enabled: true,
	created_at: 1_700_000_000,
	updated_at: 1_700_000_000,
};

const upsertBody = {
	tenant_id: 'acme-corp',
	name: 'Acme Corp',
	issuer: 'https://acme.okta.com',
	tier: 'developer',
	enabled: true,
};

describe('EmaTenantRecordSchema token_epoch', () => {
	it('accepts a positive integer epoch and a record without one (written before the field existed)', () => {
		const withEpoch = EmaTenantRecordSchema.safeParse({ ...record, token_epoch: 1_800_000_000_123 });
		expect(withEpoch.success).toBe(true);
		expect(withEpoch.data?.token_epoch).toBe(1_800_000_000_123);
		const legacy = EmaTenantRecordSchema.safeParse(record);
		expect(legacy.success).toBe(true);
		expect(legacy.data?.token_epoch).toBeUndefined();
	});

	it.each([0, -1, 1.5, '1800000000123', null])('rejects token_epoch %j', (tokenEpoch) => {
		expect(EmaTenantRecordSchema.safeParse({ ...record, token_epoch: tokenEpoch }).success).toBe(false);
	});
});

describe('EmaTenantUpsertRequestSchema allowed_client_ids default', () => {
	it('defaults to the Claude web CIMD client id exported by oauth/cimd (the one source of that constant)', async () => {
		const { CLAUDE_WEB_CIMD_CLIENT_ID } = await import('../../src/oauth/cimd');
		expect(EmaTenantUpsertRequestSchema.parse(upsertBody).allowed_client_ids).toEqual([CLAUDE_WEB_CIMD_CLIENT_ID]);
	});
});

describe('EmaTenantUpsertRequestSchema token_epoch', () => {
	it('rejects a request body that sets token_epoch (strict, server-managed)', () => {
		expect(EmaTenantUpsertRequestSchema.safeParse(upsertBody).success).toBe(true);
		expect(EmaTenantUpsertRequestSchema.safeParse({ ...upsertBody, token_epoch: 1 }).success).toBe(false);
	});
});
