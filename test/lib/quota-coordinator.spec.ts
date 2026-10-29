// SPDX-License-Identifier: BUSL-1.1
import { env, runInDurableObject } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { emaRegistryRequest, resetQuotaCoordinatorState, securityStateShardNameForKey, validateQuotaPayload } from '../../src/lib/quota-coordinator';
import {
	EMA_REGISTRY_KEY,
	emaEpochFloorStorageKey,
	emaIssuerStorageKey,
	emaRecordStorageKey,
	type EmaOperatorUpsert,
} from '../../src/oauth/ema-tenants';

// Contract A11: the EMA tenant registry is ONE QuotaCoordinator strong-state shard. Every `ema-*` kind is a
// security-state kind routed by the fixed coordination key, runs in one storage transaction, and stores
// its keys outside the `quota:` prefix the cleanup alarm sweeps.

const body: EmaOperatorUpsert = {
	tenant_id: 'acme-corp',
	name: 'Acme Corp',
	issuer: 'https://idp.example.com',
	jwks_uri: 'https://idp.example.com/keys',
	allowed_client_ids: ['https://claude.ai/oauth/mcp-oauth-client-metadata'],
	tier: 'enterprise',
	enabled: true,
};

const registryShard = () => env.QUOTA_COORDINATOR.getByName(securityStateShardNameForKey(EMA_REGISTRY_KEY));

beforeEach(() => resetQuotaCoordinatorState(env.QUOTA_COORDINATOR));
afterEach(() => resetQuotaCoordinatorState(env.QUOTA_COORDINATOR));

describe('QuotaCoordinator EMA registry kinds', () => {
	it('stores the record, issuer index and epoch floor on the registry shard, under strong: keys the cleanup alarm never lists', async () => {
		const written = await emaRegistryRequest(
			{ kind: 'ema-write', coordinationKey: EMA_REGISTRY_KEY, tenantId: 'acme-corp', write: { op: 'operator-upsert', body } },
			env.QUOTA_COORDINATOR,
		);
		expect(written).toMatchObject({ record: { tenant_id: 'acme-corp', token_epoch: 1 } });
		const keys = await runInDurableObject(registryShard(), async (_instance, state) => {
			await state.storage.setAlarm(Date.now());
			const instance = _instance as unknown as { alarm(): Promise<void> };
			await instance.alarm();
			return [...(await state.storage.list()).keys()];
		});
		expect(keys).toEqual(
			expect.arrayContaining([emaRecordStorageKey('acme-corp'), emaIssuerStorageKey('https://idp.example.com'), emaEpochFloorStorageKey('acme-corp')]),
		);
		for (const key of keys) expect(key.startsWith('quota:')).toBe(false);
		expect(await emaRegistryRequest({ kind: 'ema-get', coordinationKey: EMA_REGISTRY_KEY, tenantId: 'acme-corp' }, env.QUOTA_COORDINATOR)).toMatchObject({
			record: { tenant_id: 'acme-corp' },
			known: true,
		});
	});

	it('a failed write rolls the whole transaction back', async () => {
		const bad = { ...body, name: '' }; // schema-invalid: the store-time parse throws inside the transaction
		await expect(
			emaRegistryRequest(
				{ kind: 'ema-write', coordinationKey: EMA_REGISTRY_KEY, tenantId: 'acme-corp', write: { op: 'operator-upsert', body: bad } },
				env.QUOTA_COORDINATOR,
			),
		).rejects.toThrow();
		const keys = await runInDurableObject(registryShard(), async (_instance, state) => [...(await state.storage.list()).keys()]);
		expect(keys).toEqual([]);
	});

	it('without a binding the call answers undefined (callers turn that into a 503)', async () => {
		expect(await emaRegistryRequest({ kind: 'ema-get', coordinationKey: EMA_REGISTRY_KEY, tenantId: 'acme-corp' }, undefined)).toBeUndefined();
	});

	it.each([
		[{ kind: 'ema-get', coordinationKey: 'other-key', tenantId: 'acme-corp' }, 'Invalid coordinationKey: ema kinds use the registry key'],
		[{ kind: 'ema-get', coordinationKey: EMA_REGISTRY_KEY, tenantId: 'Bad_Id' }, 'Invalid tenantId'],
		[{ kind: 'ema-get', coordinationKey: EMA_REGISTRY_KEY }, 'Invalid ema-get: missing tenantId'],
		[{ kind: 'ema-list', coordinationKey: EMA_REGISTRY_KEY, limit: 0 }, 'Invalid limit: must be 1 to 100'],
		[{ kind: 'ema-list', coordinationKey: EMA_REGISTRY_KEY, limit: 5, cursor: 'x' }, 'Invalid cursor'],
		[{ kind: 'ema-list', coordinationKey: EMA_REGISTRY_KEY, limit: 5, approval: 'maybe' }, 'Invalid approval'],
		[{ kind: 'ema-resolve-issuer', coordinationKey: EMA_REGISTRY_KEY, issuer: 'x'.repeat(513) }, 'Invalid issuer'],
		[{ kind: 'ema-write', coordinationKey: EMA_REGISTRY_KEY, tenantId: 'acme-corp', write: { op: 'raw-put' } }, 'Invalid write'],
		[{ kind: 'ema-delete', coordinationKey: EMA_REGISTRY_KEY, tenantId: 'acme-corp', op: 'purge' }, 'Invalid op'],
	])('validateQuotaPayload refuses %j', (payload, error) => {
		expect(validateQuotaPayload(payload)).toEqual({ valid: false, error });
	});

	it('validateQuotaPayload accepts well-formed ema kinds and leaves other kinds untouched', () => {
		expect(validateQuotaPayload({ kind: 'ema-list', coordinationKey: EMA_REGISTRY_KEY, limit: 100, approval: 'pending' }).valid).toBe(true);
		expect(validateQuotaPayload({ kind: 'ema-delete', coordinationKey: EMA_REGISTRY_KEY, tenantId: 'acme-corp', op: 'self-serve' }).valid).toBe(true);
		expect(validateQuotaPayload({ kind: 'version-get', coordinationKey: 'any-key', defaultValue: 1 }).valid).toBe(true);
	});
});
