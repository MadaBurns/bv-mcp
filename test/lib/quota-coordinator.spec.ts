// SPDX-License-Identifier: BUSL-1.1
import { env, runInDurableObject } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
	EMA_REGISTRY_INSTANCE_NAME,
	emaRegistryRequest,
	resetQuotaCoordinatorState,
	securityStateShardNameForKey,
	validateQuotaPayload,
} from '../../src/lib/quota-coordinator';
import {
	EMA_MIGRATED_STORAGE_KEY,
	emaFloorStorageKey,
	emaIssuerStorageKey,
	emaRecordStorageKey,
	runEmaRegistryTransaction,
	type EmaOperatorUpsert,
	type EmaRegistryRequest,
} from '../../src/oauth/ema-tenants';

// Contract A11 as amended (M1, M2, M4, M5): the EMA tenant registry is ONE dedicated QuotaCoordinator
// instance, never a shared security shard. Every `ema-*` kind routes there, runs in one storage transaction,
// validates its payload (a caller never sets a server-managed field), answers a status union, and keeps its
// keys under `ema:`, outside the `quota:` prefix the cleanup alarm sweeps. Nothing is served until the
// one-time legacy import has set its marker.

const body: EmaOperatorUpsert = {
	tenant_id: 'acme-corp',
	name: 'Acme Corp',
	issuer: 'https://idp.example.com',
	jwks_uri: 'https://idp.example.com/keys',
	allowed_client_ids: ['https://claude.ai/oauth/mcp-oauth-client-metadata'],
	tier: 'enterprise',
	enabled: true,
};

const registry = () => env.QUOTA_COORDINATOR.getByName(EMA_REGISTRY_INSTANCE_NAME);
const storedKeys = () => runInDurableObject(registry(), async (_instance, state) => [...(await state.storage.list()).keys()].sort());
const call = (payload: EmaRegistryRequest) => emaRegistryRequest(payload, env.QUOTA_COORDINATOR);
const migrate = () => call({ kind: 'ema-migrate', records: [] });
const write = (upsert: EmaOperatorUpsert = body) =>
	call({ kind: 'ema-write', tenantId: upsert.tenant_id, write: { op: 'operator-upsert', body: upsert } });

beforeEach(() => resetQuotaCoordinatorState(env.QUOTA_COORDINATOR));
afterEach(() => resetQuotaCoordinatorState(env.QUOTA_COORDINATOR));

describe('QuotaCoordinator EMA registry kinds', () => {
	it('M1: routes every ema kind to the dedicated registry instance, under ema: keys the cleanup alarm never lists', async () => {
		expect(await migrate()).toEqual({ status: 'ok', imported: 0 });
		expect(await write()).toMatchObject({ status: 'ok', record: { tenant_id: 'acme-corp', token_epoch: 1, rev: 1 } });
		const keys = await runInDurableObject(registry(), async (instance, state) => {
			await state.storage.setAlarm(Date.now());
			await (instance as unknown as { alarm(): Promise<void> }).alarm();
			return [...(await state.storage.list()).keys()].sort();
		});
		const expected = [
			EMA_MIGRATED_STORAGE_KEY,
			emaFloorStorageKey('acme-corp'),
			emaIssuerStorageKey('https://idp.example.com'),
			emaRecordStorageKey('acme-corp'),
		];
		expect(keys).toEqual(expected.sort());
		for (const key of keys) expect(key.startsWith('ema:')).toBe(true);
		// The security shard a coordination key would hash to holds nothing: the registry shares no instance.
		const shard = env.QUOTA_COORDINATOR.getByName(securityStateShardNameForKey(EMA_REGISTRY_INSTANCE_NAME));
		expect(await runInDurableObject(shard, async (_instance, state) => (await state.storage.list()).size)).toBe(0);
		expect(await call({ kind: 'ema-get', tenantId: 'acme-corp' })).toMatchObject({ status: 'ok', record: { tenant_id: 'acme-corp' } });
	});

	it('M5: every served kind answers ema_not_migrated until the import sets its marker, and the import runs once', async () => {
		const served: EmaRegistryRequest[] = [
			{ kind: 'ema-get', tenantId: 'acme-corp' },
			{ kind: 'ema-list', limit: 10 },
			{ kind: 'ema-resolve-issuer', issuer: 'https://idp.example.com' },
			{ kind: 'ema-write', tenantId: 'acme-corp', write: { op: 'reject' } },
			{ kind: 'ema-delete', tenantId: 'acme-corp', mode: 'operator' },
		];
		for (const payload of served) expect(await call(payload)).toEqual({ status: 'ema_not_migrated' });
		expect(await storedKeys()).toEqual([]);
		const legacy = { ...body, created_at: 1_700_000_000, updated_at: 1_700_000_000, token_epoch: 7 };
		expect(await call({ kind: 'ema-migrate', records: [legacy] })).toEqual({ status: 'ok', imported: 1 });
		expect(await call({ kind: 'ema-migrate', records: [{ ...legacy, tenant_id: 'beta-corp' }] })).toEqual({ status: 'ok', imported: 0 });
		expect(await call({ kind: 'ema-get', tenantId: 'acme-corp' })).toMatchObject({ status: 'ok', record: { token_epoch: 7, rev: 0 } });
		expect(await call({ kind: 'ema-resolve-issuer', issuer: 'https://idp.example.com' })).toMatchObject({
			record: { tenant_id: 'acme-corp' },
		});
		expect(await call({ kind: 'ema-get', tenantId: 'beta-corp' })).toEqual({ status: 'ok', record: null });
	});

	it('M4: delete moves the floor to last + 1 and keeps the rev, so the re-created record starts above both', async () => {
		await migrate();
		await write(); // epoch 1, rev 1
		await write({ ...body, enabled: false }); // epoch 2, rev 2
		expect(await call({ kind: 'ema-delete', tenantId: 'acme-corp', mode: 'operator' })).toEqual({ status: 'ok', record: null });
		expect(await runInDurableObject(registry(), (_instance, state) => state.storage.get(emaFloorStorageKey('acme-corp')))).toEqual({
			value: 3,
			rev: 2,
		});
		expect(await write()).toMatchObject({ status: 'ok', record: { token_epoch: 4, rev: 3 } });
	});

	it('a record or floor that does not parse is ema_store_unavailable (never absence), and the refused write rolls back', async () => {
		await migrate();
		await write();
		await runInDurableObject(registry(), (_instance, state) => state.storage.put(emaFloorStorageKey('acme-corp'), { value: 'x' }));
		// The delete removes the record, then fails reading the floor: the whole transaction rolls back.
		expect(await call({ kind: 'ema-delete', tenantId: 'acme-corp', mode: 'operator' })).toEqual({ status: 'ema_store_unavailable' });
		expect(await call({ kind: 'ema-get', tenantId: 'acme-corp' })).toMatchObject({ status: 'ok', record: { tenant_id: 'acme-corp' } });
		await runInDurableObject(registry(), (_instance, state) =>
			state.storage.put(emaRecordStorageKey('acme-corp'), { tenant_id: 'acme-corp' }),
		);
		expect(await call({ kind: 'ema-get', tenantId: 'acme-corp' })).toEqual({ status: 'ema_store_unavailable' });
		expect(await write()).toEqual({ status: 'ema_store_unavailable' });
	});

	it.each([
		['token_epoch', { token_epoch: 99 }],
		['rev', { rev: 99 }],
		['created_at', { created_at: 1 }],
		['updated_at', { updated_at: 1 }],
		['rejected_issuer_hashes', { rejected_issuer_hashes: [] }],
		['source', { source: 'self-serve' }],
	])('M2: an operator write carrying the server-managed %s is refused at the door AND by the registry itself', async (_field, extra) => {
		await migrate();
		const payload = { kind: 'ema-write', tenantId: 'acme-corp', write: { op: 'operator-upsert', body: { ...body, ...extra } } };
		expect(validateQuotaPayload(payload)).toEqual({ valid: false, error: 'Invalid ema-write request' });
		await expect(call(payload as EmaRegistryRequest)).rejects.toThrow('Invalid ema-write request');
		const direct = await runInDurableObject(registry(), (_instance, state) => runEmaRegistryTransaction(state.storage, payload));
		expect(direct).toEqual({ status: 'invalid_request' });
		expect(await call({ kind: 'ema-get', tenantId: 'acme-corp' })).toEqual({ status: 'ok', record: null });
	});

	it('M2: a self-serve write may not carry approval, and approve must name the reviewed rev', () => {
		const selfServe = {
			name: 'Acme',
			issuer: 'https://idp.example.com',
			enabled: true,
			tier: 'enterprise',
			entitlement_expires_at: Math.floor(Date.now() / 1000) + 3600,
		};
		const write = (w: unknown) => validateQuotaPayload({ kind: 'ema-write', tenantId: 'web-acme-0000-0001', write: w });
		expect(write({ op: 'self-serve-upsert', body: selfServe }).valid).toBe(true);
		expect(write({ op: 'self-serve-upsert', body: { ...selfServe, approval: 'approved' } }).valid).toBe(false);
		expect(
			write({ op: 'approve', reviewed: { issuer: 'https://idp.example.com', jwks_uri: 'https://idp.example.com/keys', rev: 3 } }).valid,
		).toBe(true);
		expect(
			write({ op: 'approve', reviewed: { issuer: 'https://idp.example.com', jwks_uri: 'https://idp.example.com/keys', updated_at: 3 } })
				.valid,
		).toBe(false);
	});

	it('without a binding the call answers undefined (callers turn that into a 503)', async () => {
		expect(await emaRegistryRequest({ kind: 'ema-get', tenantId: 'acme-corp' }, undefined)).toBeUndefined();
	});

	it.each([
		[{ kind: 'ema-get', tenantId: 'Bad_Id' }, 'Invalid ema-get request'],
		[{ kind: 'ema-get', tenantId: 'acme-corp', coordinationKey: 'ema-registry' }, 'Invalid ema-get request'],
		[{ kind: 'ema-list', limit: 0 }, 'Invalid ema-list request'],
		[{ kind: 'ema-list', limit: 5, cursor: 'x' }, 'Invalid ema-list request'],
		[{ kind: 'ema-list', limit: 5, approval: 'maybe' }, 'Invalid ema-list request'],
		[{ kind: 'ema-resolve-issuer', issuer: 'x'.repeat(513) }, 'Invalid ema-resolve-issuer request'],
		[{ kind: 'ema-write', tenantId: 'acme-corp', write: { op: 'raw-put' } }, 'Invalid ema-write request'],
		[{ kind: 'ema-delete', tenantId: 'acme-corp', mode: 'purge' }, 'Invalid ema-delete request'],
		[{ kind: 'ema-migrate', records: [{ tenant_id: 'acme-corp' }] }, 'Invalid ema-migrate request'],
	])('validateQuotaPayload refuses %j', (payload, error) => {
		expect(validateQuotaPayload(payload)).toEqual({ valid: false, error });
	});

	it('validateQuotaPayload accepts well-formed ema kinds and leaves other kinds untouched', () => {
		expect(validateQuotaPayload({ kind: 'ema-list', limit: 100, approval: 'pending' }).valid).toBe(true);
		expect(validateQuotaPayload({ kind: 'ema-delete', tenantId: 'acme-corp', mode: 'self-serve' }).valid).toBe(true);
		expect(validateQuotaPayload({ kind: 'ema-migrate', records: [] }).valid).toBe(true);
		expect(validateQuotaPayload({ kind: 'version-get', coordinationKey: 'any-key', defaultValue: 1 }).valid).toBe(true);
	});
});
