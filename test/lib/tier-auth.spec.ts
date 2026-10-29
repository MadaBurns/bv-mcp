import { env, runInDurableObject } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { effectiveApproval, emaIssuerStorageKey, emaRecordStorageKey, EMA_MIGRATED_STORAGE_KEY } from '../../src/oauth/ema-tenants';
import { newJti, signJwt } from '../../src/oauth/jwt';
import { sha256Hex } from '../../src/oauth/jwks';
import { parseEnvelopeKey, sealKv } from '../../src/lib/kv-envelope';
import { resetQuotaCoordinatorState, EMA_REGISTRY_INSTANCE_NAME, type QuotaCoordinator } from '../../src/lib/quota-coordinator';
import type { EmaTenantRecord } from '../../src/schemas/ema';
import { clearKvPrefix } from '../helpers/kv';

// SQ-435 tenant-wide revocation on the bearer path (resolveTier): an `ema:` access token stands only
// while its tenant record is live and on the token's epoch (`tep`); every other bearer pays no
// tenant read at all.

const SECRET = 'a'.repeat(32);
const ISSUER = 'https://example.com';
const REQUEST_URL = `${ISSUER}/mcp`;
const EMA_SUB = `ema:acme-corp:${'0'.repeat(32)}`;
const EPOCH = 1_800_000_000_000;
// 32 zero bytes, base64 — a valid KV_ENVELOPE_KEY shape.
const ENVELOPE_KEY_BASE64 = btoa(String.fromCharCode(...new Uint8Array(32)));

function tenant(overrides: Partial<EmaTenantRecord> = {}): EmaTenantRecord {
	return {
		tenant_id: 'acme-corp',
		name: 'Acme Corp',
		issuer: 'https://acme.okta.com',
		jwks_uri: 'https://acme.okta.com/oauth2/v1/keys',
		allowed_client_ids: ['https://claude.ai/oauth/mcp-oauth-client-metadata'],
		tier: 'developer',
		enabled: true,
		created_at: 1_700_000_000,
		updated_at: 1_700_000_000,
		token_epoch: EPOCH,
		...overrides,
	};
}

/** QUOTA_COORDINATOR pass-through that records every EMA registry read (ema-get) and can make those reads fail. */
function spyKv(opts: { failTenantReads?: boolean } = {}): {
	kv: DurableObjectNamespace<QuotaCoordinator>;
	tenantReads: () => string[];
} {
	const reads: string[] = [];
	const coordinator = {
		getByName: (name: string) => {
			const stub = env.QUOTA_COORDINATOR.getByName(name);
			return {
				dispatch: async (request: { kind: string; tenantId?: string }) => {
					if (request.kind === 'ema-get') {
						reads.push(request.tenantId ?? '');
						if (opts.failTenantReads) throw new Error('registry unavailable (SQ-435)');
					}
					return stub.dispatch(request as never);
				},
			};
		},
	} as unknown as DurableObjectNamespace<QuotaCoordinator>;
	return { kv: coordinator, tenantReads: () => reads };
}

/** Overwrite one record directly in the registry shard (with its issuer index entry), bypassing every write rule. */
async function putRegistryRecord(rec: EmaTenantRecord): Promise<void> {
	await runInDurableObject(env.QUOTA_COORDINATOR.getByName(EMA_REGISTRY_INSTANCE_NAME), async (_instance, state) => {
		await state.storage.put(emaRecordStorageKey(rec.tenant_id), rec);
		await state.storage.put(EMA_MIGRATED_STORAGE_KEY, { at: 0, imported: 0 });
		if (effectiveApproval(rec) === 'approved') await state.storage.put(emaIssuerStorageKey(rec.issuer), rec.tenant_id);
	});
}

function mint(claims: Record<string, unknown>): Promise<string> {
	return signJwt(
		{ sub: EMA_SUB, jti: newJti(), tier: 'developer', client_id: 'test-client', entitlementGeneration: 1, ...claims },
		{ secret: SECRET, ttlSeconds: 600, issuer: ISSUER, audience: REQUEST_URL },
	);
}

async function resolve(token: string, coordinator: DurableObjectNamespace<QuotaCoordinator>, kvEnvelopeKey?: string) {
	const { resolveTier } = await import('../../src/lib/tier-auth');
	return resolveTier(
		token,
		{
			OAUTH_SIGNING_SECRET: SECRET,
			OAUTH_ISSUER: ISSUER,
			SESSION_STORE: env.SESSION_STORE,
			QUOTA_COORDINATOR: coordinator,
			KV_ENVELOPE_KEY: kvEnvelopeKey,
		},
		undefined,
		REQUEST_URL,
	);
}

beforeEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
	await putRegistryRecord(tenant());
});

afterEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

describe('resolveTier: EMA tenant-wide revocation', () => {
	it('resolves a non-EMA bearer without reading any tenant record (no extra I/O off the EMA path)', async () => {
		const { kv, tenantReads } = spyKv();
		const result = await resolve(await mint({ sub: 'user_123' }), kv);
		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('developer');
		expect(tenantReads()).toEqual([]);
	});

	it('resolves an ema: bearer on a live tenant and its epoch, reading that tenant record once', async () => {
		const { kv, tenantReads } = spyKv();
		const result = await resolve(await mint({ tep: EPOCH }), kv);
		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('developer');
		expect(result.oauthTenantId).toBe(EMA_SUB);
		expect(tenantReads()).toEqual(['acme-corp']);
	});

	it('falls back to created_at as the epoch of a record written before token_epoch existed', async () => {
		await putRegistryRecord(tenant({ token_epoch: undefined }));
		const { kv } = spyKv();
		expect((await resolve(await mint({ tep: 1_700_000_000 }), kv)).authenticated).toBe(true);
		expect(await resolve(await mint({ tep: EPOCH }), kv)).toEqual({ authenticated: false });
	});

	it('imports a sealed legacy KV tenant on first use: 503 while the envelope key is missing, then live once it is set', async () => {
		await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
		const legacy = tenant();
		await env.SESSION_STORE.put(
			`oauth:ema-tenant:${legacy.tenant_id}`,
			await sealKv(JSON.stringify(legacy), parseEnvelopeKey(ENVELOPE_KEY_BASE64)!),
		);
		await env.SESSION_STORE.put(`oauth:ema-issuer:${await sha256Hex(legacy.issuer)}`, legacy.tenant_id);
		const { kv } = spyKv();
		// A sealed record nobody can open is an outage, never an absent tenant.
		expect(await resolve(await mint({ tep: EPOCH }), kv)).toEqual({ authenticated: false, storageUnavailable: true });
		expect((await resolve(await mint({ tep: EPOCH }), kv, ENVELOPE_KEY_BASE64)).authenticated).toBe(true);
		// The KV copy stays for one release (rollback); the registry answers from now on, with or without the key.
		expect(await env.SESSION_STORE.get(`oauth:ema-tenant:${legacy.tenant_id}`)).not.toBeNull();
		expect((await resolve(await mint({ tep: EPOCH }), kv)).authenticated).toBe(true);
	});

	it.each([
		['the token carries no tep', {}, {}],
		['the tep is not the tenant epoch', { tep: EPOCH - 1 }, {}],
		['the tenant is disabled', { tep: EPOCH }, { enabled: false }],
		['the tenant entitlement has passed', { tep: EPOCH }, { entitlement_expires_at: Math.floor(Date.now() / 1000) - 1 }],
		['the token tier differs from the tenant tier', { tep: EPOCH }, { tier: 'enterprise' as const }],
		['the tenant approval is pending', { tep: EPOCH }, { approval: 'pending' as const }],
		['the tenant approval is rejected', { tep: EPOCH }, { approval: 'rejected' as const }],
		['the tenant is self-serve with no approval recorded (reads as pending)', { tep: EPOCH }, { source: 'self-serve' as const }],
	])('rejects an ema: bearer as unauthenticated (401, not 503) when %s', async (_label, claims, record) => {
		await putRegistryRecord(tenant(record));
		const { kv } = spyKv();
		expect(await resolve(await mint(claims), kv)).toEqual({ authenticated: false });
	});

	it.each([
		['explicitly approved', { approval: 'approved' as const }],
		['an approved self-serve tenant', { approval: 'approved' as const, source: 'self-serve' as const }],
		['a legacy record with neither approval nor source', {}],
	])('resolves an ema: bearer on a tenant that is %s', async (_label, record) => {
		await putRegistryRecord(tenant(record));
		const { kv } = spyKv();
		expect((await resolve(await mint({ tep: EPOCH }), kv)).authenticated).toBe(true);
	});

	it('rejects an ema: bearer whose tenant record is missing', async () => {
		await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
		const { kv } = spyKv();
		expect(await resolve(await mint({ tep: EPOCH }), kv)).toEqual({ authenticated: false });
	});

	it('judges the epoch by the registry record: once it moves, the old token is rejected and the new one resolves', async () => {
		const { kv } = spyKv();
		expect((await resolve(await mint({ tep: EPOCH }), kv)).authenticated).toBe(true);
		await putRegistryRecord(tenant({ token_epoch: EPOCH + 1 }));
		// Still enabled, approved and on the same tier, yet the old token is dead.
		expect(await resolve(await mint({ tep: EPOCH }), kv)).toEqual({ authenticated: false });
		expect((await resolve(await mint({ tep: EPOCH + 1 }), kv)).authenticated).toBe(true);
	});

	it('rejects a malformed ema: subject without reading any tenant record', async () => {
		for (const sub of ['ema:', 'ema:acme-corp', 'ema:Acme_Corp:abc', 'ema:acme-corp:x:y']) {
			const { kv, tenantReads } = spyKv();
			expect(await resolve(await mint({ sub, tep: EPOCH }), kv)).toEqual({ authenticated: false });
			expect(tenantReads()).toEqual([]);
		}
	});

	it('fails closed as storageUnavailable (503) when the tenant record cannot be read', async () => {
		const { kv } = spyKv({ failTenantReads: true });
		expect(await resolve(await mint({ tep: EPOCH }), kv)).toEqual({ authenticated: false, storageUnavailable: true });
	});
});
