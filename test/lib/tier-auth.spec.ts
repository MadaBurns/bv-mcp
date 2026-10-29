import { env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { putEmaTenant } from '../../src/oauth/ema-tenants';
import { newJti, signJwt } from '../../src/oauth/jwt';
import { resetQuotaCoordinatorState } from '../../src/lib/quota-coordinator';
import { bumpEmaTenantEpoch } from '../../src/oauth/storage';
import type { EmaTenantRecord } from '../../src/schemas/ema';
import { clearKvPrefix } from '../helpers/kv';

// SQ-435 tenant-wide revocation on the bearer path (resolveTier): an `ema:` access token stands only
// while its tenant record is live and on the token's epoch (`tep`); every other bearer pays no
// tenant read at all.

const SECRET = 'a'.repeat(32);
const ISSUER = 'https://example.com';
const REQUEST_URL = `${ISSUER}/mcp`;
const TENANT_PREFIX = 'oauth:ema-tenant:';
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

/** SESSION_STORE pass-through that records every key read and can make tenant reads fail. */
function spyKv(opts: { failTenantReads?: boolean } = {}): { kv: KVNamespace; tenantReads: () => string[] } {
	const store = env.SESSION_STORE;
	const reads: string[] = [];
	const kv = {
		get: (key: string, options?: unknown) => {
			reads.push(key);
			if (opts.failTenantReads && key.startsWith(TENANT_PREFIX)) return Promise.reject(new Error('KV unavailable (SQ-435)'));
			return store.get(key, options as KVNamespaceGetOptions<'text'>);
		},
		put: store.put.bind(store),
		delete: store.delete.bind(store),
		list: store.list.bind(store),
	} as unknown as KVNamespace;
	return { kv, tenantReads: () => reads.filter((key) => key.startsWith(TENANT_PREFIX)) };
}

function mint(claims: Record<string, unknown>): Promise<string> {
	return signJwt(
		{ sub: EMA_SUB, jti: newJti(), tier: 'developer', client_id: 'test-client', entitlementGeneration: 1, ...claims },
		{ secret: SECRET, ttlSeconds: 600, issuer: ISSUER, audience: REQUEST_URL },
	);
}

async function resolve(token: string, kv: KVNamespace, kvEnvelopeKey?: string) {
	const { resolveTier } = await import('../../src/lib/tier-auth');
	return resolveTier(
		token,
		{
			OAUTH_SIGNING_SECRET: SECRET,
			OAUTH_ISSUER: ISSUER,
			SESSION_STORE: kv,
			QUOTA_COORDINATOR: env.QUOTA_COORDINATOR,
			KV_ENVELOPE_KEY: kvEnvelopeKey,
		},
		undefined,
		REQUEST_URL,
	);
}

beforeEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
	await putEmaTenant(env.SESSION_STORE, tenant());
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
		expect(tenantReads()).toEqual([`${TENANT_PREFIX}acme-corp`]);
	});

	it('falls back to created_at as the epoch of a record written before token_epoch existed', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant({ token_epoch: undefined }));
		const { kv } = spyKv();
		expect((await resolve(await mint({ tep: 1_700_000_000 }), kv)).authenticated).toBe(true);
		expect(await resolve(await mint({ tep: EPOCH }), kv)).toEqual({ authenticated: false });
	});

	it('reads a sealed tenant record when KV_ENVELOPE_KEY is set', async () => {
		const { parseEnvelopeKey } = await import('../../src/lib/kv-envelope');
		await putEmaTenant(env.SESSION_STORE, tenant(), parseEnvelopeKey(ENVELOPE_KEY_BASE64)!);
		const { kv } = spyKv();
		expect((await resolve(await mint({ tep: EPOCH }), kv, ENVELOPE_KEY_BASE64)).authenticated).toBe(true);
		// The same sealed record without the key cannot be read, so the token is rejected (fail closed).
		expect(await resolve(await mint({ tep: EPOCH }), kv)).toEqual({ authenticated: false });
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
		await putEmaTenant(env.SESSION_STORE, tenant(record));
		const { kv } = spyKv();
		expect(await resolve(await mint(claims), kv)).toEqual({ authenticated: false });
	});

	it.each([
		['explicitly approved', { approval: 'approved' as const }],
		['an approved self-serve tenant', { approval: 'approved' as const, source: 'self-serve' as const }],
		['a legacy record with neither approval nor source', {}],
	])('resolves an ema: bearer on a tenant that is %s', async (_label, record) => {
		await putEmaTenant(env.SESSION_STORE, tenant(record));
		const { kv } = spyKv();
		expect((await resolve(await mint({ tep: EPOCH }), kv)).authenticated).toBe(true);
	});

	it('rejects an ema: bearer whose tenant record is missing', async () => {
		await env.SESSION_STORE.delete(`${TENANT_PREFIX}acme-corp`);
		const { kv } = spyKv();
		expect(await resolve(await mint({ tep: EPOCH }), kv)).toEqual({ authenticated: false });
	});

	it('judges the epoch by the coordinator version: once it moves, a token the KV record still vouches for is rejected', async () => {
		const { kv } = spyKv();
		expect((await resolve(await mint({ tep: EPOCH }), kv)).authenticated).toBe(true);
		expect(await bumpEmaTenantEpoch('acme-corp', EPOCH, env.QUOTA_COORDINATOR)).toBe(EPOCH + 1);
		// The record is untouched (token_epoch is still EPOCH, enabled, same tier), yet the old token is dead.
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
