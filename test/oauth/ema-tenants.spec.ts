import { env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
	EmaTenantConflictError,
	deleteEmaTenant,
	getEmaTenant,
	getEmaTenantByIssuer,
	listEmaTenants,
	normalizeIssuer,
	putEmaTenant,
} from '../../src/oauth/ema-tenants';
import { EmaTenantRecordSchema, EmaTenantUpsertRequestSchema, type EmaTenantRecord } from '../../src/schemas/ema';
import { parseEnvelopeKey } from '../../src/lib/kv-envelope';
import { OAUTH_KV_PREFIX } from '../../src/lib/config';
import { clearKvPrefix } from '../helpers/kv';

const CLAUDE_WEB_CLIENT_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
// 32 zero bytes, base64 — a valid KV_ENVELOPE_KEY shape.
const ENVELOPE_KEY = parseEnvelopeKey(btoa(String.fromCharCode(...new Uint8Array(32))))!;

function tenant(overrides: Partial<EmaTenantRecord> = {}): EmaTenantRecord {
	return {
		tenant_id: 'acme-corp',
		name: 'Acme Corp',
		issuer: 'https://idp.example.com',
		jwks_uri: 'https://idp.example.com/oauth2/v1/keys',
		allowed_client_ids: [CLAUDE_WEB_CLIENT_ID],
		tier: 'enterprise',
		enabled: true,
		created_at: 1_700_000_000,
		updated_at: 1_700_000_000,
		...overrides,
	};
}

beforeEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, OAUTH_KV_PREFIX);
});
afterEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, OAUTH_KV_PREFIX);
});

describe('normalizeIssuer', () => {
	it.each([
		['https://idp.example.com', 'https://idp.example.com'],
		['https://idp.example.com/', 'https://idp.example.com'],
		['https://IDP.Example.COM/', 'https://idp.example.com'],
		['https://idp.example.com/oauth2/default', 'https://idp.example.com/oauth2/default'],
		['https://idp.example.com/oauth2/default/', 'https://idp.example.com/oauth2/default'],
		['https://idp.example.com:443/', 'https://idp.example.com'],
		['https://idp.example.com:8443/tenant/', 'https://idp.example.com:8443/tenant'],
	])('normalizes %s -> %s', (input, expected) => {
		expect(normalizeIssuer(input)).toBe(expected);
	});

	it('strips only ONE trailing slash', () => {
		expect(normalizeIssuer('https://idp.example.com/a//')).toBe('https://idp.example.com/a/');
	});

	it.each([
		['http scheme', 'http://idp.example.com'],
		['userinfo', 'https://user:pw@idp.example.com'],
		['query', 'https://idp.example.com/?a=1'],
		['fragment', 'https://idp.example.com/#frag'],
		['not a URL', 'idp.example.com'],
		['other scheme', 'ftp://idp.example.com'],
	])('rejects %s', (_label, input) => {
		expect(() => normalizeIssuer(input)).toThrow();
	});
});

describe('EMA tenant schemas', () => {
	it('upsert schema defaults allowed_client_ids to the Claude web CIMD client and makes jwks_uri optional', () => {
		const parsed = EmaTenantUpsertRequestSchema.parse({
			tenant_id: 'acme-corp',
			name: 'Acme',
			issuer: 'https://idp.example.com',
			tier: 'developer',
			enabled: true,
		});
		expect(parsed.allowed_client_ids).toEqual([CLAUDE_WEB_CLIENT_ID]);
		expect(parsed.jwks_uri).toBeUndefined();
	});

	it.each([
		['short tenant_id', { tenant_id: 'ab' }],
		['uppercase tenant_id', { tenant_id: 'Acme-Corp' }],
		['leading-hyphen tenant_id', { tenant_id: '-acme' }],
		['http issuer', { issuer: 'http://idp.example.com' }],
		['http jwks_uri', { jwks_uri: 'http://idp.example.com/keys' }],
		['owner tier', { tier: 'owner' }],
		['empty client list', { allowed_client_ids: [] }],
		['nine clients', { allowed_client_ids: Array.from({ length: 9 }, (_, i) => `https://c${i}.example.com/m`) }],
		['non-positive expiry', { entitlement_expires_at: 0 }],
		['unknown field', { extra: true }],
	])('record schema rejects %s', (_label, patch) => {
		expect(EmaTenantRecordSchema.safeParse({ ...tenant(), ...patch }).success).toBe(false);
	});
});

describe('EMA tenant store', () => {
	it('put then get / getByIssuer / list round-trips', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant());
		expect(await getEmaTenant(env.SESSION_STORE, 'acme-corp')).toEqual(tenant());
		expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com')).toEqual(tenant());
		expect(await listEmaTenants(env.SESSION_STORE)).toEqual([tenant()]);
	});

	it('looks the issuer up in normalized form (trailing slash, host case)', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant({ issuer: 'https://IDP.example.com/oauth2/default/' }));
		const stored = await getEmaTenant(env.SESSION_STORE, 'acme-corp');
		expect(stored?.issuer).toBe('https://idp.example.com/oauth2/default');
		expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com/oauth2/default'))?.tenant_id).toBe('acme-corp');
		expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://IDP.example.com/oauth2/default/'))?.tenant_id).toBe('acme-corp');
	});

	it('returns null for unregistered, malformed and non-https issuers and for missing tenants', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant());
		expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://other.example.com')).toBeNull();
		expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'not a url')).toBeNull();
		expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'http://idp.example.com')).toBeNull();
		expect(await getEmaTenant(env.SESSION_STORE, 'missing-tenant')).toBeNull();
	});

	it('seals the record when an envelope key is present and still reads it back', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant(), ENVELOPE_KEY);
		const raw = await env.SESSION_STORE.get(`${OAUTH_KV_PREFIX}ema-tenant:acme-corp`);
		expect(raw).not.toBeNull();
		expect(raw).not.toContain('idp.example.com');
		expect(await getEmaTenant(env.SESSION_STORE, 'acme-corp', ENVELOPE_KEY)).toEqual(tenant());
		expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com', ENVELOPE_KEY))?.tenant_id).toBe('acme-corp');
		// Without the key a sealed record is unreadable, never mistaken for a tenant.
		expect(await getEmaTenant(env.SESSION_STORE, 'acme-corp')).toBeNull();
	});

	it('stores the record in plaintext when no envelope key is configured', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant());
		const raw = await env.SESSION_STORE.get(`${OAUTH_KV_PREFIX}ema-tenant:acme-corp`);
		expect(JSON.parse(raw!).tenant_id).toBe('acme-corp');
	});

	it('throws EmaTenantConflictError when a different tenant already owns the issuer', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant());
		await expect(
			putEmaTenant(env.SESSION_STORE, tenant({ tenant_id: 'other-corp', issuer: 'https://idp.example.com/' })),
		).rejects.toBeInstanceOf(EmaTenantConflictError);
		// The original mapping is untouched and the loser was not written.
		expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com'))?.tenant_id).toBe('acme-corp');
		expect(await getEmaTenant(env.SESSION_STORE, 'other-corp')).toBeNull();
	});

	it('updating the same tenant is allowed and releases the old issuer index when the issuer changes', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant());
		await putEmaTenant(env.SESSION_STORE, tenant({ issuer: 'https://idp2.example.com', jwks_uri: 'https://idp2.example.com/keys' }));
		expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com')).toBeNull();
		expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp2.example.com'))?.tenant_id).toBe('acme-corp');
		// The released issuer can now be claimed by another tenant.
		await putEmaTenant(env.SESSION_STORE, tenant({ tenant_id: 'other-corp' }));
		expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com'))?.tenant_id).toBe('other-corp');
	});

	it('delete removes the record and its issuer index, and leaves other tenants alone', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant());
		await putEmaTenant(env.SESSION_STORE, tenant({ tenant_id: 'other-corp', issuer: 'https://idp3.example.com' }));
		await deleteEmaTenant(env.SESSION_STORE, 'acme-corp');
		expect(await getEmaTenant(env.SESSION_STORE, 'acme-corp')).toBeNull();
		expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com')).toBeNull();
		expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp3.example.com'))?.tenant_id).toBe('other-corp');
		expect(await env.SESSION_STORE.list({ prefix: `${OAUTH_KV_PREFIX}ema-issuer:` }).then((l) => l.keys.length)).toBe(1);
	});

	it('delete of a missing tenant is a no-op', async () => {
		await expect(deleteEmaTenant(env.SESSION_STORE, 'missing-tenant')).resolves.toBeUndefined();
	});

	it('a stale issuer index never vouches for an issuer the record no longer lists', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant());
		// Simulate a half-applied update: record moved to a new issuer but the old index entry survived.
		await env.SESSION_STORE.put(`${OAUTH_KV_PREFIX}ema-tenant:acme-corp`, JSON.stringify(tenant({ issuer: 'https://idp2.example.com' })));
		expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com')).toBeNull();
	});

	it('list skips schema-invalid records', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant());
		await env.SESSION_STORE.put(`${OAUTH_KV_PREFIX}ema-tenant:broken-one`, JSON.stringify({ tenant_id: 'broken-one' }));
		expect((await listEmaTenants(env.SESSION_STORE)).map((t) => t.tenant_id)).toEqual(['acme-corp']);
	});
});
