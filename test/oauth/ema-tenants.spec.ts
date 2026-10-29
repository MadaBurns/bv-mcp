import { env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
	EmaTenantConflictError,
	EmaTenantUnreadableError,
	deleteEmaTenant,
	effectiveApproval,
	getEmaTenant,
	getEmaTenantByIssuer,
	getEmaTenantForWrite,
	isSharedIssuer,
	isTenantActive,
	listEmaTenants,
	normalizeIssuer,
	putEmaTenant,
	tenantEpoch,
} from '../../src/oauth/ema-tenants';
import {
	EMA_SELF_SERVE_MAX_ENTITLEMENT_SECONDS,
	EmaSelfServeUpsertRequestSchema,
	EmaTenantRecordSchema,
	EmaTenantUpsertRequestSchema,
	type EmaTenantRecord,
} from '../../src/schemas/ema';
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

	it('collapses repeated trailing slashes and is idempotent', () => {
		expect(normalizeIssuer('https://a.com/x//')).toBe('https://a.com/x');
		expect(normalizeIssuer('https://A.com/x/')).toBe('https://a.com/x');
		expect(normalizeIssuer('https://a.com//')).toBe('https://a.com');
		for (const input of ['https://a.com/x//', 'https://A.com/x/', 'https://a.com//', 'https://a.com:443/a///', 'https://a.com/a/b']) {
			const once = normalizeIssuer(input);
			expect(normalizeIssuer(once)).toBe(once);
		}
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

	it('indexes the issuer under oauth:ema-issuer:<lowercase sha256 hex> (fixed input, byte-identical across the refactor)', async () => {
		// Independently computed: shasum -a 256 of 'https://idp.example.com'.
		const indexKey = `${OAUTH_KV_PREFIX}ema-issuer:6e2977ae82314db30124ba2850e1a8d59388eb8f98aff11dfa82935b17b4657f`;
		await putEmaTenant(env.SESSION_STORE, tenant());
		expect(await env.SESSION_STORE.get(indexKey)).toBe('acme-corp');
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

	it('round-trips a sealed token_epoch, and tenantEpoch falls back to created_at without one', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant({ token_epoch: 1_800_000_000_123 }), ENVELOPE_KEY);
		const stored = await getEmaTenant(env.SESSION_STORE, 'acme-corp', ENVELOPE_KEY);
		expect(stored?.token_epoch).toBe(1_800_000_000_123);
		expect(tenantEpoch(stored!)).toBe(1_800_000_000_123);
		expect(tenantEpoch(tenant())).toBe(1_700_000_000);
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

	describe('caller-supplied `existing` snapshot', () => {
		const tenantKey = `${OAUTH_KV_PREFIX}ema-tenant:acme-corp`;
		const moved = () => tenant({ issuer: 'https://idp2.example.com', jwks_uri: 'https://idp2.example.com/keys' });

		function countingKv(counts: { reads: number }): KVNamespace {
			const kv = env.SESSION_STORE;
			return {
				get: (key: string, ...rest: unknown[]) => {
					if (key === tenantKey) counts.reads++;
					return (kv.get as (...args: unknown[]) => Promise<unknown>)(key, ...rest);
				},
				put: kv.put.bind(kv),
				delete: kv.delete.bind(kv),
				list: kv.list.bind(kv),
			} as unknown as KVNamespace;
		}

		it('does not re-read the tenant key, and releases the old issuer from the supplied snapshot', async () => {
			await putEmaTenant(env.SESSION_STORE, tenant());
			const snapshot = await getEmaTenant(env.SESSION_STORE, 'acme-corp');
			const counts = { reads: 0 };
			await putEmaTenant(countingKv(counts), moved(), undefined, snapshot);
			expect(counts.reads).toBe(0);
			expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com')).toBeNull();
			expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp2.example.com'))?.tenant_id).toBe('acme-corp');
		});

		it('omitting it reads the tenant key once (the pre-existing behaviour for other callers)', async () => {
			await putEmaTenant(env.SESSION_STORE, tenant());
			const counts = { reads: 0 };
			await putEmaTenant(countingKv(counts), moved());
			expect(counts.reads).toBe(1);
			expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com')).toBeNull();
		});

		it('trusts the snapshot: `null` means no previous record, so no old issuer is released', async () => {
			await putEmaTenant(env.SESSION_STORE, tenant());
			const counts = { reads: 0 };
			await putEmaTenant(countingKv(counts), moved(), undefined, null);
			expect(counts.reads).toBe(0);
			// The old index entry is untouched (two issuer keys remain), but the record no longer lists it, so it cannot vouch.
			expect((await env.SESSION_STORE.list({ prefix: `${OAUTH_KV_PREFIX}ema-issuer:` })).keys).toHaveLength(2);
			expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com')).toBeNull();
		});
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

	describe('fail-closed sealing (envelope key set)', () => {
		const tenantRecordKey = `${OAUTH_KV_PREFIX}ema-tenant:acme-corp`;
		const issuerIndexKey = async (issuer: string) => {
			const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(issuer)));
			return `${OAUTH_KV_PREFIX}ema-issuer:${Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('')}`;
		};

		it('treats a planted plaintext record as absent from get, getByIssuer and list', async () => {
			const planted = tenant({ jwks_uri: 'https://evil.example.net/keys' });
			await env.SESSION_STORE.put(tenantRecordKey, JSON.stringify(planted));
			await env.SESSION_STORE.put(await issuerIndexKey(planted.issuer), planted.tenant_id);
			expect(await getEmaTenant(env.SESSION_STORE, 'acme-corp', ENVELOPE_KEY)).toBeNull();
			expect(await getEmaTenantByIssuer(env.SESSION_STORE, planted.issuer, ENVELOPE_KEY)).toBeNull();
			expect(await listEmaTenants(env.SESSION_STORE, ENVELOPE_KEY)).toEqual([]);
			// Without a key configured the same record is the operator's own plaintext store and stays readable.
			expect(await getEmaTenant(env.SESSION_STORE, 'acme-corp')).toEqual(planted);
		});

		it('treats a sealed record whose tenant_id differs from the key it was read from as absent', async () => {
			await putEmaTenant(env.SESSION_STORE, tenant({ tenant_id: 'other-corp', issuer: 'https://idp2.example.com' }), ENVELOPE_KEY);
			const sealed = await env.SESSION_STORE.get(`${OAUTH_KV_PREFIX}ema-tenant:other-corp`);
			// Copy other-corp's valid sealed blob under acme-corp's key, and point acme-corp's issuer index at it.
			await env.SESSION_STORE.put(tenantRecordKey, sealed!);
			await env.SESSION_STORE.put(await issuerIndexKey('https://idp2.example.com'), 'acme-corp');
			expect(await getEmaTenant(env.SESSION_STORE, 'acme-corp', ENVELOPE_KEY)).toBeNull();
			expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp2.example.com', ENVELOPE_KEY)).toBeNull();
			expect((await listEmaTenants(env.SESSION_STORE, ENVELOPE_KEY)).map((t) => t.tenant_id)).toEqual(['other-corp']);
		});

		it('rejects a tenant_id mismatch without an envelope key too', async () => {
			await env.SESSION_STORE.put(tenantRecordKey, JSON.stringify(tenant({ tenant_id: 'other-corp' })));
			expect(await getEmaTenant(env.SESSION_STORE, 'acme-corp')).toBeNull();
		});
	});

	describe('orphaned issuer index', () => {
		const recordKey = (tenantId: string) => `${OAUTH_KV_PREFIX}ema-tenant:${tenantId}`;
		const indexCount = async () => (await env.SESSION_STORE.list({ prefix: `${OAUTH_KV_PREFIX}ema-issuer:` })).keys.length;

		it('treats an index entry whose record is missing as free: another tenant can claim the issuer', async () => {
			await putEmaTenant(env.SESSION_STORE, tenant());
			await env.SESSION_STORE.delete(recordKey('acme-corp'));
			await expect(putEmaTenant(env.SESSION_STORE, tenant({ tenant_id: 'other-corp' }))).resolves.toMatchObject({
				tenant_id: 'other-corp',
			});
			expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com'))?.tenant_id).toBe('other-corp');
		});

		it('treats an index entry whose record is unreadable as free', async () => {
			await putEmaTenant(env.SESSION_STORE, tenant(), ENVELOPE_KEY);
			await env.SESSION_STORE.put(recordKey('acme-corp'), 'garbage-not-json');
			await expect(putEmaTenant(env.SESSION_STORE, tenant({ tenant_id: 'other-corp' }), ENVELOPE_KEY)).resolves.toMatchObject({
				tenant_id: 'other-corp',
			});
		});

		it('does not free an index entry whose owner record is readable and still lists the issuer', async () => {
			await putEmaTenant(env.SESSION_STORE, tenant());
			await expect(putEmaTenant(env.SESSION_STORE, tenant({ tenant_id: 'other-corp' }))).rejects.toBeInstanceOf(EmaTenantConflictError);
		});

		it('delete releases the index even when the record is missing, leaving other tenants alone', async () => {
			await putEmaTenant(env.SESSION_STORE, tenant());
			await putEmaTenant(env.SESSION_STORE, tenant({ tenant_id: 'other-corp', issuer: 'https://idp3.example.com' }));
			await env.SESSION_STORE.delete(recordKey('acme-corp'));
			await deleteEmaTenant(env.SESSION_STORE, 'acme-corp');
			expect(await indexCount()).toBe(1);
			expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp3.example.com'))?.tenant_id).toBe('other-corp');
		});

		it('delete releases the index even when the record cannot be read', async () => {
			await putEmaTenant(env.SESSION_STORE, tenant(), ENVELOPE_KEY);
			await putEmaTenant(env.SESSION_STORE, tenant({ tenant_id: 'other-corp', issuer: 'https://idp3.example.com' }), ENVELOPE_KEY);
			await env.SESSION_STORE.put(recordKey('acme-corp'), 'garbage-not-json');
			await deleteEmaTenant(env.SESSION_STORE, 'acme-corp', ENVELOPE_KEY);
			expect(await env.SESSION_STORE.get(recordKey('acme-corp'))).toBeNull();
			expect(await indexCount()).toBe(1);
			expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp3.example.com', ENVELOPE_KEY))?.tenant_id).toBe('other-corp');
		});
	});

	it('list skips schema-invalid records', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant());
		await env.SESSION_STORE.put(`${OAUTH_KV_PREFIX}ema-tenant:broken-one`, JSON.stringify({ tenant_id: 'broken-one' }));
		expect((await listEmaTenants(env.SESSION_STORE)).map((t) => t.tenant_id)).toEqual(['acme-corp']);
	});
});

describe('isSharedIssuer', () => {
	const GUID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
	const ENTRA_HOSTS = [
		'login.microsoftonline.com',
		'login.microsoftonline.us',
		'login.microsoftonline.de',
		'login.partner.microsoftonline.cn',
		'login.microsoft.com',
		'login.windows.net',
		'sts.windows.net',
	];

	it.each([
		...ENTRA_HOSTS.flatMap((host) =>
			['common', 'organizations', 'consumers', '{tenantid}'].map((segment) => `https://${host}/${segment}/v2.0`),
		),
		'https://login.microsoftonline.com/common',
		'https://login.microsoftonline.com/COMMON/v2.0',
		'https://login.microsoftonline.com/%63ommon/v2.0',
		'https://login.microsoftonline.com//organizations/v2.0',
		'https://login.microsoftonline.com/%7BTenantID%7D/v2.0',
		'https://login.microsoftonline.com/common/oauth2/anything/else',
		'https://login.microsoftonline.com./common/v2.0',
		'https://login.microsoftonline.com/%zz/v2.0',
		'https://accounts.google.com',
		'https://accounts.google.com./',
		'https://login.live.com',
		'https://appleid.apple.com',
		'https://idp.xaa.dev',
		'https://token.actions.githubusercontent.com',
		'https://securetoken.google.com/some-project',
		'https://contoso.b2clogin.com/tenant-guid/v2.0',
	])('refuses %s', (issuer) => {
		expect(isSharedIssuer(normalizeIssuer(issuer))).toBe(true);
	});

	it.each([
		...ENTRA_HOSTS.map((host) => `https://${host}/${GUID}/v2.0`),
		`https://sts.windows.net/${GUID}`,
		'https://login.microsoftonline.com/commonwealth-corp/v2.0',
		'https://acme.okta.com',
		'https://acme.okta.com/oauth2/default',
		'https://idp.example.com/common',
		'https://b2clogin.com.evil.example',
		'https://google.com',
		'https://xaa.dev',
	])('allows the per-tenant or unrelated issuer %s', (issuer) => {
		expect(isSharedIssuer(normalizeIssuer(issuer))).toBe(false);
	});
});

describe('approval and the issuer index', () => {
	const pending = (overrides: Partial<EmaTenantRecord> = {}) => tenant({ source: 'self-serve', approval: 'pending', ...overrides });

	it.each([
		[{}, 'approved'],
		[{ source: 'operator' as const }, 'approved'],
		[{ source: 'self-serve' as const }, 'pending'],
		[{ source: 'self-serve' as const, approval: 'approved' as const }, 'approved'],
		[{ approval: 'rejected' as const }, 'rejected'],
	])('effectiveApproval(%j) is %s', (fields, expected) => {
		expect(effectiveApproval(fields)).toBe(expected);
	});

	it('isTenantActive needs enabled, approved and an unexpired entitlement', () => {
		const now = 1_800_000_000;
		expect(isTenantActive(tenant(), now)).toBe(true);
		expect(isTenantActive(tenant({ entitlement_expires_at: now + 1 }), now)).toBe(true);
		expect(isTenantActive(tenant({ entitlement_expires_at: now }), now)).toBe(false);
		expect(isTenantActive(tenant({ enabled: false }), now)).toBe(false);
		expect(isTenantActive(tenant({ approval: 'pending' }), now)).toBe(false);
		expect(isTenantActive(tenant({ approval: 'rejected' }), now)).toBe(false);
		expect(isTenantActive(tenant({ source: 'self-serve' }), now)).toBe(false);
	});

	it('a pending record is stored but neither indexed nor resolvable by issuer, so any number may name one issuer', async () => {
		await putEmaTenant(env.SESSION_STORE, pending({ tenant_id: 'web-first' }), ENVELOPE_KEY);
		await putEmaTenant(env.SESSION_STORE, pending({ tenant_id: 'web-second' }), ENVELOPE_KEY);
		expect((await getEmaTenant(env.SESSION_STORE, 'web-first', ENVELOPE_KEY))?.approval).toBe('pending');
		expect((await env.SESSION_STORE.list({ prefix: `${OAUTH_KV_PREFIX}ema-issuer:` })).keys).toEqual([]);
		expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com', ENVELOPE_KEY)).toBeNull();
	});

	it('approval claims the index (conflicting with another APPROVED holder only), and leaving approval releases it', async () => {
		await putEmaTenant(env.SESSION_STORE, pending({ tenant_id: 'web-first' }), ENVELOPE_KEY);
		await putEmaTenant(env.SESSION_STORE, pending({ tenant_id: 'web-second' }), ENVELOPE_KEY);
		await putEmaTenant(env.SESSION_STORE, pending({ tenant_id: 'web-first', approval: 'approved' }), ENVELOPE_KEY);
		expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com', ENVELOPE_KEY))?.tenant_id).toBe('web-first');
		await expect(
			putEmaTenant(env.SESSION_STORE, pending({ tenant_id: 'web-second', approval: 'approved' }), ENVELOPE_KEY),
		).rejects.toBeInstanceOf(EmaTenantConflictError);

		await putEmaTenant(env.SESSION_STORE, pending({ tenant_id: 'web-first', approval: 'rejected' }), ENVELOPE_KEY);
		expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com', ENVELOPE_KEY)).toBeNull();
		await putEmaTenant(env.SESSION_STORE, pending({ tenant_id: 'web-second', approval: 'approved' }), ENVELOPE_KEY);
		expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com', ENVELOPE_KEY))?.tenant_id).toBe('web-second');
	});

	it('a stale index entry pointing at a record that is no longer approved does not vouch, and does not block', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant(), ENVELOPE_KEY);
		// Rewrite the record as pending behind the store's back, leaving its index entry in place.
		const { sealKv } = await import('../../src/lib/kv-envelope');
		const sealed = await sealKv(JSON.stringify(tenant({ approval: 'pending' })), ENVELOPE_KEY);
		await env.SESSION_STORE.put(`${OAUTH_KV_PREFIX}ema-tenant:acme-corp`, sealed);
		expect(await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com', ENVELOPE_KEY)).toBeNull();
		await putEmaTenant(env.SESSION_STORE, tenant({ tenant_id: 'other-corp' }), ENVELOPE_KEY);
		expect((await getEmaTenantByIssuer(env.SESSION_STORE, 'https://idp.example.com', ENVELOPE_KEY))?.tenant_id).toBe('other-corp');
	});
});

describe('getEmaTenantForWrite', () => {
	it('is null only when nothing is stored, and returns a readable record', async () => {
		expect(await getEmaTenantForWrite(env.SESSION_STORE, 'acme-corp', ENVELOPE_KEY)).toBeNull();
		await putEmaTenant(env.SESSION_STORE, tenant(), ENVELOPE_KEY);
		expect((await getEmaTenantForWrite(env.SESSION_STORE, 'acme-corp', ENVELOPE_KEY))?.tenant_id).toBe('acme-corp');
	});

	it.each([
		['a planted plaintext record', async () => JSON.stringify(tenant())],
		['garbage', async () => 'not a record'],
	])('throws EmaTenantUnreadableError on %s, where getEmaTenant reads absent', async (_label, value) => {
		await env.SESSION_STORE.put(`${OAUTH_KV_PREFIX}ema-tenant:acme-corp`, await value());
		expect(await getEmaTenant(env.SESSION_STORE, 'acme-corp', ENVELOPE_KEY)).toBeNull();
		await expect(getEmaTenantForWrite(env.SESSION_STORE, 'acme-corp', ENVELOPE_KEY)).rejects.toBeInstanceOf(EmaTenantUnreadableError);
	});
});

describe('EMA approval schemas', () => {
	it.each([['pending'], ['approved'], ['rejected']])('record schema accepts approval %s and both sources', (approval) => {
		expect(EmaTenantRecordSchema.safeParse({ ...tenant(), approval, source: 'self-serve' }).success).toBe(true);
		expect(EmaTenantRecordSchema.safeParse({ ...tenant(), approval, source: 'operator' }).success).toBe(true);
	});

	it.each([
		['unknown approval', { approval: 'maybe' }],
		['unknown source', { source: 'web' }],
	])('record schema rejects %s', (_label, patch) => {
		expect(EmaTenantRecordSchema.safeParse({ ...tenant(), ...patch }).success).toBe(false);
	});

	it('self-serve schema requires an entitlement no further out than 400 days, and accepts a past one', () => {
		const now = Math.floor(Date.now() / 1000);
		const body = { name: 'Acme', issuer: 'https://idp.example.com', enabled: true, tier: 'enterprise' };
		expect(EmaSelfServeUpsertRequestSchema.safeParse(body).success).toBe(false);
		expect(EmaSelfServeUpsertRequestSchema.safeParse({ ...body, entitlement_expires_at: now + 86_400 }).success).toBe(true);
		expect(EmaSelfServeUpsertRequestSchema.safeParse({ ...body, entitlement_expires_at: now - 86_400 }).success).toBe(true);
		const horizon = now + EMA_SELF_SERVE_MAX_ENTITLEMENT_SECONDS;
		expect(EmaSelfServeUpsertRequestSchema.safeParse({ ...body, entitlement_expires_at: horizon - 60 }).success).toBe(true);
		expect(EmaSelfServeUpsertRequestSchema.safeParse({ ...body, entitlement_expires_at: horizon + 60 }).success).toBe(false);
		expect(EmaSelfServeUpsertRequestSchema.safeParse({ ...body, entitlement_expires_at: now + 1.5 }).success).toBe(false);
	});
});
