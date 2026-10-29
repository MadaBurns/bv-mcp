import { env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
	deleteEmaTenant,
	effectiveApproval,
	getEmaTenant,
	getEmaTenantByIssuer,
	hasRejectedIssuer,
	isEmaTokenLive,
	isSharedIssuer,
	isTenantActive,
	issuerHash,
	listEmaTenants,
	normalizeIssuer,
	tenantEpoch,
	writeEmaTenant,
	type EmaOperatorUpsert,
	type EmaRegistry,
	type EmaWriteResult,
} from '../../src/oauth/ema-tenants';
import { parseEnvelopeKey, sealKv } from '../../src/lib/kv-envelope';
import { emaRegistryRequest, resetQuotaCoordinatorState } from '../../src/lib/quota-coordinator';
import { sha256Hex } from '../../src/oauth/jwks';
import { StrongStateUnavailableError } from '../../src/oauth/storage';
import { OAUTH_KV_PREFIX } from '../../src/lib/config';
import {
	EMA_SELF_SERVE_MAX_ENTITLEMENT_SECONDS,
	EmaSelfServeUpsertRequestSchema,
	EmaTenantRecordSchema,
	EmaTenantUpsertRequestSchema,
	type EmaTenantRecord,
} from '../../src/schemas/ema';
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
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});
afterEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, OAUTH_KV_PREFIX);
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
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

describe('EMA tenant registry (contract A11)', () => {
	const REGISTRY: EmaRegistry = { coordinator: env.QUOTA_COORDINATOR, kv: env.SESSION_STORE, kvEnvelopeKey: ENVELOPE_KEY };
	const operatorBody = (overrides: Partial<EmaOperatorUpsert> = {}): EmaOperatorUpsert => {
		const { created_at: _c, updated_at: _u, ...fields } = tenant();
		return { ...fields, ...overrides } as EmaOperatorUpsert;
	};
	const upsert = (overrides: Partial<EmaOperatorUpsert> = {}) =>
		writeEmaTenant(REGISTRY, overrides.tenant_id ?? 'acme-corp', { op: 'operator-upsert', body: operatorBody(overrides) });
	const record = async (result: Promise<EmaWriteResult>) => {
		const settled = await result;
		if (!('record' in settled) || !settled.record) throw new Error(`write refused: ${JSON.stringify(settled)}`);
		return settled.record;
	};
	const putLegacy = async (rec: EmaTenantRecord, key: Uint8Array | null = ENVELOPE_KEY) => {
		await env.SESSION_STORE.put(
			`${OAUTH_KV_PREFIX}ema-tenant:${rec.tenant_id}`,
			key ? await sealKv(JSON.stringify(rec), key) : JSON.stringify(rec),
		);
		await env.SESSION_STORE.put(`${OAUTH_KV_PREFIX}ema-issuer:${await sha256Hex(normalizeIssuer(rec.issuer))}`, rec.tenant_id);
	};

	it('upsert then get / getByIssuer / list round-trips, with the issuer stored and looked up in normalized form', async () => {
		const stored = await record(upsert({ issuer: 'https://IDP.example.com/oauth2/default/' }));
		expect(stored.issuer).toBe('https://idp.example.com/oauth2/default');
		expect(await getEmaTenant(REGISTRY, 'acme-corp')).toEqual(stored);
		expect((await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com/oauth2/default/'))?.tenant_id).toBe('acme-corp');
		expect((await listEmaTenants(REGISTRY)).records).toEqual([stored]);
		expect(await getEmaTenantByIssuer(REGISTRY, 'https://other.example.com')).toBeNull();
		expect(await getEmaTenantByIssuer(REGISTRY, 'not a url')).toBeNull();
		expect(await getEmaTenantByIssuer(REGISTRY, 'http://idp.example.com/oauth2/default')).toBeNull();
		expect(await getEmaTenant(REGISTRY, 'missing-tenant')).toBeNull();
	});

	it('only an approved tenant owns its issuer: a second approved tenant is issuer_conflict and nothing is stored', async () => {
		await record(upsert());
		expect(await upsert({ tenant_id: 'other-corp', issuer: 'https://idp.example.com/' })).toEqual({ status: 'issuer_conflict' });
		expect(await getEmaTenant(REGISTRY, 'other-corp')).toBeNull();
		// A pending one may name it; it neither claims nor blocks the issuer.
		await record(upsert({ tenant_id: 'other-corp', approval: 'pending' }));
		expect((await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com'))?.tenant_id).toBe('acme-corp');
		// Leaving approval releases it; an issuer move releases the old one.
		await record(upsert({ approval: 'rejected' }));
		expect(await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com')).toBeNull();
		await record(upsert({ approval: 'approved', issuer: 'https://idp2.example.com', jwks_uri: 'https://idp2.example.com/keys' }));
		expect((await getEmaTenantByIssuer(REGISTRY, 'https://idp2.example.com'))?.tenant_id).toBe('acme-corp');
	});

	it('the epoch only moves forward: kept on a rename, a re-enable and an added client; bumped on a disable, ANY tier change and a dropped client', async () => {
		const created = tenantEpoch(await record(upsert()));
		expect(tenantEpoch(await record(upsert({ name: 'Renamed' })))).toBe(created);
		const disabled = tenantEpoch(await record(upsert({ enabled: false })));
		expect(disabled).toBeGreaterThan(created);
		expect(tenantEpoch(await record(upsert({ enabled: true })))).toBe(disabled);
		const upgraded = tenantEpoch(await record(upsert({ tier: 'developer' })));
		expect(upgraded).toBeGreaterThan(disabled);
		const reTiered = tenantEpoch(await record(upsert({ tier: 'enterprise' })));
		expect(reTiered).toBeGreaterThan(upgraded);
		// M3: adding a client keeps the epoch; removing one revokes every token, the removed client's included.
		const twoClients = [CLAUDE_WEB_CLIENT_ID, 'https://other.example.com/client.json'];
		expect(tenantEpoch(await record(upsert({ allowed_client_ids: twoClients })))).toBe(reTiered);
		expect(tenantEpoch(await record(upsert({ allowed_client_ids: [CLAUDE_WEB_CLIENT_ID] })))).toBeGreaterThan(reTiered);
	});

	it('delete moves the floor one past the last epoch, so a re-created tenant starts above every epoch and rev the id ever had', async () => {
		await record(upsert());
		const deleted = await record(upsert({ enabled: false }));
		expect(await deleteEmaTenant(REGISTRY, 'acme-corp', 'operator')).toEqual({ status: 'ok', record: null });
		expect(await getEmaTenant(REGISTRY, 'acme-corp')).toBeNull();
		expect(await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com')).toBeNull();
		// M4: floor = last + 1, re-create = max(floor, prev) + 1.
		const recreated = await record(upsert());
		expect(tenantEpoch(recreated)).toBe(tenantEpoch(deleted) + 2);
		expect(recreated.rev).toBe((deleted.rev ?? 0) + 1);
		// Deleting an id that was never stored is a no-op that still marks it known.
		expect(await deleteEmaTenant(REGISTRY, 'never-stored', 'operator')).toEqual({ status: 'ok', record: null });
	});

	it('approve is a compare-and-set on issuer, keys and rev of the fresh record; reject and approve of a missing tenant are not_found', async () => {
		const pending = await record(upsert({ approval: 'pending' }));
		const reviewed = { issuer: pending.issuer, jwks_uri: pending.jwks_uri, rev: pending.rev ?? 0 };
		expect(
			await writeEmaTenant(REGISTRY, 'acme-corp', { op: 'approve', reviewed: { ...reviewed, jwks_uri: 'https://x.example/k' } }),
		).toEqual({
			status: 'approval_stale',
		});
		// M6: any write after the review moves rev, even one in the same second on the same issuer and keys.
		const changed = await record(upsert({ approval: 'pending', tier: 'developer' }));
		expect(changed.updated_at - pending.updated_at).toBeLessThanOrEqual(1);
		expect(await writeEmaTenant(REGISTRY, 'acme-corp', { op: 'approve', reviewed })).toEqual({ status: 'approval_stale' });
		const approved = await record(
			writeEmaTenant(REGISTRY, 'acme-corp', { op: 'approve', reviewed: { ...reviewed, rev: changed.rev ?? 0 } }),
		);
		expect(approved.approval).toBe('approved');
		expect(await writeEmaTenant(REGISTRY, 'missing-tenant', { op: 'reject' })).toEqual({ status: 'not_found' });
	});

	it('a self-serve write with expected_rev applies only at the current rev; expected_rev is never stored (SQ-473)', async () => {
		const discovered = { issuer: 'https://idp.example.com', jwks_uri: 'https://idp.example.com/keys' };
		const body = {
			name: 'Acme',
			issuer: 'https://idp.example.com',
			enabled: true,
			tier: 'enterprise' as const,
			entitlement_expires_at: Math.floor(Date.now() / 1000) + 3600,
		};
		const id = 'web-acme-0000-0001';
		// An absent record never matches a named revision, rev 0 included: nothing is created.
		expect(await writeEmaTenant(REGISTRY, id, { op: 'self-serve-upsert', body: { ...body, expected_rev: 0 }, discovered })).toEqual({
			status: 'ema_record_changed',
		});
		expect(await getEmaTenant(REGISTRY, id)).toBeNull();

		const created = await record(writeEmaTenant(REGISTRY, id, { op: 'self-serve-upsert', body, discovered }));
		const matched = await record(
			writeEmaTenant(REGISTRY, id, { op: 'self-serve-upsert', body: { ...body, name: 'Matched', expected_rev: created.rev }, discovered }),
		);
		expect(matched).toMatchObject({ name: 'Matched', rev: (created.rev ?? 0) + 1 });
		expect(matched).not.toHaveProperty('expected_rev');

		// The previous rev is now stale: refused, and the stored record is untouched.
		expect(
			await writeEmaTenant(REGISTRY, id, {
				op: 'self-serve-upsert',
				body: { ...body, name: 'Stale', expected_rev: created.rev },
				discovered,
			}),
		).toEqual({ status: 'ema_record_changed' });
		expect(await getEmaTenant(REGISTRY, id)).toEqual(matched);
	});

	it('a self-serve write that skipped discovery on a record that has since changed is ema_record_changed (retryable)', async () => {
		const body = {
			name: 'Acme',
			issuer: 'https://idp.example.com',
			enabled: true,
			tier: 'enterprise' as const,
			entitlement_expires_at: Math.floor(Date.now() / 1000) + 3600,
		};
		expect(await writeEmaTenant(REGISTRY, 'web-acme-0000-0001', { op: 'self-serve-upsert', body })).toEqual({
			status: 'ema_record_changed',
		});
		const discovered = { issuer: 'https://idp.example.com', jwks_uri: 'https://idp.example.com/keys' };
		// Discovery for a different issuer than the body names is the same refusal.
		expect(
			await writeEmaTenant(REGISTRY, 'web-acme-0000-0001', {
				op: 'self-serve-upsert',
				body,
				discovered: { ...discovered, issuer: 'https://x.example' },
			}),
		).toEqual({ status: 'ema_record_changed' });
		expect((await record(writeEmaTenant(REGISTRY, 'web-acme-0000-0001', { op: 'self-serve-upsert', body, discovered }))).approval).toBe(
			'pending',
		);
		await record(upsert({ tenant_id: 'beta-corp', issuer: 'https://beta.example.com' }));
		expect(await writeEmaTenant(REGISTRY, 'beta-corp', { op: 'self-serve-upsert', body, discovered })).toEqual({
			status: 'tenant_managed_by_operator',
		});
		expect(await deleteEmaTenant(REGISTRY, 'beta-corp', 'self-serve')).toEqual({ status: 'tenant_managed_by_operator' });
	});

	it('lists one page per call in tenant_id order, filtered by approval, with a cursor to the next page', async () => {
		for (const [id, n] of [
			['tenant-a', 1],
			['tenant-b', 2],
			['tenant-c', 3],
		] as const) {
			await record(upsert({ tenant_id: id, issuer: `https://idp${n}.example.com`, approval: n === 2 ? 'pending' : 'approved' }));
		}
		expect((await listEmaTenants(REGISTRY, 'pending')).records.map((r) => r.tenant_id)).toEqual(['tenant-b']);
		const page = await registryList({ limit: 2 });
		expect(page.records.map((r) => r.tenant_id)).toEqual(['tenant-a', 'tenant-b']);
		expect(page.cursor).toBe('tenant-b');
		expect((await listEmaTenants(REGISTRY, undefined, page.cursor)).records.map((r) => r.tenant_id)).toEqual(['tenant-c']);
	});

	it('M5: imports EVERY legacy KV tenant in one transaction on first use, keeps epochs and KV copies, and never reads KV again', async () => {
		await putLegacy(tenant({ token_epoch: 42 }));
		// A record from before token_epoch keeps created_at, the epoch its tokens carry.
		await putLegacy(tenant({ tenant_id: 'beta-corp', issuer: 'https://beta.example.com' }));
		const imported = (await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com'))!;
		expect(imported.tenant_id).toBe('acme-corp');
		expect(tenantEpoch(imported)).toBe(42);
		expect(tenantEpoch((await getEmaTenant(REGISTRY, 'beta-corp'))!)).toBe(1_700_000_000);
		expect((await listEmaTenants(REGISTRY)).records.map((r) => r.tenant_id)).toEqual(['acme-corp', 'beta-corp']);
		// The KV copies stay (one release of rollback), but the registry never consults them again.
		expect((await env.SESSION_STORE.list({ prefix: `${OAUTH_KV_PREFIX}ema-tenant:` })).keys).toHaveLength(2);
		expect(await deleteEmaTenant(REGISTRY, 'acme-corp', 'operator')).toEqual({ status: 'ok', record: null });
		await putLegacy(tenant({ tenant_id: 'gamma-corp', issuer: 'https://gamma.example.com' }));
		expect(await getEmaTenant(REGISTRY, 'acme-corp')).toBeNull();
		expect(await getEmaTenant(REGISTRY, 'gamma-corp')).toBeNull();
		expect(await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com')).toBeNull();
	});

	it('M5: the tenant the legacy issuer index named keeps its issuer when two approved legacy records list it', async () => {
		await putLegacy(tenant({ tenant_id: 'zeta-corp' }));
		// acme-corp lists the same issuer and sorts first, but the KV index never named it.
		await env.SESSION_STORE.put(`${OAUTH_KV_PREFIX}ema-tenant:acme-corp`, await sealKv(JSON.stringify(tenant()), ENVELOPE_KEY));
		expect((await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com'))?.tenant_id).toBe('zeta-corp');
	});

	it('M5: a legacy record the import cannot read keeps EVERY call at 503 and imports nothing; planted plaintext is ignored', async () => {
		await putLegacy(tenant());
		await putLegacy(tenant({ tenant_id: 'beta-corp', issuer: 'https://beta.example.com' }), null);
		await expect(getEmaTenant({ ...REGISTRY, kvEnvelopeKey: undefined }, 'beta-corp')).rejects.toBeInstanceOf(StrongStateUnavailableError);
		await expect(getEmaTenant({ ...REGISTRY, kvEnvelopeKey: new Uint8Array(32).fill(3) }, 'other-corp')).rejects.toBeInstanceOf(
			StrongStateUnavailableError,
		);
		// Without the SESSION_STORE nothing proves the legacy keyspace empty: unmigrated, so 503 too.
		await expect(getEmaTenant({ coordinator: env.QUOTA_COORDINATOR }, 'acme-corp')).rejects.toBeInstanceOf(StrongStateUnavailableError);
		expect(await emaRegistryRequest({ kind: 'ema-get', tenantId: 'acme-corp' }, env.QUOTA_COORDINATOR)).toEqual({
			status: 'ema_not_migrated',
		});
		// With the key the import completes; the planted plaintext beta-corp is not imported.
		expect((await getEmaTenant(REGISTRY, 'acme-corp'))?.tenant_id).toBe('acme-corp');
		expect(await getEmaTenant(REGISTRY, 'beta-corp')).toBeNull();
	});

	it('no coordinator binding is StrongStateUnavailableError for every registry call (never a value)', async () => {
		const none: EmaRegistry = { coordinator: undefined, kv: env.SESSION_STORE };
		await expect(getEmaTenant(none, 'acme-corp')).rejects.toBeInstanceOf(StrongStateUnavailableError);
		await expect(getEmaTenantByIssuer(none, 'https://idp.example.com')).rejects.toBeInstanceOf(StrongStateUnavailableError);
		await expect(writeEmaTenant(none, 'acme-corp', { op: 'reject' })).rejects.toBeInstanceOf(StrongStateUnavailableError);
		await expect(isEmaTokenLive(none, { sub: `ema:acme-corp:${'0'.repeat(32)}`, tier: 'enterprise', tep: 1 }, 0)).rejects.toBeInstanceOf(
			StrongStateUnavailableError,
		);
	});

	it('isEmaTokenLive needs the token tep to equal the record epoch, the record tier and an active tenant', async () => {
		const stored = await record(upsert());
		const claims = { sub: `ema:acme-corp:${'0'.repeat(32)}`, tier: 'enterprise', tep: tenantEpoch(stored) };
		const now = Math.floor(Date.now() / 1000);
		expect(await isEmaTokenLive(REGISTRY, claims, now)).toBe(true);
		expect(await isEmaTokenLive(REGISTRY, { ...claims, tep: tenantEpoch(stored) - 1 }, now)).toBe(false);
		expect(await isEmaTokenLive(REGISTRY, { ...claims, tier: 'developer' }, now)).toBe(false);
		expect(await isEmaTokenLive(REGISTRY, { ...claims, sub: 'ema:Bad_Id:x' }, now)).toBe(false);
		await record(upsert({ enabled: false }));
		expect(await isEmaTokenLive(REGISTRY, claims, now)).toBe(false);
	});

	it('hasRejectedIssuer matches the sha256 of the normalized issuer, and a missing record has no history', async () => {
		const rec = tenant({ rejected_issuer_hashes: [await issuerHash('https://idp.example.com')] });
		expect(await hasRejectedIssuer(rec, 'https://idp.example.com')).toBe(true);
		expect(await hasRejectedIssuer(rec, 'https://other.example.com')).toBe(false);
		expect(await hasRejectedIssuer(tenant(), 'https://idp.example.com')).toBe(false);
		expect(await hasRejectedIssuer(null, 'https://idp.example.com')).toBe(false);
	});

	it('the record schema bounds rejected_issuer_hashes: lowercase sha256 hex, at most 16', () => {
		const hash = 'a'.repeat(64);
		expect(EmaTenantRecordSchema.safeParse(tenant({ rejected_issuer_hashes: [hash] })).success).toBe(true);
		expect(EmaTenantRecordSchema.safeParse(tenant({ rejected_issuer_hashes: Array(17).fill(hash) })).success).toBe(false);
		expect(EmaTenantRecordSchema.safeParse(tenant({ rejected_issuer_hashes: ['https://idp.example.com'] })).success).toBe(false);
		expect(EmaTenantRecordSchema.safeParse(tenant({ rejected_issuer_hashes: ['A'.repeat(64)] })).success).toBe(false);
	});

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
});

/** One raw ema-list page straight from the registry shard (a smaller page than the route uses). */
async function registryList(opts: { limit: number; cursor?: string }) {
	const page = await emaRegistryRequest({ kind: 'ema-list', ...opts }, env.QUOTA_COORDINATOR);
	return page as { records: EmaTenantRecord[]; cursor?: string };
}

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
		// A bare authority host names no tenant; an encoded slash hides where the first segment ends.
		'https://login.microsoftonline.com',
		'https://login.windows.net/',
		'https://login.microsoftonline.com/%2Fcommon/v2.0',
		'https://login.microsoftonline.com/a%2fb/v2.0',
		'https://gitlab.com',
		'https://gitlab.com/some-group',
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
		'https://gitlab.acme.example.com',
		'https://google.com',
		'https://xaa.dev',
	])('allows the per-tenant or unrelated issuer %s', (issuer) => {
		expect(isSharedIssuer(normalizeIssuer(issuer))).toBe(false);
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
