// SPDX-License-Identifier: BUSL-1.1
// bv-oversize-ok: the registry rules, its transaction storage and the Worker client share private types; splitting them is a follow-up outside SQ-468.

/**
 * Enterprise Managed Auth (EMA) tenant registry: the per-tenant trusted-issuer allowlist.
 *
 * The authority (contract A11) is ONE dedicated QuotaCoordinator instance (EMA_REGISTRY_INSTANCE_NAME). Every
 * read and write is one `ema-*` request (EmaRegistryRequestSchema) run inside its storage transaction, so a
 * write is computed from the FRESH record and a mint or liveness check reads one record atomically. Keys sit
 * under `ema:`, outside the `quota:` prefix the cleanup alarm sweeps (runbook §8a has the operator view):
 *   ema:tenant:<tenant_id> → EmaTenantRecord (plaintext);  ema:issuer:<issuer> → the ONE approved owner's id;
 *   ema:floor:<tenant_id>  → { value, rev }: at or above every epoch and rev the id has had (survives a delete);
 *   ema:migrated           → set once the legacy import ran.
 * Legacy SESSION_STORE records (sealed by KV_ENVELOPE_KEY) are imported EAGERLY: until the marker exists every
 * other kind answers `ema_not_migrated`, and the Worker sends every legacy record in ONE `ema-migrate`
 * transaction, then asks again. KV is never written and, after the marker, never read.
 */

import {
	EMA_LIST_PAGE_LIMIT,
	EMA_MIGRATE_LIMIT,
	EMA_REJECTED_ISSUER_LIMIT,
	EMA_TENANT_ID_PATTERN,
	EmaRegistryRequestSchema,
	EmaTenantRecordSchema,
	type EmaApproval,
	type EmaApproveRequest,
	type EmaRegistryRequest,
	type EmaSelfServeUpsertRequest,
	type EmaTenantRecord,
	type EmaWrite,
} from '../schemas/ema';
import { OAUTH_KV_PREFIX } from '../lib/config';
import { openKv, isSealed } from '../lib/kv-envelope';
import { emaRegistryRequest, type QuotaCoordinator } from '../lib/quota-coordinator';
import { CLAUDE_WEB_CIMD_CLIENT_ID } from './cimd';
import { sha256Hex } from './jwks';
import { StrongStateUnavailableError } from './storage';

export { EMA_LIST_PAGE_LIMIT };
export type { EmaOperatorUpsert, EmaRegistryRequest, EmaWrite } from '../schemas/ema';

function isPlainHttpsUrl(url: URL): boolean {
	return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash;
}

/**
 * Canonical form of an issuer identifier: https only, no userinfo/query/fragment,
 * lowercase host, and every trailing slash stripped, so the result is a fixed point
 * (normalizing it again changes nothing). Throws on anything else.
 */
export function normalizeIssuer(iss: string): string {
	const url = new URL(iss);
	if (!isPlainHttpsUrl(url)) throw new Error('Issuer must be an https URL without userinfo, query or fragment');
	return url.origin + url.pathname.replace(/\/+$/, '');
}

/** normalizeIssuer, or null for an issuer it refuses. */
function normalizedOrNull(iss: string): string | null {
	try {
		return normalizeIssuer(iss);
	} catch {
		return null;
	}
}

/*
 * Shared (multi-tenant) issuers. One of these signs assertions for many unrelated organisations, so
 * allowlisting it for one tenant would let users of ANY other org on that IdP mint tokens for this
 * tenant: an issuer only identifies a tenant when the IdP is single-tenant (ID-JAG draft, section 6).
 * The self-serve route refuses these; the operator route leaves the call to the operator.
 */

/** Hosts shared outright, whatever the path. */
const SHARED_ISSUER_HOSTS = new Set([
	'accounts.google.com',
	'login.live.com',
	'appleid.apple.com',
	// The public Cross App Access playground: anyone can mint an assertion for any subject there.
	'idp.xaa.dev',
	// One issuer for the workflow tokens of every repository.
	'token.actions.githubusercontent.com',
	// One host for the tokens of every project.
	'securetoken.google.com',
	// One issuer for the CI job tokens of every project on the service.
	'gitlab.com',
]);

/** Host suffixes shared outright: one login domain for many unrelated directories. */
const SHARED_ISSUER_HOST_SUFFIXES = ['.b2clogin.com'];

/** Microsoft Entra authority hosts. They also serve per-tenant issuers (`/<tenant guid>/v2.0`), which stay allowed. */
const ENTRA_AUTHORITY_HOSTS = new Set([
	'login.microsoftonline.com',
	'login.microsoftonline.us',
	'login.microsoftonline.de',
	'login.partner.microsoftonline.cn',
	'login.microsoft.com',
	'login.windows.net',
	'sts.windows.net',
]);

/** Entra first path segments that name every tenant at once, whatever follows them. */
const ENTRA_MULTI_TENANT_SEGMENTS = new Set(['common', 'organizations', 'consumers', '{tenantid}']);

/**
 * The percent-decoded, lowercased first path segment once `//` runs collapse; null when there is none
 * (a bare host), when it hides a slash (`%2f`), or when it does not decode: all of which a caller treats as shared.
 */
function firstPathSegment(pathname: string): string | null {
	const segment = pathname.replace(/\/+/g, '/').split('/')[1] ?? '';
	if (segment === '' || /%2f/i.test(segment)) return null;
	try {
		return decodeURIComponent(segment).toLowerCase();
	} catch {
		return null;
	}
}

/**
 * True when a normalized issuer (see normalizeIssuer) is shared: a host in SHARED_ISSUER_HOSTS or under
 * a SHARED_ISSUER_HOST_SUFFIXES domain (trailing dots ignored), or an Entra authority host whose first
 * path segment is a multi-tenant alias, is missing, hides a slash or does not decode (all fail closed).
 */
export function isSharedIssuer(normalizedIssuer: string): boolean {
	const url = new URL(normalizedIssuer);
	const host = url.hostname.toLowerCase().replace(/\.+$/, '');
	if (SHARED_ISSUER_HOSTS.has(host) || SHARED_ISSUER_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix))) return true;
	if (!ENTRA_AUTHORITY_HOSTS.has(host)) return false;
	const segment = firstPathSegment(url.pathname);
	return segment === null || ENTRA_MULTI_TENANT_SEGMENTS.has(segment);
}

/**
 * A record's approval. An explicit value wins; without one, a self-serve record is pending (it was
 * never approved) and any other record is approved (operator-seeded before approval existed).
 */
export function effectiveApproval(rec: Pick<EmaTenantRecord, 'approval' | 'source'>): EmaApproval {
	return rec.approval ?? (rec.source === 'self-serve' ? 'pending' : 'approved');
}

const isApproved = (rec: Pick<EmaTenantRecord, 'approval' | 'source'>): boolean => effectiveApproval(rec) === 'approved';

const entitlementEnd = (rec: Pick<EmaTenantRecord, 'entitlement_expires_at'>): number => rec.entitlement_expires_at ?? Infinity;

/**
 * The one rule for whether a tenant may mint and back access tokens right now: enabled, approved and
 * inside its entitlement. The token grant (resolveTrustedTenant) and per-request liveness
 * (isEmaTokenLive) both use it, so a tenant failing it is refused exactly like an unknown one.
 */
export function isTenantActive(rec: EmaTenantRecord, nowSeconds: number): boolean {
	return rec.enabled && isApproved(rec) && entitlementEnd(rec) > nowSeconds;
}

/** Whether `record` may vouch for `issuer` in the issuer index: it lists the issuer and is approved. */
function vouchesFor(record: EmaTenantRecord | null, issuer: string): record is EmaTenantRecord {
	return record !== null && record.issuer === issuer && isApproved(record);
}

/** A stored tenant record (or floor) exists but cannot be honoured: corruption, or a legacy record sealed with a key we lack. */
export class EmaTenantUnreadableError extends Error {
	constructor() {
		super('Tenant record is unreadable');
		this.name = 'EmaTenantUnreadableError';
	}
}

/** Every EMA access token's subject is `ema:<tenant_id>:<32 hex of sha256(IdP sub)>`. */
export const EMA_SUBJECT_PREFIX = 'ema:';

/**
 * The epoch an EMA access token must carry as `tep`: the record's `token_epoch`, which the registry sets on
 * every record it stores or imports. A record from before the field existed falls back to `created_at`,
 * which is what the tokens minted under it carry.
 */
export function tenantEpoch(rec: EmaTenantRecord): number {
	return rec.token_epoch ?? rec.created_at;
}

/** sha256 (hex) of a normalized issuer: the form `rejected_issuer_hashes` holds. */
export const issuerHash = (normalizedIssuer: string): Promise<string> => sha256Hex(normalizedIssuer);

/** Whether the operator ever rejected `normalizedIssuer` for this tenant (a null record has no history). */
export async function hasRejectedIssuer(rec: EmaTenantRecord | null, normalizedIssuer: string): Promise<boolean> {
	return !!rec?.rejected_issuer_hashes?.includes(await issuerHash(normalizedIssuer));
}

/** Whether the operator ever refused this tenant: it is rejected now, or remembers an issuer it rejected before. */
const hasBeenRejected = (rec: EmaTenantRecord): boolean =>
	effectiveApproval(rec) === 'rejected' || (rec.rejected_issuer_hashes?.length ?? 0) > 0;

// ─── Write rules: pure, applied by the registry to the FRESH record inside its transaction ───

/** A tenant as a write decides it; the registry adds the server-managed timestamps, token epoch, rev and rejected issuers. */
export type EmaTenantDraft = Omit<EmaTenantRecord, 'created_at' | 'updated_at' | 'token_epoch' | 'rev' | 'rejected_issuer_hashes'>;

/** Whether a write takes a tenant out of a state (enabled, approved) it was in. */
const leaves = (before: boolean, after: boolean): boolean => before && !after;

/** Same issuer, same keys and same tier: the identity a minted token was bound to. */
function sameBinding(existing: EmaTenantRecord, next: EmaTenantDraft): boolean {
	return existing.issuer === next.issuer && existing.jwks_uri === next.jwks_uri && existing.tier === next.tier;
}

/** Whether `next` drops a client `existing` allowed: the tokens minted for that client go with it. */
const dropsClient = (existing: EmaTenantRecord, next: EmaTenantDraft): boolean =>
	existing.allowed_client_ids.some((clientId) => !next.allowed_client_ids.includes(clientId));

/**
 * Whether tokens minted under `existing` may keep standing once `next` is stored: same issuer, keys and
 * tier, no allowed client removed, still enabled and approved, and no earlier entitlement. Anything else
 * revokes them by moving the epoch, including a tier change (a round trip back to the old tier must not
 * revive them).
 */
export function keepsTokenEpoch(existing: EmaTenantRecord, next: EmaTenantDraft): boolean {
	return (
		sameBinding(existing, next) &&
		!dropsClient(existing, next) &&
		!leaves(existing.enabled, next.enabled) &&
		!leaves(isApproved(existing), isApproved(next)) &&
		entitlementEnd(next) >= entitlementEnd(existing)
	);
}

/**
 * The tenant's rejected-issuer history after a write: a rejected tenant's issuer is appended (the oldest is
 * dropped past EMA_REJECTED_ISSUER_LIMIT) and an approved tenant's issuer is removed, since the operator has
 * now accepted exactly that issuer. Pending leaves the list as it was.
 */
async function nextRejectedIssuerHashes(existing: EmaTenantRecord | null, next: EmaTenantDraft): Promise<string[] | undefined> {
	const hashes = existing?.rejected_issuer_hashes ?? [];
	const hash = await issuerHash(next.issuer);
	const others = hashes.filter((known) => known !== hash);
	const approval = effectiveApproval(next);
	const updated = approval === 'rejected' ? [...others, hash].slice(-EMA_REJECTED_ISSUER_LIMIT) : approval === 'approved' ? others : hashes;
	return updated.length > 0 ? updated : undefined;
}

/**
 * Approval after a self-serve write. An issuer the operator ever rejected for this tenant stays rejected,
 * wherever the tenant has moved since. Otherwise a new tenant, or a move to another issuer, waits for the
 * operator, and the stored decision stands ('rejected' is sticky), except that an approved tenant whose
 * rediscovered jwks_uri changed goes back to pending: the operator approved those keys, not these.
 */
async function selfServeApproval(existing: EmaTenantRecord | null, issuer: string, jwksUri: string): Promise<EmaApproval> {
	if (await hasRejectedIssuer(existing, issuer)) return 'rejected';
	if (!existing || existing.issuer !== issuer) return 'pending';
	const current = effectiveApproval(existing);
	return current === 'approved' && existing.jwks_uri !== jwksUri ? 'pending' : current;
}

const TIER_RANK: Record<EmaTenantRecord['tier'], number> = { developer: 0, enterprise: 1 };

/**
 * Whether a self-serve write only lowers what the stored tenant may do, so it needs no discovery: same
 * issuer, no tier increase, and either a disable (whatever expiry rides along: bv-web recomputes it from
 * the subscription, so it is often LATER than the stored one) or an enabled tenant whose expiry moves
 * earlier (a past value included). Such a write reuses the stored jwks_uri, so a revoke from bv-web lands
 * even while the IdP's discovery document is down or gone, and it never re-pends the tenant.
 */
export function lowersPrivilegeOnly(existing: EmaTenantRecord, body: EmaSelfServeUpsertRequest): boolean {
	if (existing.issuer !== body.issuer || TIER_RANK[body.tier] > TIER_RANK[existing.tier]) return false;
	return !body.enabled || (existing.enabled && body.entitlement_expires_at < entitlementEnd(existing));
}

/** The self-serve compare-and-set: a caller that named `expected_rev` still sees that revision (an absent record never matches). */
export function matchesExpectedRev(rec: EmaTenantRecord | null, expectedRev: number | undefined): boolean {
	return expectedRev === undefined || (rec !== null && (rec.rev ?? 0) === expectedRev);
}

/** The approve compare-and-set: the stored record is still the revision the operator reviewed, on the same issuer and keys. */
function matchesReviewed(rec: EmaTenantRecord, reviewed: EmaApproveRequest): boolean {
	return rec.issuer === reviewed.issuer && rec.jwks_uri === reviewed.jwks_uri && (rec.rev ?? 0) === reviewed.rev;
}

// ─── Registry protocol: the `ema-*` QuotaCoordinator request kinds (EmaRegistryRequestSchema) ───

/** A write the registry refused on the fresh record. `ema_record_changed` is retryable (rediscover, then write again). */
export type EmaWriteError = 'not_found' | 'approval_stale' | 'issuer_conflict' | 'tenant_managed_by_operator' | 'ema_record_changed';

/**
 * Why the registry could not answer: the legacy import has not run, a stored record or floor does not parse,
 * or the request did not validate. The Worker turns each into a retryable 503, never a 401.
 */
export type EmaStoreStatus = 'ema_not_migrated' | 'ema_store_unavailable' | 'invalid_request';

export type EmaRecordResult = { status: 'ok'; record: EmaTenantRecord | null };
export type EmaWriteResult = EmaRecordResult | { status: EmaWriteError };
export type EmaListResult = { status: 'ok'; records: EmaTenantRecord[]; cursor?: string };
export type EmaMigrateResult = { status: 'ok'; imported: number };
export type EmaRegistryResponse = EmaWriteResult | EmaListResult | EmaMigrateResult | { status: EmaStoreStatus };

/** The coordinator's door check for the `ema-*` kinds (any other kind passes untouched): a static message, never the input. */
export function emaRegistryPayloadError(obj: Record<string, unknown>): string | undefined {
	if (typeof obj.kind !== 'string' || !obj.kind.startsWith('ema-')) return undefined;
	return EmaRegistryRequestSchema.safeParse(obj).success ? undefined : `Invalid ${obj.kind} request`;
}

// ─── Registry storage: runs INSIDE the registry instance's storage transaction ───

const RECORD_PREFIX = 'ema:tenant:';
const ISSUER_PREFIX = 'ema:issuer:';
/** Registry storage keys. Exported for tests that seed or inspect the registry directly. */
export const emaRecordStorageKey = (tenantId: string): string => `${RECORD_PREFIX}${tenantId}`;
export const emaIssuerStorageKey = (normalizedIssuer: string): string => `${ISSUER_PREFIX}${normalizedIssuer}`;
export const emaFloorStorageKey = (tenantId: string): string => `ema:floor:${tenantId}`;
export const EMA_MIGRATED_STORAGE_KEY = 'ema:migrated';

/** The most record keys one `ema-list` request scans, bounding the work a filtered page can do. */
const EMA_LIST_SCAN_LIMIT = 1000;

type Txn = DurableObjectTransaction;

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

const OK_NULL: EmaRecordResult = { status: 'ok', record: null };
const NOT_FOUND = { status: 'not_found' } as const;

/** Drop undefined-valued keys, so a stored record has exactly the fields that are set. */
const compact = <T extends object>(value: T): T => Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as T;

/** A stored value as the record of `tenantId`, or null when it is not one. */
function storedRecord(raw: unknown, tenantId: string): EmaTenantRecord | null {
	const parsed = EmaTenantRecordSchema.safeParse(raw);
	return parsed.success && parsed.data.tenant_id === tenantId ? parsed.data : null;
}

/** The record of `tenantId`; null when none is stored. A stored value that is not a valid record throws (a 503, never absence). */
async function readRecordTx(txn: Txn, tenantId: string): Promise<EmaTenantRecord | null> {
	const raw = await txn.get(emaRecordStorageKey(tenantId));
	if (raw === undefined) return null;
	const record = storedRecord(raw, tenantId);
	if (!record) throw new EmaTenantUnreadableError();
	return record;
}

/** An id's high-water marks, kept across deletes: its highest token epoch and rev. */
interface EmaFloor {
	value: number;
	rev: number;
}

const isCount = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;

/**
 * The id's floor, zeros when the registry never stored the id. Read with a plain get: a floor that is
 * missing must read as missing, never be manufactured. One that does not parse throws (a 503): reading it as
 * zero could hand a re-created tenant an epoch an old token still carries.
 */
async function floorTx(txn: Txn, tenantId: string): Promise<EmaFloor> {
	const raw = await txn.get<Partial<EmaFloor>>(emaFloorStorageKey(tenantId));
	if (raw === undefined) return { value: 0, rev: 0 };
	if (!isCount(raw?.value)) throw new EmaTenantUnreadableError();
	return { value: raw.value, rev: isCount(raw.rev) ? raw.rev : 0 };
}

/** Raise the id's floor to cover `epoch` and `rev`; it never lowers. */
async function raiseFloorTx(txn: Txn, tenantId: string, epoch: number, rev: number): Promise<void> {
	const floor = await floorTx(txn, tenantId);
	await txn.put(emaFloorStorageKey(tenantId), { value: Math.max(floor.value, epoch), rev: Math.max(floor.rev, rev) });
}

/** The highest token epoch the id has used: its floor, or its record's epoch if that is higher. */
const lastEpoch = (floor: EmaFloor, existing: EmaTenantRecord | null): number =>
	Math.max(floor.value, existing ? tenantEpoch(existing) : 0);

/**
 * The token epoch a write stores. It keeps the record's epoch only when keepsTokenEpoch allows it; every
 * other write (a create included) moves it past the last epoch the id ever used, so no token minted under
 * any earlier version of this id, a deleted one included, can match it again.
 */
function nextTokenEpoch(floor: EmaFloor, existing: EmaTenantRecord | null, draft: EmaTenantDraft): number {
	if (existing && keepsTokenEpoch(existing, draft)) return tenantEpoch(existing);
	return lastEpoch(floor, existing) + 1;
}

/** Whether a DIFFERENT approved tenant holds `record`'s issuer. A stale entry (its record moved, left approval or is unreadable) does not. */
async function issuerHeldByAnother(txn: Txn, record: EmaTenantRecord): Promise<boolean> {
	const owner = await txn.get<string>(emaIssuerStorageKey(record.issuer));
	if (typeof owner !== 'string' || owner === record.tenant_id) return false;
	return vouchesFor(storedRecord(await txn.get(emaRecordStorageKey(owner)), owner), record.issuer);
}

/** Delete an issuer's index entry, but only while it still points at `tenantId`. */
async function releaseIssuerTx(txn: Txn, issuer: string, tenantId: string): Promise<void> {
	const key = emaIssuerStorageKey(issuer);
	if ((await txn.get<string>(key)) === tenantId) await txn.delete(key);
}

/** Delete every issuer index entry that points at `tenantId` (its record cannot be read, so its issuer is unknown). */
async function releaseIssuersOwnedByTx(txn: Txn, tenantId: string): Promise<void> {
	const owned = [...(await txn.list<string>({ prefix: ISSUER_PREFIX }))].filter(([, owner]) => owner === tenantId);
	for (const [key] of owned) await txn.delete(key);
}

/** Store a record, raise its floor, and point (claimsIssuer) or release its issuer index entry. */
async function putRecordTx(txn: Txn, record: EmaTenantRecord, previous: EmaTenantRecord | null, claimsIssuer: boolean): Promise<void> {
	await txn.put(emaRecordStorageKey(record.tenant_id), record);
	await raiseFloorTx(txn, record.tenant_id, tenantEpoch(record), record.rev ?? 0);
	if (claimsIssuer) await txn.put(emaIssuerStorageKey(record.issuer), record.tenant_id);
	if (previous && (previous.issuer !== record.issuer || !claimsIssuer)) await releaseIssuerTx(txn, previous.issuer, record.tenant_id);
}

/** The record a write stores: created_at kept, updated_at stamped, and epoch, rev and rejected issuers derived, never taken from a caller. */
function composeRecord(
	draft: EmaTenantDraft,
	existing: EmaTenantRecord | null,
	floor: EmaFloor,
	rejected: string[] | undefined,
): EmaTenantRecord {
	const now = nowSeconds();
	return EmaTenantRecordSchema.parse(
		compact({
			...draft,
			created_at: existing?.created_at ?? now,
			updated_at: now,
			token_epoch: nextTokenEpoch(floor, existing, draft),
			rev: Math.max(floor.rev, existing?.rev ?? 0) + 1,
			rejected_issuer_hashes: rejected,
		}),
	);
}

/**
 * The one store path of every write, applied to the fresh record (composeRecord). Only an APPROVED tenant
 * owns its issuer: approving one whose issuer another approved tenant holds is `issuer_conflict`, and
 * nothing is stored.
 */
async function storeTx(txn: Txn, existing: EmaTenantRecord | null, input: EmaTenantDraft): Promise<EmaWriteResult> {
	const draft: EmaTenantDraft = { ...input, issuer: normalizeIssuer(input.issuer) };
	const record = composeRecord(draft, existing, await floorTx(txn, draft.tenant_id), await nextRejectedIssuerHashes(existing, draft));
	const claimsIssuer = isApproved(record);
	if (claimsIssuer && (await issuerHeldByAnother(txn, record))) return { status: 'issuer_conflict' };
	await putRecordTx(txn, record, existing, claimsIssuer);
	return { status: 'ok', record };
}

/**
 * Remove a tenant and its issuer index entry (every entry naming it, when its record cannot be read), and
 * move its floor one past the last epoch it used, so a re-created tenant starts above every token it minted.
 */
async function removeTx(txn: Txn, tenantId: string): Promise<EmaWriteResult> {
	const raw = await txn.get(emaRecordStorageKey(tenantId));
	const existing = storedRecord(raw, tenantId);
	await txn.delete(emaRecordStorageKey(tenantId));
	if (existing) await releaseIssuerTx(txn, existing.issuer, tenantId);
	else if (raw !== undefined) await releaseIssuersOwnedByTx(txn, tenantId);
	await raiseFloorTx(txn, tenantId, lastEpoch(await floorTx(txn, tenantId), existing) + 1, 0);
	return OK_NULL;
}

/** Whether the registry already knows the id: it holds a record or a floor for it. */
const isKnownTx = async (txn: Txn, tenantId: string): Promise<boolean> =>
	(await txn.get(emaRecordStorageKey(tenantId))) !== undefined || (await txn.get(emaFloorStorageKey(tenantId))) !== undefined;

/**
 * Import one legacy record, unless the registry already knows its id or its issuer does not normalize (it
 * could never have minted). It keeps its epoch, so tokens minted under it keep working, and it claims its
 * issuer when approved and no other approved tenant already holds it.
 */
async function importTx(txn: Txn, legacy: EmaTenantRecord): Promise<boolean> {
	const issuer = normalizedOrNull(legacy.issuer);
	if (issuer === null || (await isKnownTx(txn, legacy.tenant_id))) return false;
	const record = EmaTenantRecordSchema.parse(compact({ ...legacy, issuer, token_epoch: tenantEpoch(legacy), rev: legacy.rev ?? 0 }));
	await putRecordTx(txn, record, null, isApproved(record) && !(await issuerHeldByAnother(txn, record)));
	return true;
}

/** The one-time legacy import: every record in ONE transaction, then the marker. Once the marker exists it does nothing. */
async function migrateTx(txn: Txn, records: EmaTenantRecord[]): Promise<EmaMigrateResult> {
	if ((await txn.get(EMA_MIGRATED_STORAGE_KEY)) !== undefined) return { status: 'ok', imported: 0 };
	let imported = 0;
	for (const legacy of records) if (await importTx(txn, legacy)) imported += 1;
	await txn.put(EMA_MIGRATED_STORAGE_KEY, { at: nowSeconds(), imported });
	return { status: 'ok', imported };
}

/** An operator decision on the fresh record; approve also holds the reviewed compare-and-set. */
function decision(
	existing: EmaTenantRecord | null,
	approval: EmaApproval,
	reviewed?: EmaApproveRequest,
): EmaTenantDraft | { status: EmaWriteError } {
	if (!existing) return NOT_FOUND;
	if (reviewed && !matchesReviewed(existing, reviewed)) return { status: 'approval_stale' };
	return { ...existing, approval };
}

type SelfServeWrite = Extract<EmaWrite, { op: 'self-serve-upsert' }>;

/**
 * The jwks_uri a self-serve write stores, decided on the FRESH record: the stored one for a write that only
 * lowers privilege, else the one discovered for the body's issuer. Undefined when the Worker skipped
 * discovery for a record that has since changed (ema_record_changed: rediscover and retry).
 */
function selfServeJwksUri(
	existing: EmaTenantRecord | null,
	body: EmaSelfServeUpsertRequest,
	discovered: SelfServeWrite['discovered'],
): string | undefined {
	if (existing && lowersPrivilegeOnly(existing, body)) return existing.jwks_uri;
	return discovered?.issuer === body.issuer ? discovered.jwks_uri : undefined;
}

/**
 * A customer-managed tenant as a self-serve write decides it. Only the body is the customer's: jwks_uri is
 * the discovered (or, for a lowering write, the stored) one and the client allowlist is the default.
 */
async function selfServeDraft(
	existing: EmaTenantRecord | null,
	tenantId: string,
	write: SelfServeWrite,
): Promise<EmaTenantDraft | { status: EmaWriteError }> {
	if (existing && existing.source !== 'self-serve') return { status: 'tenant_managed_by_operator' };
	if (!matchesExpectedRev(existing, write.body.expected_rev)) return { status: 'ema_record_changed' };
	const { expected_rev: _expectedRev, ...fields } = write.body;
	const body = { ...fields, issuer: normalizeIssuer(fields.issuer) };
	const jwksUri = selfServeJwksUri(existing, body, write.discovered);
	if (!jwksUri) return { status: 'ema_record_changed' };
	return {
		...body,
		tenant_id: tenantId,
		allowed_client_ids: [CLAUDE_WEB_CIMD_CLIENT_ID],
		jwks_uri: jwksUri,
		approval: await selfServeApproval(existing, body.issuer, jwksUri),
		source: 'self-serve',
	};
}

/**
 * The draft each write op derives from the fresh record. Operator upsert: an omitted `approval` keeps the
 * stored one, and `source` never comes from the body (an operator edit never takes a tenant away from the
 * customer settings that sync it).
 */
const DRAFTS: {
	[K in EmaWrite['op']]: (
		existing: EmaTenantRecord | null,
		tenantId: string,
		write: Extract<EmaWrite, { op: K }>,
	) => Promise<EmaTenantDraft | { status: EmaWriteError }>;
} = {
	'operator-upsert': async (existing, tenantId, { body }) => ({
		...body,
		tenant_id: tenantId,
		approval: body.approval ?? existing?.approval,
		source: existing?.source ?? 'operator',
	}),
	'self-serve-upsert': selfServeDraft,
	approve: async (existing, _tenantId, { reviewed }) => decision(existing, 'approved', reviewed),
	reject: async (existing) => decision(existing, 'rejected'),
};

async function writeTx(txn: Txn, tenantId: string, write: EmaWrite): Promise<EmaWriteResult> {
	const existing = await readRecordTx(txn, tenantId);
	const draftFor = DRAFTS[write.op] as (
		e: EmaTenantRecord | null,
		t: string,
		w: EmaWrite,
	) => Promise<EmaTenantDraft | { status: EmaWriteError }>;
	const draft = await draftFor(existing, tenantId, write);
	return 'status' in draft ? draft : storeTx(txn, existing, draft);
}

/**
 * Delete. The operator's removes the record outright. The self-serve one refuses an operator-managed tenant,
 * and keeps a tenant the operator ever rejected as a disabled, lapsed tombstone that carries its rejected
 * issuers, so deleting and re-creating cannot launder a refusal. Either way its tokens die.
 */
async function deleteTx(txn: Txn, tenantId: string, mode: 'operator' | 'self-serve'): Promise<EmaWriteResult> {
	if (mode === 'operator') return removeTx(txn, tenantId);
	const existing = await readRecordTx(txn, tenantId);
	if (!existing) return OK_NULL;
	if (existing.source !== 'self-serve') return { status: 'tenant_managed_by_operator' };
	if (!hasBeenRejected(existing)) return removeTx(txn, tenantId);
	return storeTx(txn, existing, { ...existing, enabled: false, entitlement_expires_at: nowSeconds() });
}

/** A stored value as a list entry: a valid record passing the approval filter, else null (unreadable entries are skipped). */
function listedRecord(key: string, raw: unknown, approval: EmaApproval | undefined): EmaTenantRecord | null {
	const record = storedRecord(raw, key.slice(RECORD_PREFIX.length));
	return record && (!approval || effectiveApproval(record) === approval) ? record : null;
}

type ParsedRequest = ReturnType<typeof EmaRegistryRequestSchema.parse>;

/** One page of records (id order) after `cursor`; `cursor` in the result names where the next page starts. */
async function listTx(txn: Txn, req: Extract<ParsedRequest, { kind: 'ema-list' }>): Promise<EmaListResult> {
	const startAfter = req.cursor === undefined ? undefined : emaRecordStorageKey(req.cursor);
	const scanned = await txn.list({ prefix: RECORD_PREFIX, startAfter, limit: EMA_LIST_SCAN_LIMIT });
	const records: EmaTenantRecord[] = [];
	let last: string | undefined;
	for (const [key, raw] of scanned) {
		if (records.length === req.limit) return { status: 'ok', records, cursor: last };
		last = key.slice(RECORD_PREFIX.length);
		const record = listedRecord(key, raw, req.approval);
		if (record) records.push(record);
	}
	return scanned.size === EMA_LIST_SCAN_LIMIT ? { status: 'ok', records, cursor: last } : { status: 'ok', records };
}

/** The APPROVED tenant that owns `issuer` (already normalized), else null. */
async function resolveIssuerTx(txn: Txn, issuer: string): Promise<EmaRecordResult> {
	const owner = await txn.get<string>(emaIssuerStorageKey(issuer));
	const record = typeof owner === 'string' ? await readRecordTx(txn, owner) : null;
	return { status: 'ok', record: vouchesFor(record, issuer) ? record : null };
}

type ServedKind = Exclude<ParsedRequest['kind'], 'ema-migrate'>;

const EMA_HANDLERS: {
	[K in ServedKind]: (txn: Txn, payload: Extract<ParsedRequest, { kind: K }>) => Promise<EmaRegistryResponse>;
} = {
	'ema-get': async (txn, payload) => ({ status: 'ok', record: await readRecordTx(txn, payload.tenantId) }),
	'ema-list': listTx,
	'ema-resolve-issuer': (txn, payload) => resolveIssuerTx(txn, payload.issuer),
	'ema-write': (txn, payload) => writeTx(txn, payload.tenantId, payload.write),
	'ema-delete': (txn, payload) => deleteTx(txn, payload.tenantId, payload.mode),
};

/** One request inside the transaction: the import itself, else a served kind once the import has run. */
async function serveTx(txn: Txn, req: ParsedRequest): Promise<EmaRegistryResponse> {
	if (req.kind === 'ema-migrate') return migrateTx(txn, req.records);
	if ((await txn.get(EMA_MIGRATED_STORAGE_KEY)) === undefined) return { status: 'ema_not_migrated' };
	const handler = EMA_HANDLERS[req.kind] as (txn: Txn, payload: ParsedRequest) => Promise<EmaRegistryResponse>;
	return handler(txn, req);
}

/**
 * Run one `ema-*` request inside the registry instance's storage transaction (QuotaCoordinator calls this).
 * It answers a status union, never a thrown refusal: a payload that does not validate is `invalid_request`,
 * and a stored record or floor that does not parse is `ema_store_unavailable`, after the transaction rolled
 * back. Anything else (a storage failure) still throws to the caller, which the Worker also answers with 503.
 */
export async function runEmaRegistryTransaction(storage: DurableObjectStorage, payload: unknown): Promise<EmaRegistryResponse> {
	const parsed = EmaRegistryRequestSchema.safeParse(payload);
	if (!parsed.success) return { status: 'invalid_request' };
	try {
		return await storage.transaction((txn) => serveTx(txn, parsed.data));
	} catch (err) {
		if (err instanceof EmaTenantUnreadableError) return { status: 'ema_store_unavailable' };
		throw err;
	}
}

// ─── Worker side: the registry client, with the one-time legacy import ───

/**
 * Where the registry lives: the coordinator (the authority) and, for the one-time legacy import only, the
 * SESSION_STORE that held tenant records before and the envelope key they were sealed with.
 */
export interface EmaRegistry {
	coordinator: DurableObjectNamespace<QuotaCoordinator> | undefined;
	kv?: KVNamespace;
	kvEnvelopeKey?: Uint8Array;
}

/** Every answer of a registry that could serve the request. */
type EmaAnswer = Exclude<EmaRegistryResponse, { status: EmaStoreStatus }>;

const STORE_STATUSES: ReadonlySet<string> = new Set<EmaStoreStatus>(['ema_not_migrated', 'ema_store_unavailable', 'invalid_request']);

const registryUnavailable = (): StrongStateUnavailableError => new StrongStateUnavailableError('ema tenant registry');

/** One round trip. No binding, an RPC failure or a reply without a status is a retryable 503, never a 401. */
async function send(registry: EmaRegistry, payload: EmaRegistryRequest): Promise<EmaRegistryResponse> {
	let result: unknown;
	try {
		result = await emaRegistryRequest(payload, registry.coordinator);
	} catch {
		throw registryUnavailable();
	}
	if (typeof (result as { status?: unknown } | undefined)?.status !== 'string') throw registryUnavailable();
	return result as EmaRegistryResponse;
}

const LEGACY_TENANT_PREFIX = `${OAUTH_KV_PREFIX}ema-tenant:`;
const legacyTenantKey = (tenantId: string) => `${LEGACY_TENANT_PREFIX}${tenantId}`;
const legacyIssuerKey = async (normalizedIssuer: string) => `${OAUTH_KV_PREFIX}ema-issuer:${await sha256Hex(normalizedIssuer)}`;

/** A legacy record's JSON as the record of `tenantId`; null when it is another id's (a copied blob). Throws when it does not parse. */
function parseLegacy(json: string, tenantId: string): EmaTenantRecord | null {
	const record = EmaTenantRecordSchema.parse(JSON.parse(json));
	return record.tenant_id === tenantId ? record : null;
}

/**
 * Decode a legacy KV record, fail-closed. With an envelope key an unsealed record is ignored (the keyspace
 * was sealed from birth, so plaintext can only have been planted). A sealed record with no usable key, or
 * one that does not open or parse, throws: a record we cannot see is an outage (503), never an absence.
 */
async function decodeLegacyRecord(raw: string, tenantId: string, envelopeKey: Uint8Array | undefined): Promise<EmaTenantRecord | null> {
	if (!isSealed(raw)) return envelopeKey ? null : parseLegacy(raw, tenantId);
	if (!envelopeKey) throw new EmaTenantUnreadableError();
	return parseLegacy(await openKv(raw, envelopeKey), tenantId);
}

/** Every legacy tenant id in KV. More than EMA_MIGRATE_LIMIT throws: the import never moves a partial set. */
async function listLegacyTenantIds(kv: KVNamespace): Promise<string[]> {
	const names: string[] = [];
	let cursor: string | undefined;
	do {
		const page = await kv.list({ prefix: LEGACY_TENANT_PREFIX, cursor });
		names.push(...page.keys.map((key) => key.name.slice(LEGACY_TENANT_PREFIX.length)));
		cursor = page.list_complete ? undefined : page.cursor;
	} while (cursor !== undefined && names.length <= EMA_MIGRATE_LIMIT);
	if (names.length > EMA_MIGRATE_LIMIT) throw new Error('Too many legacy EMA tenants to import');
	return names.filter((id) => EMA_TENANT_ID_PATTERN.test(id));
}

/** The legacy record of every id, decoded fail-closed (decodeLegacyRecord); an id holding nothing honourable drops out. */
async function readLegacyRecords(kv: KVNamespace, ids: string[], envelopeKey: Uint8Array | undefined): Promise<EmaTenantRecord[]> {
	const records = await Promise.all(
		ids.map(async (id) => {
			const raw = await kv.get(legacyTenantKey(id));
			return raw === null ? null : decodeLegacyRecord(raw, id, envelopeKey);
		}),
	);
	return records.filter((record): record is EmaTenantRecord => record !== null);
}

/** The records the legacy issuer index named as their issuer's owner go first, so each keeps the issuer it held in KV. */
async function indexOwnersFirst(kv: KVNamespace, records: EmaTenantRecord[]): Promise<EmaTenantRecord[]> {
	const owns = await Promise.all(
		records.map(async (record) => {
			const issuer = normalizedOrNull(record.issuer);
			return issuer !== null && (await kv.get(await legacyIssuerKey(issuer))) === record.tenant_id;
		}),
	);
	return [...records.filter((_, i) => owns[i]), ...records.filter((_, i) => !owns[i])];
}

/**
 * The one-time import of every legacy KV tenant. Without the SESSION_STORE nothing shows the legacy keyspace
 * is empty, and a record that cannot be read may be the one a live token depends on: either way the registry
 * stays unmigrated (every EMA call 503) rather than import a partial set. KV is only ever read here.
 */
async function migrateLegacyTenants(registry: EmaRegistry): Promise<void> {
	const kv = registry.kv;
	if (!kv) throw registryUnavailable();
	let records: EmaTenantRecord[];
	try {
		records = await indexOwnersFirst(kv, await readLegacyRecords(kv, await listLegacyTenantIds(kv), registry.kvEnvelopeKey));
	} catch {
		throw new StrongStateUnavailableError('ema legacy import');
	}
	await send(registry, { kind: 'ema-migrate', records });
}

/**
 * One registry request. A registry that has not imported the legacy KV tenants yet is migrated first (any
 * Worker may send the import; the registry runs it once), then asked again. A status that is not an answer
 * throws StrongStateUnavailableError: a retryable 503, never a 401 and never an absence.
 */
async function registryCall<T extends EmaAnswer>(registry: EmaRegistry, payload: EmaRegistryRequest): Promise<T> {
	let result = await send(registry, payload);
	if (result.status === 'ema_not_migrated') {
		await migrateLegacyTenants(registry);
		result = await send(registry, payload);
	}
	if (STORE_STATUSES.has(result.status)) throw registryUnavailable();
	return result as T;
}

/** The tenant record, or null when none exists. Throws StrongStateUnavailableError when the registry or the record cannot be read. */
export async function getEmaTenant(registry: EmaRegistry, tenantId: string): Promise<EmaTenantRecord | null> {
	return (await registryCall<EmaRecordResult>(registry, { kind: 'ema-get', tenantId })).record;
}

/** The longest issuer a record can hold (EmaTenantRecordSchema): a longer `iss` cannot be registered. */
const MAX_ISSUER_LENGTH = 512;

/**
 * Resolve an `iss` claim to its APPROVED tenant, read atomically from the registry: the one record the
 * token grant validates the assertion against and stamps `tep` from. Null when the issuer is malformed,
 * unregistered or unapproved.
 */
export async function getEmaTenantByIssuer(registry: EmaRegistry, issuer: string): Promise<EmaTenantRecord | null> {
	const normalized = normalizedOrNull(issuer);
	if (normalized === null || normalized.length > MAX_ISSUER_LENGTH) return null;
	return (await registryCall<EmaRecordResult>(registry, { kind: 'ema-resolve-issuer', issuer: normalized })).record;
}

/** One page (≤ 100, id order) of tenants, optionally only those with `approval`; a returned `cursor` fetches the next page. */
export function listEmaTenants(registry: EmaRegistry, approval?: EmaApproval, cursor?: string): Promise<EmaListResult> {
	return registryCall<EmaListResult>(registry, { kind: 'ema-list', limit: EMA_LIST_PAGE_LIMIT, approval, cursor });
}

/** Apply one write to the fresh record inside the registry. */
export function writeEmaTenant(registry: EmaRegistry, tenantId: string, write: EmaWrite): Promise<EmaWriteResult> {
	return registryCall<EmaWriteResult>(registry, { kind: 'ema-write', tenantId, write });
}

/** Delete a tenant (see deleteTx). */
export function deleteEmaTenant(registry: EmaRegistry, tenantId: string, mode: 'operator' | 'self-serve'): Promise<EmaWriteResult> {
	return registryCall<EmaWriteResult>(registry, { kind: 'ema-delete', tenantId, mode });
}

/** The tenant_id of a well-formed `ema:<tenant_id>:<hash>` subject, else null. */
function emaSubjectTenantId(sub: string): string | null {
	const tenantId = sub.slice(EMA_SUBJECT_PREFIX.length, sub.lastIndexOf(':'));
	return sub.startsWith(EMA_SUBJECT_PREFIX) && EMA_TENANT_ID_PATTERN.test(tenantId) ? tenantId : null;
}

/** The claims of an EMA access token that tenant liveness is judged on. */
export interface EmaTokenClaims {
	sub: string;
	tier?: unknown;
	tep?: unknown;
}

/**
 * Tenant-wide revocation for an already-minted EMA access token, checked on every request against ONE
 * registry read: the token stands only while its tenant record exists, is active (isTenantActive), is on
 * the token's tier, and its epoch equals the token's `tep` (a token without one fails). Every revoking
 * write moves the epoch inside the same transaction that changes the record, so disabling, deleting,
 * re-creating, lapsing, re-keying, re-tiering or dropping a client cuts its tokens off at once, and nothing
 * that comes after (a re-enable, a re-approval, a tier round trip) brings them back. A registry that cannot
 * be read throws StrongStateUnavailableError (a retryable 503), never a silent accept or a 401.
 */
export async function isEmaTokenLive(registry: EmaRegistry, claims: EmaTokenClaims, nowSeconds: number): Promise<boolean> {
	const tenantId = emaSubjectTenantId(claims.sub);
	if (!tenantId) return false;
	const rec = await getEmaTenant(registry, tenantId);
	return rec !== null && isTenantActive(rec, nowSeconds) && claims.tier === rec.tier && claims.tep === tenantEpoch(rec);
}
