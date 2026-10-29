// SPDX-License-Identifier: BUSL-1.1

/**
 * Enterprise Managed Auth (EMA) tenant registry: the per-tenant trusted-issuer allowlist.
 *
 * The authority (contract A11) is ONE QuotaCoordinator strong-state shard, addressed by the fixed
 * coordination key EMA_REGISTRY_KEY. It holds every tenant record, the approved-issuer index and each
 * tenant's epoch floor. Every read and write is one `ema-*` request that runs inside that shard's storage
 * transaction, so a write is computed from the FRESH record (approval, token epoch, rejected-issuer ban and
 * tombstone included) and a mint or a liveness check reads one record atomically. Its keys sit outside the
 * `quota:` prefix the cleanup alarm sweeps, so nothing ever expires them:
 *   strong:ema:tenant:<tenant_id>                → EmaTenantRecord (plaintext: Durable Object storage is
 *                                                  encrypted at rest and reachable only through this Worker)
 *   strong:ema:issuer:<normalized issuer>        → tenant_id of the ONE approved tenant that owns the issuer
 *   strong:version:ema-tenant-epoch:<tenant_id>  → { value }: the highest token epoch the id ever had, so a
 *                                                  re-created tenant starts above it. Its presence also marks
 *                                                  the id as known to the registry.
 *
 * Records written before the registry (SESSION_STORE `oauth:ema-tenant:<id>`, sealed by KV_ENVELOPE_KEY, and
 * the `oauth:ema-issuer:<sha256>` index) are imported lazily: a registry miss on an id the registry has never
 * known reads KV once, imports the record inside a transaction, then deletes the KV copy. KV is never written.
 */

import {
	EMA_REJECTED_ISSUER_LIMIT,
	EMA_TENANT_ID_PATTERN,
	EmaApprovalSchema,
	EmaTenantRecordSchema,
	type EmaApproval,
	type EmaApproveRequest,
	type EmaSelfServeUpsertRequest,
	type EmaTenantRecord,
	type EmaTenantUpsertRequest,
} from '../schemas/ema';
import { OAUTH_KV_PREFIX } from '../lib/config';
import { openKv, isSealed } from '../lib/kv-envelope';
import { emaRegistryRequest, type QuotaCoordinator } from '../lib/quota-coordinator';
import { CLAUDE_WEB_CIMD_CLIENT_ID } from './cimd';
import { sha256Hex } from './jwks';
import { StrongStateUnavailableError } from './storage';

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

/** A stored tenant record exists but cannot be honoured (wrong envelope key, corruption, a sealed record with no key). */
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

/** A tenant as a write decides it; the registry adds the server-managed timestamps, token epoch and rejected issuers. */
export type EmaTenantDraft = Omit<EmaTenantRecord, 'created_at' | 'updated_at' | 'token_epoch' | 'rejected_issuer_hashes'>;

/** Whether a write takes a tenant out of a state (enabled, approved) it was in. */
const leaves = (before: boolean, after: boolean): boolean => before && !after;

/** Same issuer, same keys and same tier: the identity a minted token was bound to. */
function sameBinding(existing: EmaTenantRecord, next: EmaTenantDraft): boolean {
	return existing.issuer === next.issuer && existing.jwks_uri === next.jwks_uri && existing.tier === next.tier;
}

/**
 * Whether tokens minted under `existing` may keep standing once `next` is stored: same issuer, keys and
 * tier, still enabled and approved, and no earlier entitlement. Anything else revokes them by moving the
 * epoch, including a tier change (a round trip back to the old tier must not revive them).
 */
export function keepsTokenEpoch(existing: EmaTenantRecord, next: EmaTenantDraft): boolean {
	return (
		sameBinding(existing, next) &&
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

/** The approve compare-and-set: the stored record still matches the snapshot the operator reviewed. */
function matchesReviewed(rec: EmaTenantRecord, reviewed: EmaApproveRequest): boolean {
	return rec.issuer === reviewed.issuer && rec.jwks_uri === reviewed.jwks_uri && rec.updated_at === reviewed.updated_at;
}

// ─── Registry protocol: the `ema-*` QuotaCoordinator request kinds ───

/** The fixed coordination key: every `ema-*` request routes to the ONE security shard it names. */
export const EMA_REGISTRY_KEY = 'ema-registry';

/** The most records one `ema-list` page returns (the operator list route's page size). */
export const EMA_LIST_PAGE_LIMIT = 100;

/** The jwks_uri the Worker discovered, and the issuer it discovered it for. */
export interface EmaDiscovered {
	issuer: string;
	jwks_uri: string;
}

/** Operator upsert body with jwks_uri resolved (supplied or discovered). */
export type EmaOperatorUpsert = Omit<EmaTenantUpsertRequest, 'jwks_uri'> & { jwks_uri: string };

/** One write, applied by the registry to the fresh record inside its transaction. */
export type EmaWrite =
	| { op: 'operator-upsert'; body: EmaOperatorUpsert }
	| { op: 'self-serve-upsert'; body: EmaSelfServeUpsertRequest; discovered?: EmaDiscovered }
	| { op: 'approve'; reviewed: EmaApproveRequest }
	| { op: 'reject' }
	| { op: 'import'; record: EmaTenantRecord };

export type EmaRegistryRequest =
	| { kind: 'ema-get'; coordinationKey: string; tenantId: string }
	| { kind: 'ema-list'; coordinationKey: string; limit: number; approval?: EmaApproval; cursor?: string }
	| { kind: 'ema-resolve-issuer'; coordinationKey: string; issuer: string }
	| { kind: 'ema-write'; coordinationKey: string; tenantId: string; write: EmaWrite }
	| { kind: 'ema-delete'; coordinationKey: string; tenantId: string; op: 'operator' | 'self-serve' };

/** A write the registry refused on the fresh record. `ema_record_changed` is retryable (rediscover, then write again). */
export type EmaWriteError = 'not_found' | 'approval_stale' | 'issuer_conflict' | 'tenant_managed_by_operator' | 'ema_record_changed';

export type EmaWriteResult = { record: EmaTenantRecord | null } | { error: EmaWriteError };
export type EmaGetResult = { record: EmaTenantRecord | null; known: boolean };
export type EmaListResult = { records: EmaTenantRecord[]; cursor?: string };
export type EmaRegistryResponse = EmaGetResult | EmaListResult | EmaWriteResult;

const EMA_WRITE_OPS = new Set<string>(['operator-upsert', 'self-serve-upsert', 'approve', 'reject', 'import']);
const EMA_DELETE_OPS = new Set<string>(['operator', 'self-serve']);

const isTenantId = (value: unknown): boolean => typeof value === 'string' && EMA_TENANT_ID_PATTERN.test(value);
const isOptional = (value: unknown, valid: (v: unknown) => boolean): boolean => value === undefined || valid(value);
const isListLimit = (value: unknown): boolean => typeof value === 'number' && value >= 1 && value <= EMA_LIST_PAGE_LIMIT;
const isIssuerField = (value: unknown): boolean => typeof value === 'string' && value.length <= 512;
const isWrite = (value: unknown): boolean =>
	typeof value === 'object' && value !== null && EMA_WRITE_OPS.has((value as { op?: unknown }).op as string);

/** Field invariants of the `ema-*` kinds, first failure wins. Required fields are the generic validator's job. */
const EMA_PAYLOAD_CHECKS: ReadonlyArray<readonly [(obj: Record<string, unknown>) => boolean, string]> = [
	[(o) => o.coordinationKey === EMA_REGISTRY_KEY, 'Invalid coordinationKey: ema kinds use the registry key'],
	[(o) => isOptional(o.tenantId, isTenantId), 'Invalid tenantId'],
	[(o) => isOptional(o.cursor, isTenantId), 'Invalid cursor'],
	[(o) => isOptional(o.issuer, isIssuerField), 'Invalid issuer'],
	[(o) => isOptional(o.approval, (v) => EmaApprovalSchema.safeParse(v).success), 'Invalid approval'],
	[(o) => isOptional(o.limit, isListLimit), `Invalid limit: must be 1 to ${EMA_LIST_PAGE_LIMIT}`],
	[(o) => isOptional(o.op, (v) => EMA_DELETE_OPS.has(v as string)), 'Invalid op'],
	[(o) => isOptional(o.write, isWrite), 'Invalid write'],
];

/** The coordinator's per-field validator for the `ema-*` kinds (any other kind passes untouched). */
export function emaRegistryPayloadError(obj: Record<string, unknown>): string | undefined {
	if (typeof obj.kind !== 'string' || !obj.kind.startsWith('ema-')) return undefined;
	return EMA_PAYLOAD_CHECKS.find(([valid]) => !valid(obj))?.[1];
}

// ─── Registry storage: runs INSIDE the coordinator's storage transaction ───

const RECORD_PREFIX = 'strong:ema:tenant:';
const ISSUER_PREFIX = 'strong:ema:issuer:';
/** Registry storage keys. Exported for tests that seed or inspect the shard directly. */
export const emaRecordStorageKey = (tenantId: string): string => `${RECORD_PREFIX}${tenantId}`;
export const emaIssuerStorageKey = (normalizedIssuer: string): string => `${ISSUER_PREFIX}${normalizedIssuer}`;
export const emaEpochFloorStorageKey = (tenantId: string): string => `strong:version:ema-tenant-epoch:${tenantId}`;

/** The most record keys one `ema-list` request scans, bounding the work a filtered page can do. */
const EMA_LIST_SCAN_LIMIT = 1000;

type Txn = DurableObjectTransaction;

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

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

/** The id's epoch floor, or undefined when the registry has never stored the id. */
async function epochFloorTx(txn: Txn, tenantId: string): Promise<number | undefined> {
	const floor = await txn.get<{ value?: unknown }>(emaEpochFloorStorageKey(tenantId));
	return Number.isSafeInteger(floor?.value) ? (floor?.value as number) : undefined;
}

/** Raise the id's epoch floor to `epoch` (it never lowers), creating it at least 1, which marks the id known. */
async function raiseEpochFloorTx(txn: Txn, tenantId: string, epoch: number): Promise<void> {
	const floor = await epochFloorTx(txn, tenantId);
	if (floor === undefined || epoch > floor) await txn.put(emaEpochFloorStorageKey(tenantId), { value: Math.max(epoch, floor ?? 1) });
}

/**
 * The token epoch a write stores. It keeps the record's epoch only when keepsTokenEpoch allows it; every
 * other write (a create included) moves it past both the record's epoch and the id's floor, so no token
 * minted under any earlier version of this id, a deleted one included, can match it again.
 */
async function nextTokenEpochTx(txn: Txn, existing: EmaTenantRecord | null, draft: EmaTenantDraft): Promise<number> {
	if (existing && keepsTokenEpoch(existing, draft)) return tenantEpoch(existing);
	const floor = (await epochFloorTx(txn, draft.tenant_id)) ?? 0;
	return Math.max(floor, existing ? tenantEpoch(existing) : 0) + 1;
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
	await raiseEpochFloorTx(txn, record.tenant_id, tenantEpoch(record));
	if (claimsIssuer) await txn.put(emaIssuerStorageKey(record.issuer), record.tenant_id);
	if (previous && (previous.issuer !== record.issuer || !claimsIssuer)) await releaseIssuerTx(txn, previous.issuer, record.tenant_id);
}

/**
 * The one store path of every write: created_at is preserved, updated_at stamped, and token_epoch and
 * rejected_issuer_hashes derived from the fresh record (nextTokenEpochTx, nextRejectedIssuerHashes); none
 * of them comes from a caller. Only an APPROVED tenant owns its issuer: approving one whose issuer another
 * approved tenant holds is `issuer_conflict`, and nothing is stored.
 */
async function storeTx(txn: Txn, existing: EmaTenantRecord | null, input: EmaTenantDraft): Promise<EmaWriteResult> {
	const draft: EmaTenantDraft = { ...input, issuer: normalizeIssuer(input.issuer) };
	const now = nowSeconds();
	const record = EmaTenantRecordSchema.parse(
		compact({
			...draft,
			created_at: existing?.created_at ?? now,
			updated_at: now,
			token_epoch: await nextTokenEpochTx(txn, existing, draft),
			rejected_issuer_hashes: await nextRejectedIssuerHashes(existing, draft),
		}),
	);
	const claimsIssuer = isApproved(record);
	if (claimsIssuer && (await issuerHeldByAnother(txn, record))) return { error: 'issuer_conflict' };
	await putRecordTx(txn, record, existing, claimsIssuer);
	return { record };
}

/** Remove a tenant, its issuer index entry and (when unreadable) every entry naming it; the floor keeps its epoch. */
async function removeTx(txn: Txn, tenantId: string): Promise<EmaWriteResult> {
	const raw = await txn.get(emaRecordStorageKey(tenantId));
	const existing = storedRecord(raw, tenantId);
	await txn.delete(emaRecordStorageKey(tenantId));
	if (existing) await releaseIssuerTx(txn, existing.issuer, tenantId);
	else if (raw !== undefined) await releaseIssuersOwnedByTx(txn, tenantId);
	await raiseEpochFloorTx(txn, tenantId, existing ? tenantEpoch(existing) : 1);
	return { record: null };
}

/**
 * Import a legacy KV record, only while the registry has never known the id (no record, no floor): a
 * deleted tenant is never resurrected from a stale KV copy. The record keeps its epoch, so tokens minted
 * under it keep working. It claims its issuer when approved and no other approved tenant holds it.
 */
async function importTx(txn: Txn, tenantId: string, existing: EmaTenantRecord | null, legacy: EmaTenantRecord): Promise<EmaWriteResult> {
	if (existing || (await epochFloorTx(txn, tenantId)) !== undefined) return { record: existing };
	const record = storedRecord(compact({ ...legacy, issuer: normalizeIssuer(legacy.issuer), token_epoch: tenantEpoch(legacy) }), tenantId);
	if (!record) throw new EmaTenantUnreadableError();
	await putRecordTx(txn, record, null, isApproved(record) && !(await issuerHeldByAnother(txn, record)));
	return { record };
}

const NOT_FOUND = { error: 'not_found' } as const;

/** An operator decision on the fresh record; approve also holds the reviewed compare-and-set. */
function decision(existing: EmaTenantRecord | null, approval: EmaApproval, reviewed?: EmaApproveRequest): EmaTenantDraft | { error: EmaWriteError } {
	if (!existing) return NOT_FOUND;
	if (reviewed && !matchesReviewed(existing, reviewed)) return { error: 'approval_stale' };
	return { ...existing, approval };
}

/**
 * The jwks_uri a self-serve write stores, decided on the FRESH record: the stored one for a write that only
 * lowers privilege, else the one discovered for the body's issuer. Undefined when the Worker skipped
 * discovery for a record that has since changed (ema_record_changed: rediscover and retry).
 */
function selfServeJwksUri(existing: EmaTenantRecord | null, body: EmaSelfServeUpsertRequest, discovered?: EmaDiscovered): string | undefined {
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
	write: Extract<EmaWrite, { op: 'self-serve-upsert' }>,
): Promise<EmaTenantDraft | { error: EmaWriteError }> {
	if (existing && existing.source !== 'self-serve') return { error: 'tenant_managed_by_operator' };
	const body = { ...write.body, issuer: normalizeIssuer(write.body.issuer) };
	const jwksUri = selfServeJwksUri(existing, body, write.discovered);
	if (!jwksUri) return { error: 'ema_record_changed' };
	return {
		...body,
		tenant_id: tenantId,
		allowed_client_ids: [CLAUDE_WEB_CIMD_CLIENT_ID],
		jwks_uri: jwksUri,
		approval: await selfServeApproval(existing, body.issuer, jwksUri),
		source: 'self-serve',
	};
}

type DraftOp = Exclude<EmaWrite['op'], 'import'>;

/**
 * The draft each write op derives from the fresh record. Operator upsert: an omitted `approval` keeps the
 * stored one, and `source` never comes from the body (an operator edit never takes a tenant away from the
 * customer settings that sync it).
 */
const DRAFTS: {
	[K in DraftOp]: (
		existing: EmaTenantRecord | null,
		tenantId: string,
		write: Extract<EmaWrite, { op: K }>,
	) => Promise<EmaTenantDraft | { error: EmaWriteError }>;
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
	if (write.op === 'import') return importTx(txn, tenantId, existing, write.record);
	const draftFor = DRAFTS[write.op] as (e: EmaTenantRecord | null, t: string, w: EmaWrite) => Promise<EmaTenantDraft | { error: EmaWriteError }>;
	const draft = await draftFor(existing, tenantId, write);
	return 'error' in draft ? draft : storeTx(txn, existing, draft);
}

/**
 * Delete. The operator's removes the record outright. The self-serve one refuses an operator-managed tenant,
 * and keeps a tenant the operator ever rejected as a disabled, lapsed tombstone that carries its rejected
 * issuers, so deleting and re-creating cannot launder a refusal. Either way its tokens die.
 */
async function deleteTx(txn: Txn, tenantId: string, op: 'operator' | 'self-serve'): Promise<EmaWriteResult> {
	if (op === 'operator') return removeTx(txn, tenantId);
	const existing = await readRecordTx(txn, tenantId);
	if (!existing) return { record: null };
	if (existing.source !== 'self-serve') return { error: 'tenant_managed_by_operator' };
	if (!hasBeenRejected(existing)) return removeTx(txn, tenantId);
	return storeTx(txn, existing, { ...existing, enabled: false, entitlement_expires_at: nowSeconds() });
}

/** A stored value as a list entry: a valid record passing the approval filter, else null (unreadable entries are skipped). */
function listedRecord(key: string, raw: unknown, approval: EmaApproval | undefined): EmaTenantRecord | null {
	const record = storedRecord(raw, key.slice(RECORD_PREFIX.length));
	return record && (!approval || effectiveApproval(record) === approval) ? record : null;
}

/** One page of records (id order) after `cursor`; `cursor` in the result names where the next page starts. */
async function listTx(txn: Txn, req: Extract<EmaRegistryRequest, { kind: 'ema-list' }>): Promise<EmaListResult> {
	const startAfter = req.cursor === undefined ? undefined : emaRecordStorageKey(req.cursor);
	const scanned = await txn.list({ prefix: RECORD_PREFIX, startAfter, limit: EMA_LIST_SCAN_LIMIT });
	const records: EmaTenantRecord[] = [];
	let last: string | undefined;
	for (const [key, raw] of scanned) {
		if (records.length === req.limit) return { records, cursor: last };
		last = key.slice(RECORD_PREFIX.length);
		const record = listedRecord(key, raw, req.approval);
		if (record) records.push(record);
	}
	return scanned.size === EMA_LIST_SCAN_LIMIT ? { records, cursor: last } : { records };
}

/** The APPROVED tenant that owns `issuer` (already normalized), else null. */
async function resolveIssuerTx(txn: Txn, issuer: string): Promise<EmaWriteResult> {
	const owner = await txn.get<string>(emaIssuerStorageKey(issuer));
	const record = typeof owner === 'string' ? await readRecordTx(txn, owner) : null;
	return { record: vouchesFor(record, issuer) ? record : null };
}

async function getTx(txn: Txn, tenantId: string): Promise<EmaGetResult> {
	const record = await readRecordTx(txn, tenantId);
	return { record, known: record !== null || (await epochFloorTx(txn, tenantId)) !== undefined };
}

const EMA_HANDLERS: {
	[K in EmaRegistryRequest['kind']]: (txn: Txn, payload: Extract<EmaRegistryRequest, { kind: K }>) => Promise<EmaRegistryResponse>;
} = {
	'ema-get': (txn, payload) => getTx(txn, payload.tenantId),
	'ema-list': listTx,
	'ema-resolve-issuer': (txn, payload) => resolveIssuerTx(txn, payload.issuer),
	'ema-write': (txn, payload) => writeTx(txn, payload.tenantId, payload.write),
	'ema-delete': (txn, payload) => deleteTx(txn, payload.tenantId, payload.op),
};

/** Run one `ema-*` request inside the registry shard's storage transaction (QuotaCoordinator calls this). */
export function runEmaRegistryRequest(txn: Txn, payload: EmaRegistryRequest): Promise<EmaRegistryResponse> {
	const handler = EMA_HANDLERS[payload.kind] as (txn: Txn, payload: EmaRegistryRequest) => Promise<EmaRegistryResponse>;
	return handler(txn, payload);
}

// ─── Worker side: the registry client, with the lazy legacy-KV import ───

/**
 * Where the registry lives: the coordinator (the authority) and, for the one-time legacy import only, the
 * SESSION_STORE that held tenant records before and the envelope key they were sealed with.
 */
export interface EmaRegistry {
	coordinator: DurableObjectNamespace<QuotaCoordinator> | undefined;
	kv?: KVNamespace;
	kvEnvelopeKey?: Uint8Array;
}

/** One registry request. Any failure (no binding, an RPC error, an unreadable record) is a retryable 503, never a 401. */
async function registryCall<T extends EmaRegistryResponse>(registry: EmaRegistry, payload: EmaRegistryRequest): Promise<T> {
	let result: unknown;
	try {
		result = await emaRegistryRequest(payload, registry.coordinator);
	} catch {
		throw new StrongStateUnavailableError('ema tenant registry');
	}
	if (typeof result !== 'object' || result === null) throw new StrongStateUnavailableError('ema tenant registry');
	return result as T;
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

/** Best-effort removal of an imported tenant's KV copy and of its issuer index entry (while that names it). */
async function purgeLegacyTenant(kv: KVNamespace, tenantId: string, legacy: EmaTenantRecord | null): Promise<void> {
	try {
		await kv.delete(legacyTenantKey(tenantId));
		const indexKey = legacy ? await legacyIssuerKey(normalizeIssuer(legacy.issuer)) : null;
		if (indexKey && (await kv.get(indexKey)) === tenantId) await kv.delete(indexKey);
	} catch {
		// The registry now knows the id, so this KV copy is never read again; a failed delete only leaves garbage.
	}
}

/**
 * Move a legacy KV tenant into the registry and clear its KV copy. The registry refuses the import when it
 * already knows the id (then it answers the record it holds, or null). Returns null when KV holds nothing
 * honourable for the id. Throws StrongStateUnavailableError when a stored record cannot be read.
 */
async function importLegacyTenant(registry: EmaRegistry, tenantId: string): Promise<EmaTenantRecord | null> {
	const kv = registry.kv;
	if (!kv) return null;
	let legacy: EmaTenantRecord | null;
	try {
		const raw = await kv.get(legacyTenantKey(tenantId));
		legacy = raw === null ? null : await decodeLegacyRecord(raw, tenantId, registry.kvEnvelopeKey);
	} catch {
		throw new StrongStateUnavailableError('ema legacy tenant import');
	}
	if (!legacy) return null;
	const imported = await registryCall<EmaWriteResult>(registry, {
		kind: 'ema-write',
		coordinationKey: EMA_REGISTRY_KEY,
		tenantId,
		write: { op: 'import', record: legacy },
	});
	await purgeLegacyTenant(kv, tenantId, legacy);
	return 'record' in imported ? imported.record : null;
}

/**
 * The tenant record, or null when none exists. A registry miss on an id the registry has never known
 * imports a legacy KV record first. Throws StrongStateUnavailableError when the registry or a stored
 * record cannot be read.
 */
export async function getEmaTenant(registry: EmaRegistry, tenantId: string): Promise<EmaTenantRecord | null> {
	const found = await registryCall<EmaGetResult>(registry, { kind: 'ema-get', coordinationKey: EMA_REGISTRY_KEY, tenantId });
	return found.record || found.known ? found.record : importLegacyTenant(registry, tenantId);
}

async function resolveIssuer(registry: EmaRegistry, normalized: string): Promise<EmaTenantRecord | null> {
	const resolved = await registryCall<EmaWriteResult>(registry, { kind: 'ema-resolve-issuer', coordinationKey: EMA_REGISTRY_KEY, issuer: normalized });
	return 'record' in resolved ? resolved.record : null;
}

/** On a registry miss: the legacy KV index's tenant for the issuer, imported, then the issuer resolved again. */
async function resolveLegacyIssuer(registry: EmaRegistry, normalized: string): Promise<EmaTenantRecord | null> {
	let tenantId: string | null = null;
	try {
		tenantId = (await registry.kv?.get(await legacyIssuerKey(normalized))) ?? null;
	} catch {
		throw new StrongStateUnavailableError('ema legacy issuer lookup');
	}
	if (!tenantId || !EMA_TENANT_ID_PATTERN.test(tenantId)) return null;
	await importLegacyTenant(registry, tenantId);
	return resolveIssuer(registry, normalized);
}

/**
 * Resolve an `iss` claim to its APPROVED tenant, read atomically from the registry: the one record the
 * token grant validates the assertion against and stamps `tep` from. Null when the issuer is malformed,
 * unregistered or unapproved.
 */
export async function getEmaTenantByIssuer(registry: EmaRegistry, issuer: string): Promise<EmaTenantRecord | null> {
	let normalized: string;
	try {
		normalized = normalizeIssuer(issuer);
	} catch {
		return null;
	}
	return (await resolveIssuer(registry, normalized)) ?? resolveLegacyIssuer(registry, normalized);
}

/** Import every legacy KV tenant (up to a page) before a first list page, skipping any that cannot be read. */
async function importLegacyTenants(registry: EmaRegistry): Promise<void> {
	let keys: KVNamespaceListKey<unknown>[] = [];
	try {
		keys = (await registry.kv?.list({ prefix: LEGACY_TENANT_PREFIX, limit: EMA_LIST_PAGE_LIMIT }))?.keys ?? [];
	} catch {
		throw new StrongStateUnavailableError('ema legacy tenant list');
	}
	const ids = keys.map((key) => key.name.slice(LEGACY_TENANT_PREFIX.length)).filter((id) => EMA_TENANT_ID_PATTERN.test(id));
	await Promise.all(ids.map((id) => importLegacyTenant(registry, id).catch(() => null)));
}

/** One page (≤ 100, id order) of tenants, optionally only those with `approval`; a returned `cursor` fetches the next page. */
export async function listEmaTenants(registry: EmaRegistry, approval?: EmaApproval, cursor?: string): Promise<EmaListResult> {
	if (cursor === undefined) await importLegacyTenants(registry);
	return registryCall<EmaListResult>(registry, {
		kind: 'ema-list',
		coordinationKey: EMA_REGISTRY_KEY,
		limit: EMA_LIST_PAGE_LIMIT,
		approval,
		cursor,
	});
}

/** Apply one write to the fresh record inside the registry. The route imports any legacy record first (getEmaTenant). */
export function writeEmaTenant(registry: EmaRegistry, tenantId: string, write: Exclude<EmaWrite, { op: 'import' }>): Promise<EmaWriteResult> {
	return registryCall<EmaWriteResult>(registry, { kind: 'ema-write', coordinationKey: EMA_REGISTRY_KEY, tenantId, write });
}

/**
 * Delete a tenant (see deleteTx). The operator's delete also clears any legacy KV copy, best-effort: the
 * registry now knows the id, so that copy can never be imported again anyway.
 */
export async function deleteEmaTenant(registry: EmaRegistry, tenantId: string, op: 'operator' | 'self-serve'): Promise<EmaWriteResult> {
	const result = await registryCall<EmaWriteResult>(registry, { kind: 'ema-delete', coordinationKey: EMA_REGISTRY_KEY, tenantId, op });
	if (op === 'operator' && registry.kv) await purgeLegacyTenant(registry.kv, tenantId, null);
	return result;
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
 * re-creating, lapsing, re-keying or re-tiering a tenant cuts its tokens off at once, and nothing that
 * comes after (a re-enable, a re-approval, a tier round trip) brings them back. A registry that cannot
 * be read throws StrongStateUnavailableError (a retryable 503), never a silent accept or a 401.
 */
export async function isEmaTokenLive(registry: EmaRegistry, claims: EmaTokenClaims, nowSeconds: number): Promise<boolean> {
	const tenantId = emaSubjectTenantId(claims.sub);
	if (!tenantId) return false;
	const rec = await getEmaTenant(registry, tenantId);
	return rec !== null && isTenantActive(rec, nowSeconds) && claims.tier === rec.tier && claims.tep === tenantEpoch(rec);
}

