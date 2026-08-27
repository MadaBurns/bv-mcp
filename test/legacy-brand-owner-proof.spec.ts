// SPDX-License-Identifier: BUSL-1.1

import * as cloudflareTest from 'cloudflare:test';
import { describe, expect, it, vi } from 'vitest';

import worker from '../src';
import { deriveCanonicalOAuthPrincipal } from '../src/lib/auth-principal';
import { resolveLegacyBrandOwnerProof } from '../src/lib/brand-audit-legacy-owner-proof';
import { reconcileLegacyBrandAuditOwners } from '../src/lib/brand-audit-owner-reconciliation';
import { signJwt, verifyJwt } from '../src/oauth/jwt';

const { createExecutionContext, env, waitOnExecutionContext } = cloudflareTest as unknown as {
	createExecutionContext(): ExecutionContext;
	env: Env;
	waitOnExecutionContext(ctx: ExecutionContext): Promise<void>;
};

const SECRET = 'legacy-owner-proof-signing-secret-32-bytes-minimum';
const ISSUER = 'https://example.com';
const SUBJECT = 'legacy-proof-tenant';
const NOW_SECONDS = Math.floor(Date.now() / 1000);
const RETIRED_TOKEN_LIFETIME_SECONDS = 90 * 24 * 60 * 60;

async function mintToken(
	subject: string,
	options: { tier?: 'owner' | 'developer' | 'enterprise'; issuedAt?: number; ttlSeconds?: number; secret?: string } = {},
): Promise<string> {
	return signJwt(
		{ sub: subject, jti: crypto.randomUUID(), tier: options.tier ?? 'developer' },
		{
			secret: options.secret ?? SECRET,
			issuer: ISSUER,
			audience: `${ISSUER}/mcp`,
			now: options.issuedAt ?? NOW_SECONDS,
			ttlSeconds: options.ttlSeconds ?? 60 * 60,
		},
	);
}

async function currentTenantAuth(subject = SUBJECT) {
	return {
		authenticated: true,
		tier: 'developer' as const,
		keyHash: await deriveCanonicalOAuthPrincipal(ISSUER, subject, 'tenant'),
		oauthTenantId: subject,
		oauthPrincipalKind: 'tenant' as const,
	};
}

async function legacyOwnerId(token: string): Promise<string> {
	const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0'))
		.join('')
		.slice(0, 16);
}

function makeDb() {
	const statements: Array<{ sql: string; values: unknown[] }> = [];
	const prepare = vi.fn((sql: string) => ({
		bind: (...values: unknown[]) => {
			const statement = {
				sql,
				values,
				first: async () => null,
				all: async () => ({ success: true, results: [] }),
				run: async () => ({ success: true, meta: { changes: 0 } }),
			};
			statements.push(statement);
			return statement;
		},
	}));
	const batch = vi.fn(async (items: unknown[]) => items.map(() => ({ success: true, meta: { changes: 1 }, results: [] })));
	return { db: { prepare, batch } as unknown as D1Database, prepare, batch, statements };
}

describe('historical OAuth proof for legacy Brand Audit owners', () => {
	it('accepts an expired retired-lifetime JWT only as same-principal ownership evidence', async () => {
		const historical = await mintToken(SUBJECT, {
			issuedAt: NOW_SECONDS - RETIRED_TOKEN_LIFETIME_SECONDS - 60,
			ttlSeconds: RETIRED_TOKEN_LIFETIME_SECONDS,
		});

		await expect(verifyJwt(historical, { secret: SECRET, issuer: ISSUER, audience: `${ISSUER}/mcp`, now: NOW_SECONDS })).rejects.toThrow(
			'token expired',
		);
		await expect(
			resolveLegacyBrandOwnerProof(
				`Bearer ${historical}`,
				await currentTenantAuth(),
				{ OAUTH_SIGNING_SECRET: SECRET, OAUTH_ISSUER: ISSUER },
				`${ISSUER}/mcp`,
			),
		).resolves.toEqual({ status: 'valid', legacyOwnerId: await legacyOwnerId(historical) });
	});

	it.each([
		['another subject', () => mintToken('different-tenant'), () => currentTenantAuth()],
		['another signing key', () => mintToken(SUBJECT, { secret: 'different-signing-secret-32-bytes-minimum' }), () => currentTenantAuth()],
		['owner namespace for tenant principal', () => mintToken(SUBJECT, { tier: 'owner' }), () => currentTenantAuth()],
		[
			'retired token exceeding the historical lifetime ceiling',
			() => mintToken(SUBJECT, { issuedAt: NOW_SECONDS - 1, ttlSeconds: RETIRED_TOKEN_LIFETIME_SECONDS + 1 }),
			() => currentTenantAuth(),
		],
	])('rejects %s', async (_label, makeHistorical, makeCurrent) => {
		const result = await resolveLegacyBrandOwnerProof(
			`Bearer ${await makeHistorical()}`,
			await makeCurrent(),
			{ OAUTH_SIGNING_SECRET: SECRET, OAUTH_ISSUER: ISSUER },
			`${ISSUER}/mcp`,
		);
		expect(result).toEqual({ status: 'invalid' });
	});

	it('rejects a historical JWT beside a static-key identity', async () => {
		const result = await resolveLegacyBrandOwnerProof(
			`Bearer ${await mintToken(SUBJECT)}`,
			{ authenticated: true, tier: 'developer', keyHash: 'a'.repeat(64), credentialHash: 'a'.repeat(64) },
			{ OAUTH_SIGNING_SECRET: SECRET, OAUTH_ISSUER: ISSUER },
			`${ISSUER}/mcp`,
		);
		expect(result).toEqual({ status: 'invalid' });
	});

	it('allows browser clients to send the migration proof header explicitly', async () => {
		const ctx = createExecutionContext();
		const response = await worker.fetch(
			new Request(`${ISSUER}/mcp`, {
				method: 'OPTIONS',
				headers: {
					Origin: ISSUER,
					'Access-Control-Request-Method': 'POST',
					'Access-Control-Request-Headers': 'X-BV-Legacy-Owner-Token',
				},
			}),
			env,
			ctx,
		);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(204);
		expect(response.headers.get('access-control-allow-headers')?.toLowerCase()).toContain('x-bv-legacy-owner-token');
	});

	it('atomically reconciles the current and one proven historical owner alias', async () => {
		const { db, batch, statements } = makeDb();

		await expect(reconcileLegacyBrandAuditOwners(db, ['0123456789abcdef', 'fedcba9876543210'], 'a'.repeat(64))).resolves.toEqual({
			attempted: true,
		});
		expect(batch).toHaveBeenCalledTimes(1);
		expect(statements.map((statement) => statement.values)).toEqual([
			['a'.repeat(64), '0123456789abcdef'],
			['a'.repeat(64), '0123456789abcdef'],
			['a'.repeat(64), 'fedcba9876543210'],
			['a'.repeat(64), 'fedcba9876543210'],
		]);
	});

	it('rejects reconciliation batch amplification before touching D1', async () => {
		const { db, prepare, batch } = makeDb();
		await expect(
			reconcileLegacyBrandAuditOwners(db, ['0123456789abcdef', 'fedcba9876543210', '1111111111111111'], 'a'.repeat(64)),
		).rejects.toThrow('Too many legacy brand-audit owner IDs');
		expect(prepare).not.toHaveBeenCalled();
		expect(batch).not.toHaveBeenCalled();
	});

	it('wires a valid historical proof into the public owner-scoped request reconciliation', async () => {
		const current = await mintToken(SUBJECT);
		const historical = await mintToken(SUBJECT, {
			issuedAt: NOW_SECONDS - RETIRED_TOKEN_LIFETIME_SECONDS - 60,
			ttlSeconds: RETIRED_TOKEN_LIFETIME_SECONDS,
		});
		const { db, batch, statements } = makeDb();
		const customEnv = {
			...env,
			OAUTH_SIGNING_SECRET: SECRET,
			OAUTH_ISSUER: ISSUER,
			BRAND_AUDIT_DB: db,
		} as Env;
		const request = new Request(`${ISSUER}/mcp`, {
			method: 'POST',
			headers: {
				Authorization: `Bearer ${current}`,
				'X-BV-Legacy-Owner-Token': `Bearer ${historical}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'brand_audit_status', arguments: { auditId: 'legacy-proof-audit' } },
			}),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, customEnv, ctx);
		await waitOnExecutionContext(ctx);
		const historicalOwnerId = await legacyOwnerId(historical);

		// The request intentionally omits an MCP session and is rejected later by
		// the protocol gate. Ownership reconciliation must already have completed.
		expect(response.status).toBe(400);
		expect(batch).toHaveBeenCalledTimes(1);
		expect(statements.some((statement) => statement.values[1] === historicalOwnerId)).toBe(true);
	});

	it('fails closed before D1 when a different tenant supplies the historical proof header', async () => {
		const current = await mintToken(SUBJECT);
		const historical = await mintToken('different-tenant');
		const { db, batch } = makeDb();
		const customEnv = {
			...env,
			OAUTH_SIGNING_SECRET: SECRET,
			OAUTH_ISSUER: ISSUER,
			BRAND_AUDIT_DB: db,
		} as Env;
		const request = new Request(`${ISSUER}/mcp`, {
			method: 'POST',
			headers: {
				Authorization: `Bearer ${current}`,
				'X-BV-Legacy-Owner-Token': `Bearer ${historical}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'brand_audit_status', arguments: { auditId: 'legacy-proof-audit' } },
			}),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, customEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(400);
		await expect(response.json()).resolves.toEqual({ error: 'invalid_legacy_brand_owner_proof' });
		expect(batch).not.toHaveBeenCalled();
	});

	it('never authenticates an expired historical token by itself', async () => {
		const historical = await mintToken(SUBJECT, {
			issuedAt: NOW_SECONDS - RETIRED_TOKEN_LIFETIME_SECONDS - 60,
			ttlSeconds: RETIRED_TOKEN_LIFETIME_SECONDS,
		});
		const { db, batch } = makeDb();
		const customEnv = {
			...env,
			OAUTH_SIGNING_SECRET: SECRET,
			OAUTH_ISSUER: ISSUER,
			BRAND_AUDIT_DB: db,
		} as Env;
		const request = new Request(`${ISSUER}/mcp`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${historical}`, 'Content-Type': 'application/json' },
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'brand_audit_status', arguments: { auditId: 'legacy-proof-audit' } },
			}),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, customEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(401);
		expect(batch).not.toHaveBeenCalled();
	});
});
