// SPDX-License-Identifier: BUSL-1.1

/**
 * The internal door against STRICT tool schemas, driving the REAL `handleToolsCall`
 * (test/internal-tool-door-identity-decision-table.spec.ts mocks the dispatcher, so
 * it cannot see what the strict schema does with the arguments the door forwards).
 *
 * - /tools/call: the door-only legacy-watch keys bv-web sends (`legacyWebhookTokenFingerprint`
 *   on list/delete, plus the `watchId` it sends to list) are consumed and stripped before
 *   dispatch; delete still receives its declared `watchId`; any other unknown key is still
 *   refused with the allowlisted unknown-argument message.
 * - /tools/batch: a door-allowlisted key is forwarded only when the target tool declares it,
 *   so `profile` never fails a check_* item, while a declared key (`format`) still arrives.
 *
 * Only the D1 reconciliation collaborators are mocked.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const reconcileMock = vi.fn();
const adoptMock = vi.fn();

vi.mock('../src/lib/brand-audit-owner-reconciliation', async (importOriginal) => ({
	...(await importOriginal<typeof import('../src/lib/brand-audit-owner-reconciliation')>()),
	reconcileLegacyBrandAuditOwner: (...args: unknown[]) => reconcileMock(...args),
	adoptAnonymousBrandAuditWatchInternal: (...args: unknown[]) => adoptMock(...args),
}));

const WEB_KEY = 'web-internal-capability-key-32-bytes-minimum';
const MOBILE_KEY = 'mobile-internal-capability-key-32-bytes-minimum';
const TENANT_TOOL_KEY = 'tenant-tool-delegation-key-32-bytes-minimum';
const WATCH_CLEANUP_KEY = 'watch-cleanup-capability-key-32-bytes-minimum';
const FINGERPRINT = 'f'.repeat(64);
const WATCH_ID = 'a'.repeat(32);
const UNKNOWN_ARG = 'Invalid request: unknown argument(s)';

/** Minimal D1 stand-in: the watch table is empty for every owner. */
const emptyWatchDb = {
	prepare: () => ({
		bind: () => ({
			all: async () => ({ results: [] }),
			first: async () => null,
			run: async () => ({ success: true }),
		}),
	}),
} as unknown as D1Database;

const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext;

function env(): Record<string, unknown> {
	return {
		BV_WEB_INTERNAL_KEY: WEB_KEY,
		BV_MOBILE_INTERNAL_KEY: MOBILE_KEY,
		BV_MCP_TOOL_DELEGATION_KEY: TENANT_TOOL_KEY,
		BV_MCP_WATCH_CLEANUP_KEY: WATCH_CLEANUP_KEY,
		OAUTH_ISSUER: 'https://issuer.example',
		BRAND_AUDIT_DB: emptyWatchDb,
	};
}

async function post(path: '/tools/call' | '/tools/batch', key: string, body: unknown, headers: Record<string, string> = {}) {
	const { internalRoutes } = await import('../src/internal');
	return internalRoutes.request(
		path,
		{
			method: 'POST',
			headers: { 'content-type': 'application/json', authorization: `Bearer ${key}`, ...headers },
			body: JSON.stringify(body),
		},
		env(),
		ctx,
	);
}

const tenantHeaders = { 'x-tenant': 'tenant_123', 'x-auth-tier': 'developer' };

beforeEach(() => {
	reconcileMock.mockReset().mockResolvedValue(undefined);
	adoptMock.mockReset().mockResolvedValue({ status: 'no_match' });
	IN_MEMORY_CACHE.clear();
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe('POST /internal/tools/call — door-only keys vs strict tool schemas', () => {
	it('list_brand_audit_watches runs when bv-web sends the legacy proof and a watchId', async () => {
		const res = await post(
			'/tools/call',
			TENANT_TOOL_KEY,
			{ name: 'list_brand_audit_watches', arguments: { legacyWebhookTokenFingerprint: FINGERPRINT, watchId: WATCH_ID } },
			tenantHeaders,
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { isError?: boolean };
		const text = JSON.stringify(body);
		expect(text).not.toContain(UNKNOWN_ARG);
		expect(body.isError ?? false).toBe(false);
		expect(text).toContain('Brand audit watches: 0');
		// The proof was still consumed by the door before it was stripped.
		expect(adoptMock).toHaveBeenCalledTimes(1);
	});

	it('delete_brand_audit_watch drops the proof but still hands its declared watchId to the tool', async () => {
		const res = await post(
			'/tools/call',
			WATCH_CLEANUP_KEY,
			{ name: 'delete_brand_audit_watch', arguments: { legacyWebhookTokenFingerprint: FINGERPRINT, watchId: WATCH_ID } },
			tenantHeaders,
		);
		expect(res.status).toBe(200);
		const text = JSON.stringify(await res.json());
		expect(text).not.toContain(UNKNOWN_ARG);
		expect(text).toContain(`No watch with id ${WATCH_ID}`);
		expect(adoptMock).toHaveBeenCalledTimes(1);
	});

	it('any other unknown key is still refused with the allowlisted message', async () => {
		const res = await post('/tools/call', TENANT_TOOL_KEY, { name: 'list_brand_audit_watches', arguments: { bogus: 1 } }, tenantHeaders);
		const body = (await res.json()) as { isError?: boolean };
		expect(body.isError).toBe(true);
		expect(JSON.stringify(body)).toContain(`${UNKNOWN_ARG}: bogus`);
	});
});

describe('POST /internal/tools/batch — forwards only keys the target tool declares', () => {
	it('profile sent with a BaseDomainArgs tool (check_spf) does not fail any item', async () => {
		const { mockTxtRecords } = await import('./helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const res = await post('/tools/batch', WEB_KEY, {
			tool: 'check_spf',
			domains: ['example.com', 'example.org'],
			arguments: { profile: 'mail_enabled', format: 'compact' },
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as { results: { isError: boolean; result: unknown }[]; summary: { succeeded: number; failed: number } };
		expect(JSON.stringify(body)).not.toContain(UNKNOWN_ARG);
		expect(body.summary).toMatchObject({ succeeded: 2, failed: 0 });
	});

	it('a key the tool declares (format) is still forwarded', async () => {
		const { mockTxtRecords } = await import('./helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const res = await post('/tools/batch', WEB_KEY, {
			tool: 'check_spf',
			domains: ['example.com'],
			arguments: { profile: 'mail_enabled', format: 'not-a-format' },
		});
		const body = (await res.json()) as { summary: { failed: number } };
		const text = JSON.stringify(body);
		expect(body.summary.failed).toBe(1);
		expect(text).toContain('Invalid format');
		expect(text).not.toContain(UNKNOWN_ARG);
	});
});
