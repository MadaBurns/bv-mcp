// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the identity_secops M365 read tools.
 *
 * All tests mock the m365Proxy binding — no live M365 or bv-web calls.
 *
 * Coverage:
 *   (a) proxy present + 200 response → { ok: true, data: ... }
 *   (b) proxy absent (undefined)     → { ok: false, unprovisioned: true, tool: <path> }
 *   (c) keyHash threads into request body when provided
 *   (d) Authorization: Bearer header set when authToken provided
 *   (e) No Authorization header when authToken omitted
 */

import { describe, it, expect } from 'vitest';
import { querySignins } from '../../src/tools/m365/query-signins';
import { queryUal } from '../../src/tools/m365/query-ual';
import { getCaPolicies } from '../../src/tools/m365/get-ca-policies';
import { assessCoverage } from '../../src/tools/m365/assess-coverage';

/** Build a fake m365Proxy that returns a fixed JSON body with status 200. */
function mockProxy(responseBody: unknown): { fetch: typeof fetch } {
	return {
		fetch: async () => new Response(JSON.stringify(responseBody), { status: 200, headers: { 'content-type': 'application/json' } }),
	};
}

/** Build a fake m365Proxy that returns a fixed HTTP error status. */
function errorProxy(status: number): { fetch: typeof fetch } {
	return {
		fetch: async () => new Response('error', { status }),
	};
}

/** Build a capturing proxy that records the last request for assertions. */
function capturingProxy(): { fetch: typeof fetch; getLastRequest: () => { body: unknown; headers: Record<string, string> } } {
	let lastBody: unknown = undefined;
	let lastHeaders: Record<string, string> = {};
	return {
		fetch: async (input, init) => {
			lastBody = JSON.parse(init?.body as string);
			const hdrs = init?.headers as Record<string, string> | Headers | undefined;
			if (hdrs instanceof Headers) {
				hdrs.forEach((v, k) => { lastHeaders[k] = v; });
			} else if (hdrs) {
				lastHeaders = { ...hdrs };
			}
			return new Response(JSON.stringify({}), { status: 200 });
		},
		getLastRequest: () => ({ body: lastBody, headers: lastHeaders }),
	};
}

// ---------------------------------------------------------------------------
// query_signins
// ---------------------------------------------------------------------------

describe('querySignins', () => {
	it('returns { ok: true, data } when proxy responds 200', async () => {
		const data = { signIns: [{ id: 's1', userPrincipalName: 'alice@corp.com' }] };
		const result = await querySignins({ ms_tenant_id: 'tenant-abc' }, mockProxy(data));
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.data).toEqual(data);
		}
	});

	it('returns { ok: false, unprovisioned: true } when proxy is undefined (fail-soft)', async () => {
		const result = await querySignins({ ms_tenant_id: 'tenant-abc' });
		expect(result.ok).toBe(false);
		if (!result.ok && 'unprovisioned' in result) {
			expect(result.unprovisioned).toBe(true);
			expect(result.tool).toBe('query-signins');
		} else {
			throw new Error('expected unprovisioned shape');
		}
	});

	it('returns { ok: false, error } on non-2xx response', async () => {
		const result = await querySignins({ ms_tenant_id: 'tenant-abc' }, errorProxy(403));
		expect(result.ok).toBe(false);
		if (!result.ok && 'error' in result) {
			expect(result.error).toBe('m365_proxy_403');
		} else {
			throw new Error('expected error shape');
		}
	});

	it('does not throw on any input', async () => {
		await expect(querySignins({ ms_tenant_id: 'x' })).resolves.toBeDefined();
	});

	it('threads keyHash into request body when provided', async () => {
		const proxy = capturingProxy();
		await querySignins({ ms_tenant_id: 'tenant-abc' }, proxy, { keyHash: 'hash-xyz' });
		const { body } = proxy.getLastRequest();
		expect((body as Record<string, unknown>).keyHash).toBe('hash-xyz');
	});

	it('sets Authorization: Bearer header when authToken is provided', async () => {
		const proxy = capturingProxy();
		await querySignins({ ms_tenant_id: 'tenant-abc' }, proxy, { authToken: 'my-secret-key' });
		const { headers } = proxy.getLastRequest();
		expect(headers['Authorization']).toBe('Bearer my-secret-key');
	});

	it('does not set Authorization header when authToken is omitted', async () => {
		const proxy = capturingProxy();
		await querySignins({ ms_tenant_id: 'tenant-abc' }, proxy, { keyHash: 'hash-only' });
		const { headers } = proxy.getLastRequest();
		expect(headers['Authorization']).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// query_ual
// ---------------------------------------------------------------------------

describe('queryUal', () => {
	it('returns { ok: true, data } when proxy responds 200', async () => {
		const data = { auditRecords: [{ operation: 'MailItemsAccessed' }] };
		const result = await queryUal({ ms_tenant_id: 'tenant-abc' }, mockProxy(data));
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.data).toEqual(data);
		}
	});

	it('returns { ok: false, unprovisioned: true } when proxy is undefined (fail-soft)', async () => {
		const result = await queryUal({ ms_tenant_id: 'tenant-abc' });
		expect(result.ok).toBe(false);
		if (!result.ok && 'unprovisioned' in result) {
			expect(result.unprovisioned).toBe(true);
			expect(result.tool).toBe('query-ual');
		} else {
			throw new Error('expected unprovisioned shape');
		}
	});

	it('passes optional filters in args', async () => {
		let capturedBody = '';
		const capturingProxyLegacy: { fetch: typeof fetch } = {
			fetch: async (input, init) => {
				capturedBody = init?.body as string;
				return new Response(JSON.stringify({}), { status: 200 });
			},
		};
		await queryUal(
			{ ms_tenant_id: 'tenant-abc', operation: 'MailItemsAccessed', user_principal_name: 'bob@corp.com', since_hours: 6 },
			capturingProxyLegacy,
		);
		const parsed = JSON.parse(capturedBody);
		expect(parsed.operation).toBe('MailItemsAccessed');
		expect(parsed.user_principal_name).toBe('bob@corp.com');
		expect(parsed.since_hours).toBe(6);
	});

	it('threads keyHash into request body when provided', async () => {
		const proxy = capturingProxy();
		await queryUal({ ms_tenant_id: 'tenant-abc' }, proxy, { keyHash: 'hash-ual' });
		const { body } = proxy.getLastRequest();
		expect((body as Record<string, unknown>).keyHash).toBe('hash-ual');
	});

	it('sets Authorization: Bearer header when authToken is provided', async () => {
		const proxy = capturingProxy();
		await queryUal({ ms_tenant_id: 'tenant-abc' }, proxy, { authToken: 'ual-token' });
		const { headers } = proxy.getLastRequest();
		expect(headers['Authorization']).toBe('Bearer ual-token');
	});
});

// ---------------------------------------------------------------------------
// get_ca_policies
// ---------------------------------------------------------------------------

describe('getCaPolicies', () => {
	it('returns { ok: true, data } when proxy responds 200', async () => {
		const data = { policies: [{ id: 'pol1', displayName: 'MFA for all users' }] };
		const result = await getCaPolicies({ ms_tenant_id: 'tenant-abc' }, mockProxy(data));
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.data).toEqual(data);
		}
	});

	it('returns { ok: false, unprovisioned: true } when proxy is undefined (fail-soft)', async () => {
		const result = await getCaPolicies({ ms_tenant_id: 'tenant-abc' });
		expect(result.ok).toBe(false);
		if (!result.ok && 'unprovisioned' in result) {
			expect(result.unprovisioned).toBe(true);
			expect(result.tool).toBe('get-ca-policies');
		} else {
			throw new Error('expected unprovisioned shape');
		}
	});

	it('threads keyHash into request body when provided', async () => {
		const proxy = capturingProxy();
		await getCaPolicies({ ms_tenant_id: 'tenant-abc' }, proxy, { keyHash: 'hash-ca' });
		const { body } = proxy.getLastRequest();
		expect((body as Record<string, unknown>).keyHash).toBe('hash-ca');
	});

	it('sets Authorization: Bearer header when authToken is provided', async () => {
		const proxy = capturingProxy();
		await getCaPolicies({ ms_tenant_id: 'tenant-abc' }, proxy, { authToken: 'ca-token' });
		const { headers } = proxy.getLastRequest();
		expect(headers['Authorization']).toBe('Bearer ca-token');
	});
});

// ---------------------------------------------------------------------------
// assess_coverage
// ---------------------------------------------------------------------------

describe('assessCoverage', () => {
	it('returns { ok: true, data } when proxy responds 200', async () => {
		const data = { uncoveredUsers: 3, uncoveredApps: ['SharePoint'], coveragePct: 92 };
		const result = await assessCoverage({ ms_tenant_id: 'tenant-abc' }, mockProxy(data));
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.data).toEqual(data);
		}
	});

	it('returns { ok: false, unprovisioned: true } when proxy is undefined (fail-soft)', async () => {
		const result = await assessCoverage({ ms_tenant_id: 'tenant-abc' });
		expect(result.ok).toBe(false);
		if (!result.ok && 'unprovisioned' in result) {
			expect(result.unprovisioned).toBe(true);
			expect(result.tool).toBe('assess-coverage');
		} else {
			throw new Error('expected unprovisioned shape');
		}
	});

	it('returns { ok: false, error: m365_proxy_unreachable } when fetch throws', async () => {
		const throwingProxy: { fetch: typeof fetch } = {
			fetch: async () => {
				throw new Error('network failure');
			},
		};
		const result = await assessCoverage({ ms_tenant_id: 'tenant-abc' }, throwingProxy);
		expect(result.ok).toBe(false);
		if (!result.ok && 'error' in result) {
			expect(result.error).toBe('m365_proxy_unreachable');
		} else {
			throw new Error('expected error shape');
		}
	});

	it('threads keyHash into request body when provided', async () => {
		const proxy = capturingProxy();
		await assessCoverage({ ms_tenant_id: 'tenant-abc' }, proxy, { keyHash: 'hash-cov' });
		const { body } = proxy.getLastRequest();
		expect((body as Record<string, unknown>).keyHash).toBe('hash-cov');
	});

	it('sets Authorization: Bearer header when authToken is provided', async () => {
		const proxy = capturingProxy();
		await assessCoverage({ ms_tenant_id: 'tenant-abc' }, proxy, { authToken: 'cov-token' });
		const { headers } = proxy.getLastRequest();
		expect(headers['Authorization']).toBe('Bearer cov-token');
	});

	it('does not set Authorization header when authToken is omitted', async () => {
		const proxy = capturingProxy();
		await assessCoverage({ ms_tenant_id: 'tenant-abc' }, proxy);
		const { headers } = proxy.getLastRequest();
		expect(headers['Authorization']).toBeUndefined();
	});
});
