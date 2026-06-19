// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi } from 'vitest';
import { streamScanResult } from '../src/lib/hooks/analytics-stream';

const PAYLOAD = {
	domain: 'example.com',
	grade: 'A',
	score: 95,
	sub_tenant_id: 'tenant-example',
	cycle_id: 'cycle-123',
};

describe('streamScanResult (analytics-stream hook, #418)', () => {
	it('posts to bv-web-prod ingest route with the internal bearer', async () => {
		const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 }));
		const env = { BV_WEB: { fetch: fetchMock }, BV_WEB_INTERNAL_KEY: 'internal-key' };

		await streamScanResult(env, PAYLOAD);

		expect(fetchMock).toHaveBeenCalledTimes(1);
		const req = fetchMock.mock.calls[0][0] as Request;
		expect(req.url).toBe('https://internal/api/internal/mcp/ingest-scan');
		expect(req.method).toBe('POST');
		expect(req.headers.get('Authorization')).toBe('Bearer internal-key');
		expect(await req.json()).toEqual(PAYLOAD);
	});

	it('noops (no fetch) when BV_WEB binding is absent — OSS/self-host', async () => {
		const env = { BV_WEB_INTERNAL_KEY: 'internal-key' } as Parameters<typeof streamScanResult>[0];
		await expect(streamScanResult(env, PAYLOAD)).resolves.toBeUndefined();
	});

	it('noops (no fetch) when BV_WEB_INTERNAL_KEY is unset — never posts unauthenticated', async () => {
		const fetchMock = vi.fn();
		const env = { BV_WEB: { fetch: fetchMock } } as Parameters<typeof streamScanResult>[0];

		await streamScanResult(env, PAYLOAD);

		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('is fail-soft — a fetch rejection is swallowed (no throw)', async () => {
		const fetchMock = vi.fn().mockRejectedValue(new Error('binding down'));
		const env = { BV_WEB: { fetch: fetchMock }, BV_WEB_INTERNAL_KEY: 'internal-key' };

		await expect(streamScanResult(env, PAYLOAD)).resolves.toBeUndefined();
	});
});
