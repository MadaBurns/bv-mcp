// SPDX-License-Identifier: BUSL-1.1
import { afterEach, describe, expect, it, vi } from 'vitest';
import { handleToolsCall } from '../src/handlers/tools';

afterEach(() => {
	vi.restoreAllMocks();
});

function getConsoleLogs(spy: ReturnType<typeof vi.spyOn>): Record<string, unknown>[] {
	const logs: Record<string, unknown>[] = [];
	for (const call of spy.mock.calls) {
		const arg = call[0];
		if (typeof arg !== 'string') continue;
		try {
			logs.push(JSON.parse(arg) as Record<string, unknown>);
		} catch {
			// not JSON
		}
	}
	return logs;
}

describe('M365 tool logging', () => {
	it('logs only aggregate success details, not raw proxy result rows', async () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		const m365Proxy = {
			fetch: vi.fn(async () =>
				new Response(JSON.stringify({ rows: [{ mail: 'admin@example.com', ipAddress: '192.0.2.10' }], count: 1 }), {
					status: 200,
					headers: { 'content-type': 'application/json' },
				}),
			),
		};

		await handleToolsCall(
			{ name: 'query_signins', arguments: { ms_tenant_id: 'tenant-abc', user_principal_name: 'admin@example.com' } },
			undefined,
			{ m365Proxy, m365ProxyAuthToken: 'internal-token', keyHash: 'key_abc', authTier: 'developer' },
		);

		const logs = getConsoleLogs(consoleSpy);
		const toolLog = logs.find((log) => log.tool === 'query_signins');
		expect(toolLog).toBeDefined();
		expect(toolLog!.details).toEqual({ ok: true, unprovisioned: false, rowCount: 1 });
		expect(JSON.stringify(toolLog)).not.toContain('admin@example.com');
		expect(JSON.stringify(toolLog)).not.toContain('192.0.2.10');
	});
});
