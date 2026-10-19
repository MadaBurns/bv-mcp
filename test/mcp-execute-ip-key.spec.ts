// SPDX-License-Identifier: BUSL-1.1

/**
 * encryptIpEvidence validates MCP_ACCESS_LOG_IP_ENCRYPTION_KEY once per distinct value and
 * logs the misconfiguration at error level with the decoded key length. The `keyBytes`
 * detail is computed by an inline helper that must survive an undecodable key.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

type LoggedEvent = { severity?: string; category?: string; error?: string; details?: { keyBytes?: number | string } };

function captureLogs(): () => LoggedEvent[] {
	const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
	return () => spy.mock.calls.map(([line]) => JSON.parse(String(line)) as LoggedEvent);
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe('encryptIpEvidence — key validation logging', () => {
	it('records the decoded byte length when the key is valid base64 of the wrong size, then stays silent', async () => {
		const logs = captureLogs();
		const { encryptIpEvidence } = await import('../src/mcp/execute');
		const shortKey = btoa(String.fromCharCode(...new Uint8Array(16)));

		expect(await encryptIpEvidence('192.0.2.10', shortKey)).toBeNull();
		const first = logs().filter((event) => event.severity === 'error');
		expect(first).toHaveLength(1);
		expect(first[0]).toMatchObject({ category: 'config', details: { keyBytes: 16 } });
		expect(first[0]!.error).toContain('Invalid MCP_ACCESS_LOG_IP_ENCRYPTION_KEY');

		// Cached verdict: no second log line for the same misconfigured value.
		expect(await encryptIpEvidence('192.0.2.11', shortKey)).toBeNull();
		expect(logs().filter((event) => event.severity === 'error')).toHaveLength(1);
	});

	it('reports unparseable_base64 when the key cannot be decoded at all', async () => {
		const logs = captureLogs();
		const { encryptIpEvidence } = await import('../src/mcp/execute');

		expect(await encryptIpEvidence('192.0.2.12', '***not-base64***')).toBeNull();
		const errors = logs().filter((event) => event.severity === 'error');
		expect(errors).toHaveLength(1);
		expect(errors[0]).toMatchObject({ category: 'config', details: { keyBytes: 'unparseable_base64' } });
	});

	it('skips validation entirely for an unknown IP or an absent key', async () => {
		const logs = captureLogs();
		const { encryptIpEvidence } = await import('../src/mcp/execute');
		const goodKey = btoa(String.fromCharCode(...new Uint8Array(32)));

		expect(await encryptIpEvidence('unknown', goodKey)).toBeNull();
		expect(await encryptIpEvidence('192.0.2.13', undefined)).toBeNull();
		expect(logs()).toHaveLength(0);
		expect(typeof (await encryptIpEvidence('192.0.2.13', goodKey))).toBe('string');
	});
});
