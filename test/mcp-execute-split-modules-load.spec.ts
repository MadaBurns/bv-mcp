// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi, beforeEach } from 'vitest';

/**
 * Load census for the modules split out of src/mcp/execute.ts. Each module is
 * imported on its own in a fresh module graph (guards against a TDZ / circular
 * import failure at Worker start-up), and execute.ts must still re-export every
 * name it exported before the split.
 */
describe('mcp execute split modules load', () => {
	beforeEach(() => {
		vi.resetModules();
	});

	it('ip-evidence loads standalone', async () => {
		const mod = await import('../src/mcp/ip-evidence');
		expect(mod.encryptIpEvidence).toBeTypeOf('function');
		expect(mod.decryptIpEvidence).toBeTypeOf('function');
	});

	it('access-log loads standalone', async () => {
		const mod = await import('../src/mcp/access-log');
		expect(mod.extractAccessLogDomain).toBeTypeOf('function');
		expect(mod.recordInternalAccessLog).toBeTypeOf('function');
		expect(mod.accessLogInsertSql).toBeTypeOf('function');
	});

	it('request-telemetry loads standalone', async () => {
		const mod = await import('../src/mcp/request-telemetry');
		expect(mod.emitRequestAnalytics).toBeTypeOf('function');
		expect(mod.recordFuzzEvent).toBeTypeOf('function');
		expect(mod.recordMcpToolErrorIfUnknownTool).toBeTypeOf('function');
	});

	it('responses loads standalone', async () => {
		const mod = await import('../src/mcp/responses');
		expect(mod.buildAuthRequiredResponse).toBeTypeOf('function');
		expect(mod.buildTierQuotaExceededResponse).toBeTypeOf('function');
		expect(mod.buildGatedToolResponse).toBeTypeOf('function');
		expect(mod.buildInternalOnlyToolResponse).toBeTypeOf('function');
	});

	it('execute.ts still re-exports every previously exported name, bound to the moved implementations', async () => {
		const exec = await import('../src/mcp/execute');
		const ip = await import('../src/mcp/ip-evidence');
		const log = await import('../src/mcp/access-log');
		expect(exec.executeMcpRequest).toBeTypeOf('function');
		expect(exec.extractAccessLogDomain).toBe(log.extractAccessLogDomain);
		expect(exec.recordInternalAccessLog).toBe(log.recordInternalAccessLog);
		expect(exec.accessLogInsertSql).toBe(log.accessLogInsertSql);
		expect(exec.accessLogBindings).toBe(log.accessLogBindings);
		expect(exec.__recordMcpAccessLogForTest).toBe(log.__recordMcpAccessLogForTest);
		expect(exec.encryptIpEvidence).toBe(ip.encryptIpEvidence);
		expect(exec.decryptIpEvidence).toBe(ip.decryptIpEvidence);
	});

	it('IP evidence round-trips through the old execute.ts import path with a generated key', async () => {
		const { encryptIpEvidence, decryptIpEvidence } = await import('../src/mcp/execute');
		const rawKey = crypto.getRandomValues(new Uint8Array(32));
		const key = btoa(String.fromCharCode(...rawKey));
		const wire = await encryptIpEvidence('203.0.113.7', key);
		expect(wire).toMatch(/^v1:[^:]+:[^:]+$/);
		expect(wire).not.toContain('203.0.113.7');
		expect(await decryptIpEvidence(wire as string, key)).toBe('203.0.113.7');

		const otherKey = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
		expect(await decryptIpEvidence(wire as string, otherKey)).toBeNull();
		expect(await encryptIpEvidence('unknown', key)).toBeNull();
	});
});
