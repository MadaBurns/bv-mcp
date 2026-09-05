// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { canonicalEvidenceJson, createEvidenceSnapshot, verifyEvidenceSnapshot } from '../src/cli/evidence';

describe('CLI evidence envelope', () => {
	it('canonicalizes object keys deterministically', () => {
		expect(canonicalEvidenceJson({ z: 1, a: { y: 2, x: 3 } })).toBe(canonicalEvidenceJson({ a: { x: 3, y: 2 }, z: 1 }));
	});

	it('seals and verifies the complete versioned envelope', async () => {
		const snapshot = await createEvidenceSnapshot({
			capturedAt: '2026-09-05T00:00:00.000Z',
			serverName: 'blackveil-dns-mcp',
			serverVersion: '1.2.3',
			endpointOrigin: 'https://dns-mcp.blackveilsecurity.com',
			tool: 'scan_domain',
			result: { domain: 'example.com', score: 92 },
		});

		expect(snapshot.schemaVersion).toBe('blackveil-evidence/v1');
		expect(snapshot.integrity).toMatchObject({ algorithm: 'sha-256', canonicalization: 'blackveil-cjson/v1' });
		expect(snapshot.integrity.digest).toMatch(/^[a-f0-9]{64}$/);
		expect((await verifyEvidenceSnapshot(snapshot)).valid).toBe(true);
	});

	it('detects a result or provenance mutation', async () => {
		const snapshot = await createEvidenceSnapshot({
			capturedAt: '2026-09-05T00:00:00.000Z',
			serverName: 'blackveil-dns-mcp',
			serverVersion: '1.2.3',
			endpointOrigin: 'https://dns-mcp.blackveilsecurity.com',
			tool: 'scan_domain',
			result: { domain: 'example.com', score: 92 },
		});
		const tampered = structuredClone(snapshot);
		tampered.result.score = 12;
		expect((await verifyEvidenceSnapshot(tampered)).valid).toBe(false);
	});

	it('rejects non-JSON numeric values', () => {
		expect(() => canonicalEvidenceJson({ score: Number.NaN })).toThrow('non-finite');
	});
});
