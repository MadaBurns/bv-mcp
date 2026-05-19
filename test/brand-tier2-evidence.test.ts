// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for the Tier 2 evidence wrapper around the `BV_INTEL_GATEWAY`
 * service binding's `getDomainEvidence` RPC.
 *
 * Layer rationale: pure wrapper logic (call binding, parse, map). The binding
 * itself is mocked — real RPC round-trips live in the `.integration.test.ts`
 * placeholders.
 */

import { describe, it, expect, vi } from 'vitest';
import { tier2EvidenceLookup, type IntelGatewayBinding } from '../src/lib/brand-tier2-evidence';
import type { DomainEvidenceResponse } from '../src/schemas/cross-worker-domain-evidence';

function makeBinding(response: DomainEvidenceResponse): IntelGatewayBinding {
	return {
		getDomainEvidence: vi.fn().mockResolvedValue(response),
	};
}

describe('tier2EvidenceLookup', () => {
	it('emits Tier 2 observation for seed with latestScan + empty scoreAlerts', async () => {
		const binding = makeBinding({
			ok: true,
			domain: 'example.com',
			region: 'AMER',
			latestScan: { capturedAt: 1_779_000_000, score: 85, threatLevel: 'secure' },
			scanHistory: [],
			scoreAlerts: [],
		});

		const result = await tier2EvidenceLookup('example.com', binding);

		expect(result.status).toBe('ok');
		expect(result.observations).toHaveLength(1);
		expect(result.observations[0]).toMatchObject({
			tier: 2,
			source: 'gsi_evidence',
			confidence: 0.9,
			candidate: 'example.com',
			threatLevel: 'secure',
			capturedAt: 1_779_000_000,
		});
	});

	it('emits additional Tier 4 candidate observation when scoreAlerts has becoming-critical (low -> critical)', async () => {
		const binding = makeBinding({
			ok: true,
			domain: 'lookalike.com',
			region: 'EMEA',
			latestScan: { capturedAt: 1_779_000_500, score: 30, threatLevel: 'critical' },
			scanHistory: [],
			scoreAlerts: [
				{
					createdAt: 1_779_000_500,
					alertType: 'critical_drop',
					previousThreatLevel: 'low',
					newThreatLevel: 'critical',
					scoreDelta: -55,
				},
			],
		});

		const result = await tier2EvidenceLookup('lookalike.com', binding);

		expect(result.status).toBe('ok');
		expect(result.observations).toHaveLength(2);
		const tier4 = result.observations.find((o) => o.tier === 4);
		expect(tier4).toBeDefined();
		expect(tier4?.confidence).toBeGreaterThanOrEqual(0.5);
		expect(tier4).toMatchObject({
			source: 'score_alert_critical_drop',
			alertType: 'critical_drop',
			transition: 'low->critical',
			candidate: 'lookalike.com',
		});
	});

	it('emits Tier 4 observation for medium -> high transition (also becoming-critical)', async () => {
		const binding = makeBinding({
			ok: true,
			domain: 'creeping.com',
			region: 'AMER',
			latestScan: { capturedAt: 1_779_000_000, score: 55, threatLevel: 'high' },
			scanHistory: [],
			scoreAlerts: [
				{
					createdAt: 1_779_000_000,
					alertType: 'degradation',
					previousThreatLevel: 'medium',
					newThreatLevel: 'high',
					scoreDelta: -15,
				},
			],
		});

		const result = await tier2EvidenceLookup('creeping.com', binding);

		const tier4 = result.observations.find((o) => o.tier === 4);
		expect(tier4).toBeDefined();
		expect(tier4).toMatchObject({ transition: 'medium->high' });
	});

	it('does NOT emit Tier 4 observation for non-critical transitions (improvement, low -> medium)', async () => {
		const binding = makeBinding({
			ok: true,
			domain: 'recovering.com',
			region: 'APAC',
			latestScan: { capturedAt: 1_779_000_000, score: 70, threatLevel: 'medium' },
			scanHistory: [],
			scoreAlerts: [
				{
					createdAt: 1_779_000_000,
					alertType: 'improvement',
					previousThreatLevel: 'high',
					newThreatLevel: 'medium',
					scoreDelta: 20,
				},
				{
					createdAt: 1_779_000_100,
					alertType: 'degradation',
					previousThreatLevel: 'low',
					newThreatLevel: 'medium',
					scoreDelta: -10,
				},
			],
		});

		const result = await tier2EvidenceLookup('recovering.com', binding);

		// Tier 2 seed observation, but no Tier 4 (neither alert is becoming-critical).
		expect(result.observations.filter((o) => o.tier === 4)).toHaveLength(0);
		expect(result.observations).toHaveLength(1);
	});

	it('handles ok=false (not_in_corpus) by returning empty observations + skipped status', async () => {
		const binding = makeBinding({ ok: false, error: 'not_in_corpus' });

		const result = await tier2EvidenceLookup('unknown.com', binding);

		expect(result.observations).toHaveLength(0);
		expect(result.status).toBe('skipped');
	});

	it('handles ok=false (opted_out) by returning empty observations + skipped status', async () => {
		const binding = makeBinding({ ok: false, error: 'opted_out' });

		const result = await tier2EvidenceLookup('opted-out.com', binding);

		expect(result.observations).toHaveLength(0);
		expect(result.status).toBe('skipped');
	});

	it('handles latestScan=null on ok=true by skipping the Tier 2 seed observation', async () => {
		const binding = makeBinding({
			ok: true,
			domain: 'in-corpus-no-scan.com',
			region: 'AMER',
			latestScan: null,
			scanHistory: [],
			scoreAlerts: [],
		});

		const result = await tier2EvidenceLookup('in-corpus-no-scan.com', binding);

		expect(result.status).toBe('ok');
		expect(result.observations).toHaveLength(0);
	});

	it('returns degraded status (never throws) when the binding throws', async () => {
		const binding: IntelGatewayBinding = {
			getDomainEvidence: vi.fn().mockRejectedValue(new Error('RPC unreachable')),
		};

		const result = await tier2EvidenceLookup('example.com', binding);

		expect(result.observations).toHaveLength(0);
		expect(result.status).toBe('degraded');
	});

	it('returns degraded status when binding returns a malformed (schema-invalid) response', async () => {
		const binding = {
			getDomainEvidence: vi.fn().mockResolvedValue({
				ok: true,
				domain: 'bad.com',
				// missing required fields — would fail Zod parse
			}),
		} as unknown as IntelGatewayBinding;

		const result = await tier2EvidenceLookup('bad.com', binding);

		expect(result.observations).toHaveLength(0);
		expect(result.status).toBe('degraded');
	});

	it('returns skipped status when binding is undefined (no env wiring)', async () => {
		const result = await tier2EvidenceLookup('example.com', undefined);

		expect(result.observations).toHaveLength(0);
		expect(result.status).toBe('skipped');
	});

	it('calls the binding with the §1.2 object-arg shape ({ domain })', async () => {
		const binding = makeBinding({
			ok: true,
			domain: 'example.com',
			region: 'AMER',
			latestScan: { capturedAt: 1, score: 50, threatLevel: 'low' },
			scanHistory: [],
			scoreAlerts: [],
		});

		await tier2EvidenceLookup('example.com', binding);

		expect(binding.getDomainEvidence).toHaveBeenCalledWith({ domain: 'example.com' });
	});
});
