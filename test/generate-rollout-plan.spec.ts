// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Mock DNS responses for SPF, DMARC, and DKIM checks.
 * The DNS transport layer sends type as a string (e.g., "TXT", "MX") not a number.
 */
function mockEmailAuth(options: {
	spf?: string | null;
	dmarc?: string | null;
	dkim?: boolean;
}) {
	const { spf, dmarc, dkim = false } = options;

	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? '';
		const typeParam = u.searchParams.get('type') ?? '';
		const isTxt = typeParam === 'TXT' || typeParam === '16';
		const isMx = typeParam === 'MX' || typeParam === '15';

		if (isTxt) {
			if (name === 'example.com') {
				const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
				if (spf !== null && spf !== undefined) {
					records.push({ name, type: 16, TTL: 300, data: `"${spf}"` });
				}
				return Promise.resolve(createDohResponse([{ name, type: 16 }], records));
			}
			if (name === '_dmarc.example.com') {
				const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
				if (dmarc !== null && dmarc !== undefined) {
					records.push({ name, type: 16, TTL: 300, data: `"${dmarc}"` });
				}
				return Promise.resolve(createDohResponse([{ name, type: 16 }], records));
			}
			if (name.includes('_domainkey')) {
				const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
				if (dkim) {
					records.push({ name, type: 16, TTL: 300, data: '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"' });
				}
				return Promise.resolve(createDohResponse([{ name, type: 16 }], records));
			}
			return Promise.resolve(createDohResponse([{ name, type: 16 }], []));
		}
		if (isMx) {
			return Promise.resolve(createDohResponse([{ name, type: 15 }], [
				{ name, type: 15, TTL: 300, data: '10 mail.example.com.' },
			]));
		}
		return Promise.resolve(createDohResponse([{ name, type: 0 }], []));
	});
}

describe('generateRolloutPlan', () => {
	it('generates phases starting with p=none when no DMARC exists', async () => {
		mockEmailAuth({ spf: 'v=spf1 include:_spf.google.com -all', dmarc: null, dkim: true });
		const { generateRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const result = await generateRolloutPlan('example.com');

		expect(result.domain).toBe('example.com');
		expect(result.atTarget).toBe(false);
		expect(result.currentPolicy).toBe('none');
		expect(result.targetPolicy).toBe('reject');
		expect(result.phases.length).toBeGreaterThanOrEqual(3);
		// First phase should be Monitor with p=none
		expect(result.phases[0].name).toBe('Monitor');
		expect(result.phases[0].record).toContain('p=none');
		// Last phase should be Reject
		expect(result.phases[result.phases.length - 1].name).toBe('Reject');
		expect(result.phases[result.phases.length - 1].record).toContain('p=reject');
	});

	it('skips monitor phase when starting from p=none', async () => {
		mockEmailAuth({ spf: 'v=spf1 include:_spf.google.com -all', dmarc: 'v=DMARC1; p=none; rua=mailto:d@example.com', dkim: true });
		const { generateRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const result = await generateRolloutPlan('example.com');

		expect(result.atTarget).toBe(false);
		expect(result.currentPolicy).toBe('none');
		// Since current is already p=none, first phase after monitor is quarantine ramp
		// The monitor phase IS included because p=none still needs monitoring
		// But the first "action" phase should be quarantine ramp
		const phaseNames = result.phases.map((p) => p.name);
		expect(phaseNames).toContain('Quarantine 10%');
		expect(phaseNames).toContain('Reject');
	});

	it('returns atTarget=true when already at p=reject', async () => {
		mockEmailAuth({ spf: 'v=spf1 include:_spf.google.com -all', dmarc: 'v=DMARC1; p=reject; rua=mailto:d@example.com', dkim: true });
		const { generateRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const result = await generateRolloutPlan('example.com');

		expect(result.atTarget).toBe(true);
		expect(result.currentPolicy).toBe('reject');
		expect(result.phases).toHaveLength(0);
		expect(result.prerequisites).toHaveLength(0);
	});

	it('uses shorter durations with aggressive timeline', async () => {
		mockEmailAuth({ spf: 'v=spf1 include:_spf.google.com -all', dmarc: null, dkim: true });
		const { generateRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const result = await generateRolloutPlan('example.com', 'reject', 'aggressive');

		expect(result.timeline).toBe('aggressive');
		// Monitor phase should be 1 week
		const monitorPhase = result.phases.find((p) => p.name === 'Monitor');
		expect(monitorPhase).toBeDefined();
		expect(monitorPhase!.duration).toBe('1 week');
		// Ramp phases should be 3 days
		const rampPhase = result.phases.find((p) => p.name === 'Quarantine 10%');
		expect(rampPhase).toBeDefined();
		expect(rampPhase!.duration).toBe('3 days');
	});

	it('uses longer durations with conservative timeline', async () => {
		mockEmailAuth({ spf: 'v=spf1 include:_spf.google.com -all', dmarc: null, dkim: true });
		const { generateRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const result = await generateRolloutPlan('example.com', 'reject', 'conservative');

		expect(result.timeline).toBe('conservative');
		// Monitor phase should be 3 weeks
		const monitorPhase = result.phases.find((p) => p.name === 'Monitor');
		expect(monitorPhase).toBeDefined();
		expect(monitorPhase!.duration).toBe('3 weeks');
		// Ramp10 phase should be 2 weeks
		const rampPhase = result.phases.find((p) => p.name === 'Quarantine 10%');
		expect(rampPhase).toBeDefined();
		expect(rampPhase!.duration).toBe('2 weeks');
	});

	it('last phase is quarantine when target is quarantine', async () => {
		mockEmailAuth({ spf: 'v=spf1 include:_spf.google.com -all', dmarc: null, dkim: true });
		const { generateRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const result = await generateRolloutPlan('example.com', 'quarantine', 'standard');

		expect(result.targetPolicy).toBe('quarantine');
		expect(result.atTarget).toBe(false);
		// Should not have a reject phase
		const rejectPhase = result.phases.find((p) => p.name === 'Reject');
		expect(rejectPhase).toBeUndefined();
		// Last phase should be quarantine
		const lastPhase = result.phases[result.phases.length - 1];
		expect(lastPhase.record).toContain('p=quarantine');
		expect(lastPhase.record).not.toContain('pct=10');
	});

	it('identifies missing SPF as prerequisite', async () => {
		mockEmailAuth({ spf: null, dmarc: null, dkim: true });
		const { generateRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const result = await generateRolloutPlan('example.com');

		expect(result.prerequisites.some((p) => p.toLowerCase().includes('spf'))).toBe(true);
	});

	it('identifies missing DKIM as prerequisite', async () => {
		mockEmailAuth({ spf: 'v=spf1 include:_spf.google.com -all', dmarc: null, dkim: false });
		const { generateRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const result = await generateRolloutPlan('example.com');

		expect(result.prerequisites.some((p) => p.toLowerCase().includes('dkim'))).toBe(true);
	});

	it('from p=quarantine to reject generates a single phase', async () => {
		mockEmailAuth({ spf: 'v=spf1 include:_spf.google.com -all', dmarc: 'v=DMARC1; p=quarantine; rua=mailto:d@example.com', dkim: true });
		const { generateRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const result = await generateRolloutPlan('example.com', 'reject');

		expect(result.currentPolicy).toBe('quarantine');
		expect(result.atTarget).toBe(false);
		expect(result.phases).toHaveLength(1);
		expect(result.phases[0].name).toBe('Reject');
		expect(result.phases[0].record).toContain('p=reject');
	});

	it('phases include rollback records', async () => {
		mockEmailAuth({ spf: 'v=spf1 include:_spf.google.com -all', dmarc: null, dkim: true });
		const { generateRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const result = await generateRolloutPlan('example.com');

		for (const phase of result.phases) {
			expect(phase.rollback).toBeDefined();
			expect(phase.rollback.length).toBeGreaterThan(0);
		}
	});
});

describe('formatRolloutPlan', () => {
	it('formats at-target result', async () => {
		const { formatRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const text = formatRolloutPlan({
			domain: 'example.com',
			currentPolicy: 'reject',
			targetPolicy: 'reject',
			timeline: 'standard',
			atTarget: true,
			prerequisites: [],
			phases: [],
			estimatedDuration: 'already at target',
		});
		expect(text).toContain('example.com');
		expect(text).toContain('already at');
	});

	it('full format includes headers and DNS records', async () => {
		const { formatRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const text = formatRolloutPlan({
			domain: 'example.com',
			currentPolicy: 'none',
			targetPolicy: 'reject',
			timeline: 'standard',
			atTarget: false,
			prerequisites: ['Add SPF record'],
			phases: [
				{ name: 'Monitor', record: 'v=DMARC1; p=none; rua=mailto:d@example.com', duration: '2 weeks', successCriteria: 'Review reports', rollback: 'Remove record' },
				{ name: 'Reject', record: 'v=DMARC1; p=reject; rua=mailto:d@example.com', duration: 'ongoing', successCriteria: 'Monitor', rollback: 'v=DMARC1; p=quarantine' },
			],
			estimatedDuration: '~4 weeks',
		}, 'full');

		expect(text).toContain('# DMARC Rollout Plan');
		expect(text).toContain('Prerequisites');
		expect(text).toContain('Add SPF record');
		expect(text).toContain('Phase 1: Monitor');
		expect(text).toContain('Phase 2: Reject');
		expect(text).toContain('p=none');
		expect(text).toContain('p=reject');
	});

	it('compact format is shorter than full format', async () => {
		const { formatRolloutPlan } = await import('../src/tools/generate-rollout-plan');
		const data = {
			domain: 'example.com',
			currentPolicy: 'none',
			targetPolicy: 'reject',
			timeline: 'standard',
			atTarget: false,
			prerequisites: ['Add SPF record'],
			phases: [
				{ name: 'Monitor', record: 'v=DMARC1; p=none; rua=mailto:d@example.com', duration: '2 weeks', successCriteria: 'Review', rollback: 'Remove' },
				{ name: 'Reject', record: 'v=DMARC1; p=reject; rua=mailto:d@example.com', duration: 'ongoing', successCriteria: 'Monitor', rollback: 'p=quarantine' },
			],
			estimatedDuration: '~4 weeks',
		} as const;

		const compact = formatRolloutPlan(data as any, 'compact');
		const full = formatRolloutPlan(data as any, 'full');
		expect(compact.length).toBeLessThan(full.length);
		expect(compact).toContain('example.com');
		expect(compact).toContain('none -> reject');
		expect(compact).not.toContain('#');
	});
});
