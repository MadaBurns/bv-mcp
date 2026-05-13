// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the discover_brand_domains MCP tool (Phase-4 brand-discovery
 * orchestrator).
 *
 * The tool aggregates output from the four phase-4 discovery signal modules
 * (SAN, NS, DMARC RUA, DKIM key reuse) and returns a unified candidate list
 * with combined-confidence scoring. The signal modules are stubbed via the
 * deps injection seam exposed on the orchestrator — no live DNS or HTTP.
 */

import { describe, it, expect, vi } from 'vitest';
import type {
	SanCorrelationResult,
	NsCorrelationResult,
	DmarcRuaResult,
	DkimKeyReuseResult,
} from '../src/tenants/discovery';
import type { DiscoverBrandDomainsDeps } from '../src/tools/discover-brand-domains';

function okSan(coOwned: string[]): SanCorrelationResult {
	return { seedDomain: 'example.com', coOwnedDomains: coOwned, certIds: [], queryStatus: 'ok' };
}

function okNs(domains: Array<{ domain: string; confidence: number }>): NsCorrelationResult {
	return {
		seedDomain: 'example.com',
		seedNs: ['ns1.example.com'],
		coOwnedDomains: domains.map((d) => ({ domain: d.domain, sharedNs: ['ns1.example.com'], confidence: d.confidence })),
		queryStatus: 'ok',
	};
}

function okRua(domains: string[]): DmarcRuaResult {
	return {
		seedDomain: 'example.com',
		dmarcPresent: true,
		ruaUris: domains.map((d) => `mailto:dmarc@${d}`),
		ruaDomains: domains.map((d) => ({ domain: d, classification: 'related' as const, confidence: 0.6 })),
		queryStatus: 'ok',
	};
}

function okDkim(domains: string[]): DkimKeyReuseResult {
	return {
		seedDomain: 'example.com',
		seedSelectors: ['default'],
		coOwnedDomains: domains.map((d) => ({ domain: d, sharedKeys: ['abc123'], sharedSelectors: ['default'], confidence: 0.95 })),
		queryStatus: 'ok',
	};
}

function makeDeps(overrides: Partial<DiscoverBrandDomainsDeps> = {}): DiscoverBrandDomainsDeps {
	return {
		correlateSans: vi.fn().mockResolvedValue(okSan([])),
		correlateNs: vi.fn().mockResolvedValue(okNs([])),
		mineDmarcRua: vi.fn().mockResolvedValue(okRua([])),
		detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim([])),
		...overrides,
	};
}

describe('discoverBrandDomains', () => {
	it('returns a candidate from a single SAN signal (happy path)', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({ correlateSans: vi.fn().mockResolvedValue(okSan(['sister.com'])) });
		const result = await discoverBrandDomains('example.com', { signals: ['san'] }, deps);

		expect(result.category).toBe('brand_discovery');
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(1);
		expect(candidates[0].metadata?.candidate).toBe('sister.com');
		expect(candidates[0].metadata?.combinedConfidence).toBeCloseTo(0.7, 2); // SAN default = 0.7
		expect(candidates[0].metadata?.signals).toEqual(['san']);
	});

	it('aggregates multi-signal candidates with combined-confidence math', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		// Same candidate reported by SAN (0.7) AND DKIM (0.95).
		// combined = 1 - (1-0.7) * (1-0.95) = 1 - 0.3*0.05 = 1 - 0.015 = 0.985
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue(okSan(['sister.com'])),
			detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim(['sister.com'])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['san', 'dkim_key_reuse'], candidate_domains: ['sister.com'] },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(1);
		expect(candidates[0].metadata?.candidate).toBe('sister.com');
		expect(candidates[0].metadata?.combinedConfidence).toBeCloseTo(0.985, 3);
		expect((candidates[0].metadata?.signals as string[]).sort()).toEqual(['dkim_key_reuse', 'san']);
		// High-confidence => severity 'low' (auto-include candidate)
		expect(candidates[0].severity).toBe('low');
	});

	it('drops candidates below min_confidence', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		// NS partial overlap = 0.4, below default 0.5 threshold
		const deps = makeDeps({
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'weak.com', confidence: 0.4 }])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns'], candidate_domains: ['weak.com'] },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(0);
	});

	it('keeps candidates at or above an explicit min_confidence', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'partner.com', confidence: 0.6 }])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns'], candidate_domains: ['partner.com'], min_confidence: 0.5 },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(1);
		expect(candidates[0].metadata?.candidate).toBe('partner.com');
	});

	it('returns missingControl finding when signal modules all throw (DNS-failure resilience)', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateSans: vi.fn().mockRejectedValue(new Error('crt.sh timed out')),
			correlateNs: vi.fn().mockRejectedValue(new Error('DNS NXDOMAIN')),
			mineDmarcRua: vi.fn().mockRejectedValue(new Error('DNS error')),
			detectDkimKeyReuse: vi.fn().mockRejectedValue(new Error('DNS error')),
		});
		const result = await discoverBrandDomains('example.com', {}, deps);
		expect(result.category).toBe('brand_discovery');
		const missing = result.findings.find((f) => f.metadata?.missingControl);
		expect(missing).toBeDefined();
		expect(missing!.severity).toBe('high');
	});

	it('sorts candidates descending by combined confidence', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue(okSan(['low.com', 'high.com'])),
			detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim(['high.com'])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['san', 'dkim_key_reuse'], candidate_domains: ['high.com', 'low.com'] },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates[0].metadata?.candidate).toBe('high.com');
		expect(candidates[1].metadata?.candidate).toBe('low.com');
		expect(
			(candidates[0].metadata?.combinedConfidence as number) >=
				(candidates[1].metadata?.combinedConfidence as number),
		).toBe(true);
	});

	it('only invokes the requested signal modules', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const sanSpy = vi.fn().mockResolvedValue(okSan([]));
		const nsSpy = vi.fn().mockResolvedValue(okNs([]));
		const ruaSpy = vi.fn().mockResolvedValue(okRua([]));
		const dkimSpy = vi.fn().mockResolvedValue(okDkim([]));
		const deps: DiscoverBrandDomainsDeps = {
			correlateSans: sanSpy,
			correlateNs: nsSpy,
			mineDmarcRua: ruaSpy,
			detectDkimKeyReuse: dkimSpy,
		};
		await discoverBrandDomains('example.com', { signals: ['san'] }, deps);
		expect(sanSpy).toHaveBeenCalled();
		expect(nsSpy).not.toHaveBeenCalled();
		expect(ruaSpy).not.toHaveBeenCalled();
		expect(dkimSpy).not.toHaveBeenCalled();
	});

	it('throws on invalid seed domain (programmer error)', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		await expect(discoverBrandDomains('not a domain!', {}, makeDeps())).rejects.toThrow(/Domain validation failed/);
	});

	it('skips candidates that are subdomains of the seed domain', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		// Signal module incorrectly reports a subdomain of the seed as a candidate
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue(okSan(['dmarc.example.com', 'other.com'])),
		});
		const result = await discoverBrandDomains('example.com', { signals: ['san'] }, deps);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		
		// dmarc.example.com should be skipped, other.com should remain
		expect(candidates).toHaveLength(1);
		expect(candidates[0].metadata?.candidate).toBe('other.com');
	});

	it('format=compact omits emoji icons in formatter', async () => {
		const { formatDiscoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const result = {
			category: 'brand_discovery' as const,
			passed: true,
			score: 100,
			findings: [
				{
					category: 'brand_discovery' as const,
					title: 'Discovered candidate: sister.com',
					severity: 'low' as const,
					detail: 'Found via 1 signal(s); confidence 0.7',
					metadata: {
						candidate: 'sister.com',
						signals: ['san'],
						combinedConfidence: 0.7,
					},
				},
			],
		};
		const compact = formatDiscoverBrandDomains(result, 'compact');
		const full = formatDiscoverBrandDomains(result, 'full');
		// Emoji set used in full mode
		expect(/[🔵🟡🟠🔴]/.test(full)).toBe(true);
		expect(/[🔵🟡🟠🔴]/.test(compact)).toBe(false);
	});
});
