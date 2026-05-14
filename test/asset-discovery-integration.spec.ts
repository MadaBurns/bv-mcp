import { describe, it, expect } from 'vitest';

// Import the actual tools (unmocked)
import { discoverBrandDomains } from '../src/tools/discover-brand-domains';
import { discoverSubdomains } from '../src/tools/discover-subdomains';
import { checkShadowDomains } from '../src/tools/check-shadow-domains';

const corpus = {
	seed: "blackveilsecurity.com",
	groundTruth: {
		subdomains: ["www.blackveilsecurity.com"],
		brandDomains: [
			{ domain: "blackveil.nz", signals: ["ns"] },
			{ domain: "blackveil.io", signals: ["ns"] }
		],
		shadowVariants: [
			{ domain: "blackveilsecurity.net", expectedSeverity: "info" },
			{ domain: "blackveilsecurity.org", expectedSeverity: "info" }
		]
	}
};

describe('Asset Discovery Integration (Live)', () => {
	it('should discover expected subdomains from live crt.sh', async () => {
		const result = await discoverSubdomains(corpus.seed);
		
		expect(result.domain).toBe(corpus.seed);
		// Note: this might still fail if crt.sh is down
		if (result.totalSubdomains === 0) {
			console.warn('crt.sh returned 0 subdomains for ' + corpus.seed + '. It might be down (502/404).');
			return;
		}
		expect(result.totalSubdomains).toBeGreaterThan(0);
		
		const foundNames = result.subdomains.map(s => s.subdomain);
		for (const expected of corpus.groundTruth.subdomains) {
			expect(foundNames).toContain(expected);
		}
	}, 30000); // Higher timeout for live network

	// LR-2 (PR #111) intentionally filters single-signal NS candidates because
	// commodity-DNS / parking co-tenants on the same nameserver are ambient
	// noise — they cannot be distinguished from a true brand-affiliated apex
	// without a second corroborating signal. blackveil.nz / blackveil.io
	// would each return a 1.0-confidence NS match but no second signal in a
	// live test, so they're dropped by the NEAR_DETERMINISTIC_SIGNALS gate.
	// The new policy is pinned by test/discover-brand-domains-corroboration.test.ts.
	it.skip('should discover expected brand domains via NS correlation (legacy single-signal — see LR-2)', async () => {
		// For NS signal to work, we must provide candidates to correlate
		const result = await discoverBrandDomains(corpus.seed, {
			signals: ['ns'],
			candidate_domains: corpus.groundTruth.brandDomains.map(d => d.domain),
			min_confidence: 0.1
		});

		const candidates = result.findings
			.filter(f => f.metadata?.candidate)
			.map(f => ({
				domain: f.metadata?.candidate as string,
				signals: f.metadata?.signals as string[]
			}));

		for (const expected of corpus.groundTruth.brandDomains) {
			const match = candidates.find(c => c.domain === expected.domain);
			expect(match, `Expected to find brand domain ${expected.domain} in ${JSON.stringify(candidates)}`).toBeDefined();
			for (const signal of expected.signals) {
				expect(match!.signals).toContain(signal);
			}
		}
	}, 30000);

	it('should identify shadow variants and their registration status', async () => {
		const result = await checkShadowDomains(corpus.seed);
		
		expect(result.category).toBe('shadow_domains');
		
		const findingDetails = result.findings.map(f => f.detail).join(' | ');
		
		for (const expected of corpus.groundTruth.shadowVariants) {
			const finding = result.findings.find(f => f.detail.toLowerCase().includes(expected.domain.toLowerCase()));
			expect(finding, `Expected to find shadow variant ${expected.domain} in findings: ${findingDetails}`).toBeDefined();
			expect(finding!.severity).toBe(expected.expectedSeverity);
		}
	}, 30000);
});

