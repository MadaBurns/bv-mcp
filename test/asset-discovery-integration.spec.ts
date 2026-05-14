import { describe, it, expect } from 'vitest';

// Import the actual tools (unmocked)
import { discoverBrandDomains } from '../src/tools/discover-brand-domains';
import { discoverSubdomains } from '../src/tools/discover-subdomains';
import { checkShadowDomains } from '../src/tools/check-shadow-domains';

const corpus = {
	seed: "blackveilsecurity.com",
	groundTruth: {
		// dns-mcp.* is the production MCP endpoint with a current CT-logged cert,
		// so it's a stable ground-truth anchor for the live crt.sh check. www.*
		// was used previously but isn't a literal SAN — only the wildcard
		// *.blackveilsecurity.com covers it, and discoverSubdomains doesn't
		// expand wildcards into synthetic literals.
		subdomains: ["dns-mcp.blackveilsecurity.com"],
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

	it('should discover expected brand domains via NS correlation', async () => {
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

