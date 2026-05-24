import { describe, it, expect } from 'vitest';
const RECON_TOOLS = [
	'discover_subdomains',
	'discover_brand_domains',
	'check_lookalikes',
	'check_shadow_domains',
	'check_mx_reputation',
	'map_supply_chain',
	'map_compliance',
	'simulate_attack_paths',
	'check_fast_flux',
	'analyze_drift',
	'check_dbl',
	'check_rbl',
	'rdap_lookup',
	'cymru_asn',
];
describe('outbound-heavy tool caps', () => {
	it('caps every recon/discovery tool at <=5 free-tier daily', async () => {
		const { FREE_TOOL_DAILY_LIMITS } = await import('../src/lib/config');
		for (const t of RECON_TOOLS) {
			expect(FREE_TOOL_DAILY_LIMITS[t], `${t} exceeds 5`).toBeLessThanOrEqual(5);
		}
	});
});
