import { describe, it, expect } from 'vitest';
import {
	GATED_PAID_ONLY_TOOLS,
	SELF_SERVE_UPGRADE_TOOLS,
	ENUMERABLE_RECON_UPGRADE_TOOLS,
	UPGRADE_SELF_SERVE_URL,
	UPGRADE_SALES_URL,
	resolveUpgradeChannel,
	buildUpgradeData,
} from '../../src/lib/config';

/**
 * The upgrade-channel partition is the "money alone never opens the enumeration
 * surface" invariant expressed at the paywall boundary: a free caller hitting a
 * gated tool is routed either to self-serve checkout (a small curated set) or to
 * vetted sales (everything that enumerates). This audit pins the partition and a
 * name-pattern tripwire so an enumerating recon/OSINT/brand-discovery tool can
 * never silently drift into the self-serve set.
 */
describe('upgrade-channel SSOT', () => {
	it('SELF_SERVE is a strict subset of the gated set', () => {
		expect(SELF_SERVE_UPGRADE_TOOLS.size).toBeGreaterThan(0);
		for (const tool of SELF_SERVE_UPGRADE_TOOLS) {
			expect(GATED_PAID_ONLY_TOOLS.has(tool)).toBe(true);
		}
	});

	it('SELF_SERVE and ENUMERABLE_RECON are disjoint', () => {
		for (const tool of SELF_SERVE_UPGRADE_TOOLS) {
			expect(ENUMERABLE_RECON_UPGRADE_TOOLS.has(tool)).toBe(false);
		}
	});

	it('SELF_SERVE ∪ ENUMERABLE_RECON exactly partitions the gated set', () => {
		const union = new Set<string>([...SELF_SERVE_UPGRADE_TOOLS, ...ENUMERABLE_RECON_UPGRADE_TOOLS]);
		expect(union.size).toBe(GATED_PAID_ONLY_TOOLS.size);
		expect(SELF_SERVE_UPGRADE_TOOLS.size + ENUMERABLE_RECON_UPGRADE_TOOLS.size).toBe(GATED_PAID_ONLY_TOOLS.size);
		for (const tool of GATED_PAID_ONLY_TOOLS) {
			expect(union.has(tool)).toBe(true);
		}
	});

	it('no SELF_SERVE member matches an enumerator name pattern (tripwire)', () => {
		// If a future edit puts an enumerating tool into SELF_SERVE, this fires.
		const enumeratorPattern = /^(discover_|osint_|map_|prioritize_|scan_buckets_|register_brand|delete_brand|list_brand|brand_audit_|check_lookalikes|check_shadow_domains|check_fast_flux|check_realtime|simulate_|query_|get_ca_policies|assess_coverage)|_start$/;
		for (const tool of SELF_SERVE_UPGRADE_TOOLS) {
			expect(tool).not.toMatch(enumeratorPattern);
		}
	});

	it('resolveUpgradeChannel defaults an unknown/new gated tool to sales', () => {
		expect(resolveUpgradeChannel('some_brand_new_recon_tool')).toBe('sales');
	});

	it('resolveUpgradeChannel routes SELF_SERVE tools to self_serve', () => {
		for (const tool of SELF_SERVE_UPGRADE_TOOLS) {
			expect(resolveUpgradeChannel(tool)).toBe('self_serve');
		}
	});

	it('resolveUpgradeChannel routes ENUMERABLE_RECON tools to sales', () => {
		for (const tool of ENUMERABLE_RECON_UPGRADE_TOOLS) {
			expect(resolveUpgradeChannel(tool)).toBe('sales');
		}
	});

	it('a pure volume block (isVolume429) is always self_serve regardless of tool', () => {
		expect(resolveUpgradeChannel('discover_subdomains', true)).toBe('self_serve');
		expect(resolveUpgradeChannel('scan_domain', true)).toBe('self_serve');
	});

	it('buildUpgradeData attaches the channel-correct URL, developer tier, and a tool-naming CTA', () => {
		const selfServe = buildUpgradeData('batch_scan');
		expect(selfServe.upgrade).toEqual({
			channel: 'self_serve',
			url: UPGRADE_SELF_SERVE_URL,
			tool: 'batch_scan',
			tier_required: 'developer',
			cta: 'Upgrade to the developer tier to unlock batch_scan.',
		});

		const sales = buildUpgradeData('discover_subdomains');
		expect(sales.upgrade).toEqual({
			channel: 'sales',
			url: UPGRADE_SALES_URL,
			tool: 'discover_subdomains',
			tier_required: 'developer',
			cta: 'Contact us to enable discover_subdomains on a vetted plan.',
		});
	});

	it('the CTA is price-free and plan-name-free (public-surface copy invariant)', () => {
		// The CTA must never leak a price or a marketing plan name — those are
		// operator-owned. It may name the existing `developer` tier and the tool.
		for (const tool of ['batch_scan', 'discover_subdomains', 'map_supply_chain']) {
			const { cta } = buildUpgradeData(tool).upgrade;
			expect(cta).toContain(tool);
			expect(cta).not.toMatch(/\$\d|\bUSD\b|\bpro\b|\benterprise\b|\bstarter\b|\bbusiness\b/i);
		}
	});
});
