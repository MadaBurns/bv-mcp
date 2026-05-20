// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';

const REQUIRED_INFRA_CAPABILITIES = [
	'dns53_udp_reachability',
	'dns53_tcp_reachability',
	'authoritative_aa_flag',
	'recursion_ra_refused',
	'root_priming_ns_set',
	'soa_serial_consistency',
	'direct_dnssec_dnskey_ds_rrsig',
	'edns0_large_response',
	'truncation_and_tcp_fallback',
	'zone_transfer_refusal',
	'amplification_ratio',
	'dns_cookies_or_rrl',
	'ipv4_ipv6_parity',
	'bgp_origin_asn',
	'rpki_roa_validity',
	'anycast_path_diversity',
	'vantage_latency_jitter_loss',
	'route_leak_hijack_alerts',
	'prefix_rir_rdap',
	'official_root_hints_match',
	'root_glue_records',
	'root_servers_parent_child_delegation',
	'root_server_ns_soa_dnskey_cross_compare',
	'stale_root_zone_serial_detection',
	'chaos_id_version_behavior',
	'unsupported_query_refusal',
	'ptr_reverse_dns_consistency',
] as const;

describe('authoritative DNS infrastructure coverage', () => {
	it('tracks every required root-server infrastructure capability', async () => {
		const { AUTHORITATIVE_DNS_INFRA_CAPABILITY_MAP } = await import('../../src/lib/authoritative-dns-infra/types');

		expect(Object.keys(AUTHORITATIVE_DNS_INFRA_CAPABILITY_MAP).sort()).toEqual([...REQUIRED_INFRA_CAPABILITIES].sort());
		for (const capability of REQUIRED_INFRA_CAPABILITIES) {
			expect(AUTHORITATIVE_DNS_INFRA_CAPABILITY_MAP[capability]).toMatchObject({
				source: expect.stringMatching(/^(worker|infra_probe|worker_and_infra_probe)$/),
				scoredBy: expect.stringMatching(/^check_(authoritative_dns_infra|root_server_set)$/),
				severityWhenMissing: expect.stringMatching(/^(info|low|medium|high|critical)$/),
			});
		}
	});
});
