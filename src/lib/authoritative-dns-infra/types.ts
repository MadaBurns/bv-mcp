// SPDX-License-Identifier: BUSL-1.1

export type InfraCapabilitySource = 'worker' | 'infra_probe' | 'worker_and_infra_probe';
export type InfraCapabilitySeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type InfraScoredBy = 'check_authoritative_dns_infra' | 'check_root_server_set';

export interface InfraCapabilityDefinition {
	source: InfraCapabilitySource;
	scoredBy: InfraScoredBy;
	severityWhenMissing: InfraCapabilitySeverity;
}

export const AUTHORITATIVE_DNS_INFRA_CAPABILITY_MAP = {
	dns53_udp_reachability: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'high',
	},
	dns53_tcp_reachability: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'high',
	},
	authoritative_aa_flag: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'critical',
	},
	recursion_ra_refused: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'critical',
	},
	root_priming_ns_set: {
		source: 'worker_and_infra_probe',
		scoredBy: 'check_root_server_set',
		severityWhenMissing: 'critical',
	},
	soa_serial_consistency: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'medium',
	},
	direct_dnssec_dnskey_ds_rrsig: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'high',
	},
	edns0_large_response: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'medium',
	},
	truncation_and_tcp_fallback: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'medium',
	},
	zone_transfer_refusal: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'critical',
	},
	amplification_ratio: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'high',
	},
	dns_cookies_or_rrl: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'medium',
	},
	ipv4_ipv6_parity: {
		source: 'worker_and_infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'medium',
	},
	bgp_origin_asn: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'medium',
	},
	rpki_roa_validity: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'high',
	},
	anycast_path_diversity: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'medium',
	},
	vantage_latency_jitter_loss: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'low',
	},
	route_leak_hijack_alerts: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'critical',
	},
	prefix_rir_rdap: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'low',
	},
	official_root_hints_match: {
		source: 'worker',
		scoredBy: 'check_root_server_set',
		severityWhenMissing: 'critical',
	},
	root_glue_records: {
		source: 'worker_and_infra_probe',
		scoredBy: 'check_root_server_set',
		severityWhenMissing: 'critical',
	},
	root_servers_parent_child_delegation: {
		source: 'worker_and_infra_probe',
		scoredBy: 'check_root_server_set',
		severityWhenMissing: 'critical',
	},
	root_server_ns_soa_dnskey_cross_compare: {
		source: 'worker_and_infra_probe',
		scoredBy: 'check_root_server_set',
		severityWhenMissing: 'high',
	},
	stale_root_zone_serial_detection: {
		source: 'worker_and_infra_probe',
		scoredBy: 'check_root_server_set',
		severityWhenMissing: 'medium',
	},
	chaos_id_version_behavior: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'low',
	},
	unsupported_query_refusal: {
		source: 'infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'medium',
	},
	ptr_reverse_dns_consistency: {
		source: 'worker_and_infra_probe',
		scoredBy: 'check_authoritative_dns_infra',
		severityWhenMissing: 'low',
	},
} as const satisfies Record<string, InfraCapabilityDefinition>;

export type InfraCapabilityKey = keyof typeof AUTHORITATIVE_DNS_INFRA_CAPABILITY_MAP;

export interface AddressSet {
	addresses: string[];
	reachable?: boolean;
	errors?: string[];
}

export interface ReachabilityEvidence {
	ipv4?: AddressSet;
	ipv6?: AddressSet;
	udp53Reachable?: boolean;
	tcp53Reachable?: boolean;
}

export interface AuthoritativeBehaviorEvidence {
	aaFlag?: boolean;
	recursionAvailable?: boolean;
	recursionRefused?: boolean;
}

export interface RootPrimingEvidence {
	nsNames?: string[];
	matchesOfficialHints?: boolean;
}

export interface SoaSerialEvidence {
	serialsByNameserver?: Record<string, number>;
	consistent?: boolean;
}

export interface DnssecDirectEvidence {
	dnskeyPresent?: boolean;
	dsPresent?: boolean;
	rrsigPresent?: boolean;
	validates?: boolean;
}

export interface LargeResponseHandlingEvidence {
	edns0Supported?: boolean;
	largeUdpResponseOk?: boolean;
	truncatesWhenNeeded?: boolean;
	tcpFallbackOk?: boolean;
}

export interface ZoneTransferRefusalEvidence {
	axfrRefused?: boolean;
	ixfrRefused?: boolean;
}

export interface AmplificationEvidence {
	maxAmplificationRatio?: number;
	risky?: boolean;
}

export interface AbuseResistanceEvidence {
	dnsCookiesSupported?: boolean;
	responseRateLimited?: boolean;
}

export interface TransportParityEvidence {
	ipv4Ipv6Parity?: boolean;
	notes?: string[];
}

export interface BgpRoutingEvidence {
	originAsns?: number[];
	expectedOriginAsns?: number[];
	rpkiStatus?: 'valid' | 'invalid' | 'not_found' | 'unknown';
	anycastPaths?: string[];
	routeLeakOrHijackSignals?: string[];
}

export interface VantageMetricsEvidence {
	vantageCount?: number;
	latencyMsP50?: number;
	latencyMsP95?: number;
	jitterMs?: number;
	packetLossPct?: number;
}

export interface OperationalExposureEvidence {
	rir?: string;
	rdapHandle?: string;
	ptrRecords?: string[];
	chaosId?: string;
	chaosVersion?: string;
	unsupportedQueriesRefused?: boolean;
}

export interface AuthoritativeDnsInfraEvidence {
	hostname: string;
	checkedAt?: string;
	reachability?: ReachabilityEvidence;
	authoritative?: AuthoritativeBehaviorEvidence;
	rootPriming?: RootPrimingEvidence;
	soaSerial?: SoaSerialEvidence;
	dnssec?: DnssecDirectEvidence;
	largeResponse?: LargeResponseHandlingEvidence;
	zoneTransfer?: ZoneTransferRefusalEvidence;
	amplification?: AmplificationEvidence;
	abuseResistance?: AbuseResistanceEvidence;
	transportParity?: TransportParityEvidence;
	routing?: BgpRoutingEvidence;
	vantage?: VantageMetricsEvidence;
	operationalExposure?: OperationalExposureEvidence;
	errors?: string[];
}

export interface RootHintEntryEvidence {
	name: string;
	ipv4: string;
	ipv6: string;
	operator: string;
}

export interface RootServerSetEvidence {
	hostname: '.';
	checkedAt?: string;
	rootHints: RootHintEntryEvidence[];
	observedRootServers?: string[];
	parentChildDelegationMatches?: boolean;
	glueMatchesHints?: boolean;
	serialsByRoot?: Record<string, number>;
	dnskeyDigestsByRoot?: Record<string, string>;
	errors?: string[];
}
