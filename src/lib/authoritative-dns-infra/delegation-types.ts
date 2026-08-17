// SPDX-License-Identifier: BUSL-1.1

export interface ParentDelegationObservation {
	nameserver: string;
	delegationNs?: string[];
	glueIpv4?: Record<string, string[]>;
	glueIpv6?: Record<string, string[]>;
	rcode?: number;
	error?: string;
}

export interface ChildAuthorityObservation {
	nameserver: string;
	aaFlag?: boolean;
	publishedNs?: string[];
	rcode?: number;
	error?: string;
}

export interface GlueObservation {
	nameserver: string;
	parentIpv4: string[];
	parentIpv6: string[];
	currentIpv4?: string[];
	currentIpv6?: string[];
}

/** Raw ordinary-zone delegation evidence returned by BV_INFRA_PROBE. */
export interface DelegationConsistencyEvidence {
	hostname: string;
	parentZone: string;
	checkedAt: string;
	parentNameservers: string[];
	parentDelegationNs: string[];
	parentObservations: ParentDelegationObservation[];
	childObservations: ChildAuthorityObservation[];
	glue: GlueObservation[];
	errors?: string[];
}
