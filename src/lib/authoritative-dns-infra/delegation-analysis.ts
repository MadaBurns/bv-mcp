// SPDX-License-Identifier: BUSL-1.1

import { type Finding, createFinding } from '../scoring';
import type { DelegationConsistencyEvidence } from './delegation-types';

function canonical(values: string[]): string {
	return [...new Set(values.map((value) => value.replace(/\.$/, '').toLowerCase()))].sort().join('|');
}

function sameSet(left: string[], right: string[]): boolean {
	return canonical(left) === canonical(right);
}

function addressesDiffer(parent: string[], current: string[] | undefined): boolean {
	if (current === undefined || current.length === 0) return false;
	return !sameSet(parent, current);
}

export interface DelegationAnalysis {
	findings: Finding[];
	conclusive: boolean;
	failedChecks: string[];
}

/** Convert raw direct-DNS evidence into conservative, scored NS findings. */
export function analyzeDelegationConsistency(evidence: DelegationConsistencyEvidence): DelegationAnalysis {
	const findings: Finding[] = [];
	const failedChecks: string[] = [];
	const conclusiveChildren = evidence.childObservations.filter(
		(observation) => !observation.error && observation.rcode === 0 && typeof observation.aaFlag === 'boolean',
	);

	const parentSets = evidence.parentObservations
		.filter((observation) => !observation.error && observation.rcode === 0 && (observation.delegationNs?.length ?? 0) > 0)
		.map((observation) => canonical(observation.delegationNs ?? []));
	if (new Set(parentSets).size > 1) {
		failedChecks.push('parent_consistency');
		findings.push(
			createFinding(
				'ns',
				'Parent nameservers disagree on delegation',
				'medium',
				`Authoritative nameservers for ${evidence.parentZone} returned different NS delegations for ${evidence.hostname}. This can produce resolver-dependent routing during an incomplete registrar or registry update.`,
				{ parentObservations: evidence.parentObservations },
			),
		);
	}

	const nonAuthoritative = conclusiveChildren
		.filter((observation) => observation.aaFlag === false)
		.map((observation) => observation.nameserver);
	if (nonAuthoritative.length > 0) {
		failedChecks.push('authoritative_aa');
		findings.push(
			createFinding(
				'ns',
				'Delegated nameserver is not authoritative',
				'high',
				`The parent delegates ${evidence.hostname} to ${nonAuthoritative.join(', ')}, but direct RD=0 queries did not return the authoritative AA flag. Remove stale registrar delegation entries or provision the zone on those nameservers.`,
				{ nonAuthoritativeNameservers: nonAuthoritative, evidenceMode: 'direct_dns_tcp' },
			),
		);
	}

	const childMismatches = conclusiveChildren.filter(
		(observation) => observation.aaFlag === true && !sameSet(observation.publishedNs ?? [], evidence.parentDelegationNs),
	);
	if (childMismatches.length > 0) {
		failedChecks.push('parent_child_ns_match');
		findings.push(
			createFinding(
				'ns',
				'Parent and child NS sets do not match',
				'high',
				`The parent delegation for ${evidence.hostname} does not match the NS set published by ${childMismatches.map((observation) => observation.nameserver).join(', ')}. Resolvers may use stale or unintended authoritative servers until both sides are aligned.`,
				{
					parentNs: evidence.parentDelegationNs,
					childObservations: childMismatches,
					evidenceMode: 'direct_dns_tcp',
				},
			),
		);
	}

	const missingGlue = evidence.glue
		.filter((observation) => observation.parentIpv4.length === 0 && observation.parentIpv6.length === 0)
		.map((observation) => observation.nameserver);
	if (missingGlue.length > 0) {
		failedChecks.push('in_bailiwick_glue');
		findings.push(
			createFinding(
				'ns',
				'In-bailiwick nameserver glue is missing',
				'high',
				`${missingGlue.join(', ')} ${missingGlue.length === 1 ? 'is' : 'are'} inside ${evidence.hostname} but the parent referral supplied no A or AAAA glue. This creates a circular dependency that can make the delegation unreachable. Publish glue at the registrar or registry.`,
				{ missingGlueNameservers: missingGlue, evidenceMode: 'direct_dns_tcp' },
			),
		);
	}

	const staleGlue = evidence.glue.filter(
		(observation) =>
			addressesDiffer(observation.parentIpv4, observation.currentIpv4) ||
			addressesDiffer(observation.parentIpv6, observation.currentIpv6),
	);
	if (staleGlue.length > 0) {
		failedChecks.push('glue_address_match');
		findings.push(
			createFinding(
				'ns',
				'Parent glue addresses are stale',
				'medium',
				`Parent glue for ${staleGlue.map((observation) => observation.nameserver).join(', ')} does not match the nameservers' current A/AAAA records. Update host/glue records at the registrar to prevent intermittent delegation failures.`,
				{ staleGlue, evidenceMode: 'direct_dns_tcp' },
			),
		);
	}

	const conclusive = evidence.parentDelegationNs.length > 0 && conclusiveChildren.some((observation) => observation.aaFlag === true);
	if (findings.length === 0 && conclusive) {
		findings.push(
			createFinding(
				'ns',
				'Parent/child delegation and glue are consistent',
				'info',
				`Direct DNS-over-TCP checks confirmed that the parent and child NS sets for ${evidence.hostname} align, delegated servers answer authoritatively, and required in-bailiwick glue is present.`,
				{ evidenceMode: 'direct_dns_tcp', checkedAt: evidence.checkedAt },
			),
		);
	}

	return { findings, conclusive, failedChecks };
}
