// SPDX-License-Identifier: BUSL-1.1

import { type Finding, createFinding } from '../scoring';
import { ROOT_HINTS, ROOT_SERVER_NAMES } from './root-hints';
import type { InfraCapabilityKey, InfraCapabilitySeverity, RootServerSetEvidence } from './types';
import type { InfraCapabilitySummary } from './analyze';

const CATEGORY = 'authoritative_dns_infra';

export interface RootServerSetAnalysis {
	findings: Finding[];
	capabilitySummary: InfraCapabilitySummary;
}

interface FailureTemplate {
	title: string;
	severity: InfraCapabilitySeverity;
	detail: string;
	metadata?: Record<string, unknown>;
}

function pushCapabilityResult(
	summary: InfraCapabilitySummary,
	findings: Finding[],
	capability: InfraCapabilityKey,
	status: boolean | undefined,
	failure: FailureTemplate,
): void {
	if (status === true) {
		summary.passed.push(capability);
		return;
	}
	if (status === false) {
		summary.failed.push(capability);
		findings.push(
			createFinding(CATEGORY, failure.title, failure.severity, failure.detail, {
				capability,
				evidenceMode: 'infra_probe',
				...(failure.metadata ?? {}),
			}),
		);
		return;
	}
	summary.inconclusive.push(capability);
}

function sameStringSet(left: readonly string[], right: readonly string[]): boolean {
	if (left.length !== right.length) return false;
	const normalizedRight = new Set(right.map((value) => value.toLowerCase().replace(/\.$/, '')));
	return left.every((value) => normalizedRight.has(value.toLowerCase().replace(/\.$/, '')));
}

function rootHintsMatchOfficial(evidence: RootServerSetEvidence): boolean {
	if (evidence.rootHints.length !== ROOT_HINTS.length) return false;
	return ROOT_HINTS.every((expected) => {
		const actual = evidence.rootHints.find((hint) => hint.name === expected.name);
		return actual?.ipv4 === expected.ipv4
			&& actual.ipv6 === expected.ipv6
			&& actual.operator === expected.operator;
	});
}

function valuesConverge(record: Record<string, string | number> | undefined): boolean | undefined {
	if (!record) return undefined;
	const unique = new Set(Object.values(record));
	return unique.size <= 1;
}

export function analyzeRootServerSetEvidence(evidence: RootServerSetEvidence): RootServerSetAnalysis {
	const findings: Finding[] = [];
	const capabilitySummary: InfraCapabilitySummary = { passed: [], failed: [], inconclusive: [] };

	pushCapabilityResult(
		capabilitySummary,
		findings,
		'official_root_hints_match',
		rootHintsMatchOfficial(evidence),
		{
			title: 'Root hints do not match official constants',
			severity: 'critical',
			detail: 'The infra probe returned root-hint address data that differs from the embedded official root hints.',
			metadata: { missingControl: true },
		},
	);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'root_priming_ns_set',
		evidence.observedRootServers
			? sameStringSet(evidence.observedRootServers, ROOT_SERVER_NAMES)
			: undefined,
		{
			title: 'Root server set mismatch',
			severity: 'critical',
			detail: 'Root priming did not return the complete a.root-servers.net through m.root-servers.net set.',
			metadata: {
				missingControl: true,
				observedRootServers: evidence.observedRootServers,
			},
		},
	);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'root_glue_records',
		evidence.glueMatchesHints,
		{
			title: 'Root glue does not match official hints',
			severity: 'critical',
			detail: 'Root-zone glue address records do not match the official root hints.',
			metadata: { missingControl: true },
		},
	);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'root_servers_parent_child_delegation',
		evidence.parentChildDelegationMatches,
		{
			title: 'Root parent/child delegation mismatch',
			severity: 'critical',
			detail: 'Parent and child delegation evidence for the root server set did not match.',
			metadata: { missingControl: true },
		},
	);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'root_server_ns_soa_dnskey_cross_compare',
		valuesConverge(evidence.dnskeyDigestsByRoot),
		{
			title: 'Root DNSKEY digests differ across roots',
			severity: 'high',
			detail: 'DNSKEY digest evidence differed across root server vantage checks.',
		},
	);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'stale_root_zone_serial_detection',
		valuesConverge(evidence.serialsByRoot),
		{
			title: 'Root zone serials differ across roots',
			severity: 'medium',
			detail: 'SOA serial evidence differed across root servers, which can indicate stale root-zone data.',
		},
	);

	if (findings.length === 0) {
		findings.push(
			createFinding(
				CATEGORY,
				'Root server set checks passed',
				'info',
				'Root-server-set evidence matched the official hints and all conclusive cross-root checks.',
				{ evidenceMode: 'infra_probe' },
			),
		);
	}

	return { findings, capabilitySummary };
}
