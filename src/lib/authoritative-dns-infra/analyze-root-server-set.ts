// SPDX-License-Identifier: BUSL-1.1

import { type Finding, createFinding } from '../scoring';
import { ROOT_HINTS, ROOT_SERVER_NAMES } from './root-hints';
import type { InfraCapabilityKey, InfraCapabilitySeverity, RootServerSetEvidence } from './types';
import { type InfraCapabilitySummary, isUnconfiguredLaneCode } from './analyze';

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

/** Reported by the sidecar when its root-server-set lane queried nothing. */
const ROOT_SET_LANE_UNCONFIGURED = 'live_root_server_set_probe_not_configured';
/** Reported by the lane when no session answered at all — transient/environmental. */
const ROOT_SET_NO_CONTACT = 'root_server_set_probe_no_contact';
/** Reported by the lane when sessions answered but none proved authoritative (AA=1) —
 * usually DNS interception on the probe's network path, or a lame delegation. */
const ROOT_SET_NO_AUTHORITATIVE_ANSWER = 'root_server_set_probe_no_authoritative_answer';

const MAX_REPORTED_ROOT_NAMES = 26;
const MAX_HOSTNAME_LENGTH = 253;

/**
 * Names decoded off the wire are attacker-influenced (an on-path responder can put any
 * bytes in an NS RDATA label) and this metadata reaches LLM clients verbatim. Report at
 * most twice the real root set, each reduced to hostname characters and capped (SQ-131 S6).
 */
function boundedHostnames(names: readonly string[] | undefined): string[] | undefined {
	return names?.slice(0, MAX_REPORTED_ROOT_NAMES).map((name) => name.replace(/[^A-Za-z0-9.-]/g, '?').slice(0, MAX_HOSTNAME_LENGTH));
}

/**
 * Did this evidence carry at least one LIVE authoritative observation of the root zone?
 * `official_root_hints_match` compares the sidecar's `rootHints` against this Worker's own
 * embedded copy of the SAME module — with no other live signal alongside it, a MATCH is the
 * checker agreeing with itself, not a measurement (#1079 class, comment c_mubkwv04_a0fee8).
 */
function hasLiveObservation(evidence: RootServerSetEvidence): boolean {
	return (evidence.observedRootServers?.length ?? 0) > 0 || Object.keys(evidence.serialsByRoot ?? {}).length > 0;
}

export function analyzeRootServerSetEvidence(probeEvidence: RootServerSetEvidence): RootServerSetAnalysis {
	const findings: Finding[] = [];
	const capabilitySummary: InfraCapabilitySummary = { passed: [], failed: [], inconclusive: [] };

	// A lane that reports itself unconfigured observed nothing, so none of its cross-root
	// claims — pass OR fail — is a measurement. The sidecar used to send `observedRootServers`
	// (a copy of the hints), `glueMatchesHints: true` and `parentChildDelegationMatches: true`
	// beside this very error, and the tool published 100 / passed for a root zone nobody
	// queried. The sidecar deploys separately from this Worker, so a stale one must not be
	// able to do that; twin of `withoutUnmeasuredRawDnsEvidence` in analyze.ts.
	const laneUnconfigured = (probeEvidence.errors ?? []).includes(ROOT_SET_LANE_UNCONFIGURED);
	const evidence: RootServerSetEvidence = laneUnconfigured
		? {
				hostname: probeEvidence.hostname,
				checkedAt: probeEvidence.checkedAt,
				rootHints: probeEvidence.rootHints,
				errors: probeEvidence.errors,
			}
		: probeEvidence;

	// ⚠️ Deliberately asymmetric, and generalised past "lane unconfigured": a MATCH may PASS
	// only when the evidence also carries a live authoritative observation
	// (`hasLiveObservation`) — rootHints alone is the sidecar's build of the SAME root-hints
	// module this file imports, so a bare MATCH is the checker agreeing with itself
	// (#696/#1079, live-smoke evidence comment c_mubkwv04_a0fee8: an intercepting middlebox
	// answered every session non-authoritatively and the old `laneUnconfigured`-only gate let
	// the vacuous self-match through as a published pass). A MISMATCH is always a genuine
	// observed inconsistency and still scores as a real failure regardless of live
	// observation — #828.
	const hintsMatch = rootHintsMatchOfficial(evidence);
	const liveObservation = hasLiveObservation(evidence);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'official_root_hints_match',
		!liveObservation && hintsMatch ? undefined : hintsMatch,
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
				observedRootServers: boundedHostnames(evidence.observedRootServers),
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
		// `findings.length === 0` only means no FAILURE finding was emitted — every
		// `pushCapabilityResult(..., false, ...)` call above pushes one, so a failure
		// would already show up here. It says nothing about whether anything was
		// actually CONCLUSIVE: with every capability inconclusive (`passed` and
		// `failed` both empty), this branch is reached with zero evidence either way.
		// Asserting a pass there is a vacuous truth ("satisfied all zero checks") that
		// directly contradicted the sibling structured fields the caller derives from
		// this same `capabilitySummary` — see `analyze.ts`'s twin fix (#812, PR #824).
		// Gate the affirmative finding on at least one CONCLUSIVE (passed) capability,
		// and tell the truth otherwise.
		if (capabilitySummary.passed.length > 0) {
			findings.push(
				createFinding(
					CATEGORY,
					'Root server set checks passed',
					'info',
					'Root-server-set evidence matched the official hints and all conclusive cross-root checks.',
					{ evidenceMode: 'infra_probe' },
				),
			);
		} else {
			// Same reasoning as #1054: when the probe says WHY nothing was verified, name the
			// state — a PROVISIONING state (`*_not_configured`) cannot change on retry, but a
			// NO-CONTACT / NO-AUTHORITATIVE-ANSWER abstention is transient and environmental
			// (a dropped connection, or a middlebox intercepting TCP/53) and IS worth retrying,
			// so it must never carry `unprovisioned: true`.
			const unconfigured = (evidence.errors ?? []).filter(isUnconfiguredLaneCode);
			const errors = evidence.errors ?? [];
			const noAuthoritativeAnswer = errors.includes(ROOT_SET_NO_AUTHORITATIVE_ANSWER);
			const noContact = errors.includes(ROOT_SET_NO_CONTACT);
			let detail: string;
			if (unconfigured.length > 0) {
				detail = `The infra probe's root-server-set lane is not provisioned in this deployment (${unconfigured.join(', ')}): it returns the embedded official root hints without querying the root zone, so no capability could be verified either way. This is a provisioning state, not a transient failure — retrying returns the same result.`;
			} else if (noAuthoritativeAnswer) {
				detail = 'The infra probe received responses from the sampled root servers, but none was authoritative (AA=1) for the root zone, which usually means DNS interception on the probe\'s network path or a lame delegation. This is transient and environmental, not a provisioning state — retrying, or a different vantage, may succeed.';
			} else if (noContact) {
				detail = 'The infra probe could not establish contact with any of the sampled root servers. This is transient and environmental, not a provisioning state — retrying may succeed.';
			} else {
				detail = 'Root-server-set evidence did not yield any conclusive capability checks; nothing was verified.';
			}
			findings.push(
				createFinding(CATEGORY, 'Root server set checks inconclusive', 'info', detail, {
					evidenceMode: 'infra_probe',
					inconclusive: true,
					...(unconfigured.length > 0 ? { unprovisioned: true, probeErrors: unconfigured } : {}),
				}),
			);
		}
	}

	return { findings, capabilitySummary };
}
