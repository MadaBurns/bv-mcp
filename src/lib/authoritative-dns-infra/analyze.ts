// SPDX-License-Identifier: BUSL-1.1

import { type Finding, createFinding } from '../scoring';
import type {
	AuthoritativeDnsInfraEvidence,
	InfraCapabilityKey,
	InfraCapabilitySeverity,
} from './types';

const CATEGORY = 'authoritative_dns_infra';
const AMPLIFICATION_RATIO_LIMIT = 10;
const LATENCY_P95_LIMIT_MS = 500;
const PACKET_LOSS_LIMIT_PCT = 1;

export interface InfraCapabilitySummary {
	passed: InfraCapabilityKey[];
	failed: InfraCapabilityKey[];
	inconclusive: InfraCapabilityKey[];
}

export interface AuthoritativeDnsInfraAnalysis {
	findings: Finding[];
	capabilitySummary: InfraCapabilitySummary;
}

type CapabilityStatus = boolean | undefined;

interface FailureTemplate {
	title: string;
	severity: InfraCapabilitySeverity;
	detail: string;
	metadata?: Record<string, unknown>;
}

function includesOnlyExpectedOrigins(origins: number[], expected: number[]): boolean {
	if (origins.length === 0 || expected.length === 0) return false;
	const expectedSet = new Set(expected);
	return origins.every((origin) => expectedSet.has(origin));
}

function pushCapabilityResult(
	summary: InfraCapabilitySummary,
	findings: Finding[],
	capability: InfraCapabilityKey,
	status: CapabilityStatus,
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

function reachabilityStatus(evidence: AuthoritativeDnsInfraEvidence): CapabilityStatus {
	if (typeof evidence.reachability?.udp53Reachable === 'boolean') {
		return evidence.reachability.udp53Reachable;
	}
	const addressSets = [evidence.reachability?.ipv4, evidence.reachability?.ipv6].filter(Boolean);
	if (addressSets.length === 0) return undefined;
	return addressSets.some((set) => set?.reachable === true);
}

function recursionRefusedStatus(evidence: AuthoritativeDnsInfraEvidence): CapabilityStatus {
	if (evidence.authoritative?.recursionAvailable === true) return false;
	if (evidence.authoritative?.recursionAvailable === false) return true;
	if (evidence.authoritative?.recursionRefused === true) return true;
	if (evidence.authoritative?.recursionRefused === false) return false;
	return undefined;
}

function zoneTransferRefusedStatus(evidence: AuthoritativeDnsInfraEvidence): CapabilityStatus {
	const axfr = evidence.zoneTransfer?.axfrRefused;
	const ixfr = evidence.zoneTransfer?.ixfrRefused;
	if (axfr === false || ixfr === false) return false;
	if (axfr === true || ixfr === true) return true;
	return undefined;
}

function directDnssecStatus(evidence: AuthoritativeDnsInfraEvidence): CapabilityStatus {
	if (evidence.dnssec?.validates === true) return true;
	const values = [
		evidence.dnssec?.dnskeyPresent,
		evidence.dnssec?.dsPresent,
		evidence.dnssec?.rrsigPresent,
	];
	if (values.some((value) => value === false)) return false;
	if (values.every((value) => value === true)) return true;
	return undefined;
}

function largeResponseStatus(evidence: AuthoritativeDnsInfraEvidence): CapabilityStatus {
	const edns0 = evidence.largeResponse?.edns0Supported;
	const largeUdp = evidence.largeResponse?.largeUdpResponseOk;
	if (edns0 === false || largeUdp === false) return false;
	if (edns0 === true && largeUdp === true) return true;
	return undefined;
}

function tcpFallbackStatus(evidence: AuthoritativeDnsInfraEvidence): CapabilityStatus {
	const truncates = evidence.largeResponse?.truncatesWhenNeeded;
	const fallback = evidence.largeResponse?.tcpFallbackOk;
	if (truncates === false || fallback === false) return false;
	if (truncates === true && fallback === true) return true;
	if (fallback === true) return true;
	return undefined;
}

function amplificationStatus(evidence: AuthoritativeDnsInfraEvidence): CapabilityStatus {
	const ratio = evidence.amplification?.maxAmplificationRatio;
	if (evidence.amplification?.risky === true) return false;
	if (typeof ratio === 'number' && ratio > AMPLIFICATION_RATIO_LIMIT) return false;
	if (evidence.amplification?.risky === false || typeof ratio === 'number') return true;
	return undefined;
}

function abuseResistanceStatus(evidence: AuthoritativeDnsInfraEvidence): CapabilityStatus {
	const cookies = evidence.abuseResistance?.dnsCookiesSupported;
	const rrl = evidence.abuseResistance?.responseRateLimited;
	if (cookies === false && rrl === false) return false;
	if (cookies === true || rrl === true) return true;
	return undefined;
}

function bgpOriginStatus(evidence: AuthoritativeDnsInfraEvidence): CapabilityStatus {
	const origins = evidence.routing?.originAsns ?? [];
	const expected = evidence.routing?.expectedOriginAsns ?? [];
	if (origins.length === 0) return undefined;
	if (expected.length === 0) return true;
	return includesOnlyExpectedOrigins(origins, expected);
}

function rpkiStatus(evidence: AuthoritativeDnsInfraEvidence): CapabilityStatus {
	switch (evidence.routing?.rpkiStatus) {
		case 'valid': return true;
		case 'invalid': return false;
		case 'not_found': return false;
		case 'unknown': return undefined;
		default: return undefined;
	}
}

function vantageStatus(evidence: AuthoritativeDnsInfraEvidence): CapabilityStatus {
	const vantage = evidence.vantage;
	if (!vantage) return undefined;
	if ((vantage.packetLossPct ?? 0) > PACKET_LOSS_LIMIT_PCT) return false;
	if ((vantage.latencyMsP95 ?? 0) > LATENCY_P95_LIMIT_MS) return false;
	if (
		typeof vantage.vantageCount === 'number' ||
		typeof vantage.latencyMsP50 === 'number' ||
		typeof vantage.latencyMsP95 === 'number'
	) return true;
	return undefined;
}

/**
 * Did the probe establish *any* positive contact with the target?
 *
 * Reachability over UDP/53 or TCP/53 is the transport substrate every other
 * authoritative probe rides on. If the probe never reached the target at all,
 * a single `udp53Reachable === false` reflects a probe-side / vantage limitation
 * (the BV_INFRA_PROBE couldn't get to the target), NOT positive evidence that the
 * domain refuses DNS service. Only treat a reachability failure as a genuine
 * domain finding when some other capability proves the probe *did* talk to the
 * target — e.g. TCP answered while UDP was blocked, or an authoritative response
 * was observed.
 */
function probeEstablishedContact(evidence: AuthoritativeDnsInfraEvidence): boolean {
	const r = evidence.reachability;
	if (r?.udp53Reachable === true || r?.tcp53Reachable === true) return true;
	if (r?.ipv4?.reachable === true || r?.ipv6?.reachable === true) return true;
	// Any conclusive authoritative-behaviour signal means we received a real answer.
	const a = evidence.authoritative;
	if (typeof a?.aaFlag === 'boolean') return true;
	if (typeof a?.recursionAvailable === 'boolean' || typeof a?.recursionRefused === 'boolean') return true;
	if (typeof evidence.soaSerial?.consistent === 'boolean') return true;
	if (typeof evidence.dnssec?.validates === 'boolean') return true;
	if (typeof evidence.dnssec?.dnskeyPresent === 'boolean') return true;
	return false;
}

/**
 * Probe `errors` reach client-visible finding text and metadata, so only a code-shaped
 * token is echoed — never free text from the other side of the service binding.
 */
export function isUnconfiguredLaneCode(code: unknown): code is string {
	return typeof code === 'string' && /^[a-z0-9_]{1,64}_not_configured$/.test(code);
}

/** Reported by the sidecar when its raw UDP/TCP DNS lane issued no query at all. */
const RAW_DNS_LANE_UNCONFIGURED = 'live_raw_dns_probe_not_configured';
/** Reported by the lane when no session answered at all — transient/environmental. */
const RAW_DNS_NO_CONTACT = 'raw_dns_probe_no_contact';
/** Reported by the lane when sessions answered but none proved authoritative (AA=1) for the
 * zone — usually DNS interception on the probe's network path, or a lame delegation. */
const RAW_DNS_NO_AUTHORITATIVE_ANSWER = 'raw_dns_probe_no_authoritative_answer';

/**
 * Drop every raw-DNS-lane claim from evidence whose own `errors` say that lane never ran.
 *
 * The sidecar answered root hostnames with `matchesOfficialHints: true`,
 * `ipv4Ipv6Parity: true` and `ptrRecords: [hostname]` — constants from its static hints
 * table, the PTR being the input echoed back — next to `live_raw_dns_probe_not_configured`.
 * Three capabilities "passed", `measuredNothing` stayed false, and the tool published
 * 100 / passed for a probe that issued no query (the #696 / #812 class). The sidecar
 * deploys separately from this Worker, so a stale one must not be able to do that: a
 * verdict — pass OR fail — from a lane that reports itself unconfigured is not a measurement.
 *
 * ⚠️ Scoped to the raw DNS lane. `routing`, `vantage` and the RIR/RDAP half of
 * `operationalExposure` come from other lanes and need no DNS contact; discarding them
 * would throw away genuinely measured critical findings.
 */
function withoutUnmeasuredRawDnsEvidence(evidence: AuthoritativeDnsInfraEvidence): AuthoritativeDnsInfraEvidence {
	if (!(evidence.errors ?? []).includes(RAW_DNS_LANE_UNCONFIGURED)) return evidence;
	const { hostname, checkedAt, routing, vantage, operationalExposure, errors } = evidence;
	const registry =
		operationalExposure?.rir !== undefined || operationalExposure?.rdapHandle !== undefined
			? { rir: operationalExposure.rir, rdapHandle: operationalExposure.rdapHandle }
			: undefined;
	return { hostname, checkedAt, routing, vantage, ...(registry ? { operationalExposure: registry } : {}), errors };
}

export function analyzeAuthoritativeDnsInfraEvidence(
	probeEvidence: AuthoritativeDnsInfraEvidence,
): AuthoritativeDnsInfraAnalysis {
	const evidence = withoutUnmeasuredRawDnsEvidence(probeEvidence);
	const findings: Finding[] = [];
	const capabilitySummary: InfraCapabilitySummary = { passed: [], failed: [], inconclusive: [] };

	const contactEstablished = probeEstablishedContact(evidence);

	// Demote a bare reachability=false to inconclusive when the probe never
	// established any contact — that is a probe/vantage artefact, not a
	// domain-side service failure. Keep it as a HIGH finding only when contact
	// was proven another way (e.g. TCP answered but UDP was blocked).
	const udpStatus = reachabilityStatus(evidence);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'dns53_udp_reachability',
		udpStatus === false && !contactEstablished ? undefined : udpStatus,
		{
			title: 'UDP/53 is not reachable',
			severity: 'high',
			detail: `The infra probe could not reach UDP/53 for ${evidence.hostname}.`,
		},
	);
	const tcpStatus: CapabilityStatus = evidence.reachability?.tcp53Reachable;
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'dns53_tcp_reachability',
		tcpStatus === false && !contactEstablished ? undefined : tcpStatus,
		{
			title: 'TCP/53 is not reachable',
			severity: 'high',
			detail: `The infra probe could not reach TCP/53 for ${evidence.hostname}.`,
		},
	);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'authoritative_aa_flag',
		evidence.authoritative?.aaFlag,
		{
			title: 'Authoritative AA flag missing',
			severity: 'critical',
			detail: `Authoritative responses for ${evidence.hostname} did not set the AA flag.`,
			metadata: { missingControl: true },
		},
	);
	pushCapabilityResult(capabilitySummary, findings, 'recursion_ra_refused', recursionRefusedStatus(evidence), {
		title: 'Recursive service exposed',
		severity: 'critical',
		detail: `The authoritative endpoint for ${evidence.hostname} appears to expose recursion.`,
		metadata: { missingControl: true },
	});
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'root_priming_ns_set',
		evidence.rootPriming?.matchesOfficialHints,
		{
			title: 'Root priming set mismatch',
			severity: 'critical',
			detail: `Root priming from ${evidence.hostname} did not match the official root-hints set.`,
			metadata: { missingControl: true },
		},
	);
	pushCapabilityResult(capabilitySummary, findings, 'soa_serial_consistency', evidence.soaSerial?.consistent, {
		title: 'SOA serials are inconsistent',
		severity: 'medium',
		detail: `The infra probe observed inconsistent SOA serials for ${evidence.hostname}.`,
	});
	pushCapabilityResult(capabilitySummary, findings, 'direct_dnssec_dnskey_ds_rrsig', directDnssecStatus(evidence), {
		title: 'Direct DNSSEC evidence missing',
		severity: 'high',
		detail: `Direct DNSSEC probes for ${evidence.hostname} did not confirm DNSKEY, DS, and RRSIG coverage.`,
	});
	pushCapabilityResult(capabilitySummary, findings, 'edns0_large_response', largeResponseStatus(evidence), {
		title: 'EDNS0 large response handling failed',
		severity: 'medium',
		detail: `The infra probe did not confirm EDNS0 large-response handling for ${evidence.hostname}.`,
	});
	pushCapabilityResult(capabilitySummary, findings, 'truncation_and_tcp_fallback', tcpFallbackStatus(evidence), {
		title: 'TCP fallback handling failed',
		severity: 'medium',
		detail: `The infra probe did not confirm truncation and TCP fallback for ${evidence.hostname}.`,
	});
	pushCapabilityResult(capabilitySummary, findings, 'zone_transfer_refusal', zoneTransferRefusedStatus(evidence), {
		title: 'Zone transfer is not refused',
		severity: 'critical',
		detail: `The authoritative endpoint for ${evidence.hostname} did not refuse every zone-transfer probe.`,
		metadata: { missingControl: true },
	});
	pushCapabilityResult(capabilitySummary, findings, 'amplification_ratio', amplificationStatus(evidence), {
		title: 'DNS amplification risk detected',
		severity: 'high',
		detail: `The infra probe observed risky response amplification for ${evidence.hostname}.`,
	});
	pushCapabilityResult(capabilitySummary, findings, 'dns_cookies_or_rrl', abuseResistanceStatus(evidence), {
		title: 'DNS abuse resistance not observed',
		severity: 'medium',
		detail: `The infra probe did not observe DNS Cookies or response-rate limiting for ${evidence.hostname}.`,
	});
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'ipv4_ipv6_parity',
		evidence.transportParity?.ipv4Ipv6Parity,
		{
			title: 'IPv4/IPv6 parity mismatch',
			severity: 'medium',
			detail: `The infra probe observed different IPv4 and IPv6 behavior for ${evidence.hostname}.`,
		},
	);
	pushCapabilityResult(capabilitySummary, findings, 'bgp_origin_asn', bgpOriginStatus(evidence), {
		title: 'BGP origin ASN mismatch',
		severity: 'medium',
		detail: `The observed origin ASN set for ${evidence.hostname} did not match expected origins.`,
	});
	pushCapabilityResult(capabilitySummary, findings, 'rpki_roa_validity', rpkiStatus(evidence), {
		title: 'RPKI origin validation failed',
		severity: 'high',
		detail: `RPKI validation for ${evidence.hostname} was invalid or missing.`,
	});
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'anycast_path_diversity',
		evidence.routing?.anycastPaths ? evidence.routing.anycastPaths.length >= 2 : undefined,
		{
			title: 'Anycast path diversity is low',
			severity: 'medium',
			detail: `The infra probe observed fewer than two anycast paths for ${evidence.hostname}.`,
		},
	);
	pushCapabilityResult(capabilitySummary, findings, 'vantage_latency_jitter_loss', vantageStatus(evidence), {
		title: 'Vantage-point quality degraded',
		severity: 'low',
		detail: `The infra probe observed high latency or packet loss for ${evidence.hostname}.`,
	});
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'route_leak_hijack_alerts',
		evidence.routing?.routeLeakOrHijackSignals
			? evidence.routing.routeLeakOrHijackSignals.length === 0
			: undefined,
		{
			title: 'Route leak or hijack signal observed',
			severity: 'critical',
			detail: `Route monitoring reported leak or hijack signals for ${evidence.hostname}.`,
			metadata: {
				missingControl: true,
				signals: evidence.routing?.routeLeakOrHijackSignals,
			},
		},
	);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'prefix_rir_rdap',
		Boolean(evidence.operationalExposure?.rir || evidence.operationalExposure?.rdapHandle) || undefined,
		{
			title: 'Prefix registry evidence missing',
			severity: 'low',
			detail: `The infra probe did not return RIR/RDAP prefix evidence for ${evidence.hostname}.`,
		},
	);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'chaos_id_version_behavior',
		Boolean(evidence.operationalExposure?.chaosId || evidence.operationalExposure?.chaosVersion) || undefined,
		{
			title: 'CHAOS identity/version behavior not observed',
			severity: 'low',
			detail: `The infra probe did not return CHAOS identity or version behavior for ${evidence.hostname}.`,
		},
	);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'unsupported_query_refusal',
		evidence.operationalExposure?.unsupportedQueriesRefused,
		{
			title: 'Unsupported query refusal missing',
			severity: 'medium',
			detail: `The authoritative endpoint for ${evidence.hostname} did not refuse unsupported query probes.`,
		},
	);
	pushCapabilityResult(
		capabilitySummary,
		findings,
		'ptr_reverse_dns_consistency',
		evidence.operationalExposure?.ptrRecords
			? evidence.operationalExposure.ptrRecords.length > 0
			: undefined,
		{
			title: 'PTR reverse DNS evidence missing',
			severity: 'low',
			detail: `The infra probe did not return PTR reverse DNS evidence for ${evidence.hostname}.`,
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
		// this same `capabilitySummary` (`checkStatus: 'error'`, `passed: false`,
		// `score: 0` — see `checkAuthoritativeDnsInfra`'s `measuredNothing`) (#812,
		// split from #786). Gate the affirmative finding on at least one CONCLUSIVE
		// (passed) capability, and tell the truth otherwise.
		if (capabilitySummary.passed.length > 0) {
			findings.push(
				createFinding(
					CATEGORY,
					'Authoritative DNS infrastructure checks passed',
					'info',
					`Infra probe evidence for ${evidence.hostname} satisfied all conclusive capability checks.`,
					{ evidenceMode: 'infra_probe' },
				),
			);
		} else {
			// #1054: "did not yield any conclusive capability checks" reads as a transient
			// failure and invites a pointless retry. When the probe TOLD us why, say so.
			// A PROVISIONING state (`*_not_configured`) cannot change on retry; a NO-CONTACT /
			// NO-AUTHORITATIVE-ANSWER abstention is transient and environmental (a dropped
			// connection, or a middlebox intercepting TCP/53) and IS worth retrying, so it must
			// never carry `unprovisioned: true`.
			const unconfigured = (evidence.errors ?? []).filter(isUnconfiguredLaneCode);
			const errors = evidence.errors ?? [];
			const noAuthoritativeAnswer = errors.includes(RAW_DNS_NO_AUTHORITATIVE_ANSWER);
			const noContact = errors.includes(RAW_DNS_NO_CONTACT);
			let detail: string;
			if (unconfigured.length > 0) {
				detail = `The infra probe's raw DNS lane is not provisioned for hostname targets in this deployment (${unconfigured.join(', ')}), so no capability check for ${evidence.hostname} could be verified either way. This is a provisioning state, not a transient failure — retrying returns the same result.`;
			} else if (noAuthoritativeAnswer) {
				detail = `The infra probe received responses from ${evidence.hostname}'s nameservers, but none was authoritative (AA=1) for the zone, which usually means DNS interception on the probe's network path or a lame delegation. This is transient and environmental, not a provisioning state — retrying, or a different vantage, may succeed.`;
			} else if (noContact) {
				detail = `The infra probe could not establish contact with any nameserver for ${evidence.hostname}. This is transient and environmental, not a provisioning state — retrying may succeed.`;
			} else {
				detail = `Infra probe evidence for ${evidence.hostname} did not yield any conclusive capability checks; nothing was verified.`;
			}
			findings.push(
				createFinding(CATEGORY, 'Authoritative DNS infrastructure checks inconclusive', 'info', detail, {
					evidenceMode: 'infra_probe',
					inconclusive: true,
					...(unconfigured.length > 0 ? { unprovisioned: true, probeErrors: unconfigured } : {}),
				}),
			);
		}
	}

	return { findings, capabilitySummary };
}
