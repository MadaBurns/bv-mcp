// SPDX-License-Identifier: BUSL-1.1

import type { Finding } from '../lib/scoring';
import { createFinding } from '../lib/scoring';

/**
 * Common SRV service prefixes to probe during a domain service discovery audit.
 * Covers email, autodiscovery, calendar, messaging, and web/infra services.
 */
export const SRV_PREFIXES = [
	// Email
	'_submission._tcp', // SMTP submission (587)
	'_imap._tcp', // IMAP plain (143)
	'_imaps._tcp', // IMAP TLS (993)
	'_pop3._tcp', // POP3 plain (110)
	'_pop3s._tcp', // POP3 TLS (995)
	// Autodiscovery
	'_autodiscover._tcp', // Exchange/Outlook autodiscover
	'_carddav._tcp', // CardDAV
	'_carddavs._tcp', // CardDAV TLS
	'_caldav._tcp', // CalDAV
	'_caldavs._tcp', // CalDAV TLS
	// Communication
	'_sip._tcp', // SIP
	'_sip._udp', // SIP UDP
	'_xmpp-client._tcp', // XMPP client
	'_xmpp-server._tcp', // XMPP server
	// Web/Infra
	'_http._tcp', // HTTP
	'_https._tcp', // HTTPS
] as const;

/** Result of probing a single SRV prefix for a domain. */
export interface SrvProbeResult {
	prefix: string;
	records: Array<{ priority: number; weight: number; port: number; target: string }>;
}

/** Insecure protocol pairs: plain-text prefix → encrypted counterpart */
const INSECURE_PAIRS: Array<{ plain: string; encrypted: string; protocol: string }> = [
	{ plain: '_imap._tcp', encrypted: '_imaps._tcp', protocol: 'IMAP' },
	{ plain: '_pop3._tcp', encrypted: '_pop3s._tcp', protocol: 'POP3' },
];

/**
 * Analyze SRV probe results and generate findings.
 *
 * Identifies discovered services, flags insecure protocol exposure
 * (plain-text without encrypted variant), and reports infrastructure exposure.
 *
 * @param results - Array of SRV probe results (may include empty records)
 * @returns Array of findings for the srv category
 */
export function analyzeSrvResults(results: SrvProbeResult[]): Finding[] {
	const findings: Finding[] = [];
	const discovered = results.filter((r) => r.records.length > 0);

	if (discovered.length === 0) {
		findings.push(createFinding('srv', 'No SRV service records found', 'info', 'No SRV service discovery records were found for this domain.'));
		return findings;
	}

	// Report each discovered service
	for (const service of discovered) {
		const firstRecord = service.records[0];
		findings.push(
			createFinding('srv', `SRV service discovered: ${service.prefix}`, 'info', `SRV record found for ${service.prefix} pointing to ${firstRecord.target}:${firstRecord.port}.`, {
				prefix: service.prefix,
				port: firstRecord.port,
				target: firstRecord.target,
			}),
		);
	}

	// Build a set of discovered prefixes for quick lookup
	const discoveredPrefixes = new Set(discovered.map((r) => r.prefix));

	// Check for insecure protocol exposure
	for (const pair of INSECURE_PAIRS) {
		if (discoveredPrefixes.has(pair.plain) && !discoveredPrefixes.has(pair.encrypted)) {
			findings.push(
				createFinding(
					'srv',
					`Plain-text ${pair.protocol} advertised without encrypted variant`,
					'medium',
					`${pair.plain} SRV record exists but ${pair.encrypted} does not. Clients may connect over unencrypted ${pair.protocol}, exposing credentials and message content.`,
				),
			);
		}
	}

	// Autodiscover exposure
	if (discoveredPrefixes.has('_autodiscover._tcp')) {
		findings.push(
			createFinding('srv', 'Autodiscover SRV record exposed', 'low', 'The _autodiscover._tcp SRV record reveals mail server infrastructure details to external observers.'),
		);
	}

	// SIP/XMPP services
	const commPrefixes = ['_sip._tcp', '_sip._udp', '_xmpp-client._tcp', '_xmpp-server._tcp'];
	const activeComm = commPrefixes.filter((p) => discoveredPrefixes.has(p));
	if (activeComm.length > 0) {
		findings.push(
			createFinding('srv', 'SIP/XMPP services publicly advertised', 'info', `Communication services advertised via SRV: ${activeComm.join(', ')}.`),
		);
	}

	// Summary finding
	const allPrefixes = discovered.map((r) => r.prefix);
	findings.push(
		createFinding('srv', `Service footprint: ${discovered.length} services discovered via SRV`, 'info', `SRV service discovery audit found ${discovered.length} active service(s): ${allPrefixes.join(', ')}.`, {
			serviceCount: discovered.length,
			prefixes: allPrefixes,
		}),
	);

	return findings;
}
