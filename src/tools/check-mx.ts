/**
 * MX record check tool for MCP server.
 * Validates presence and quality of MX records for a domain.
 * Returns CheckResult with findings including RFC compliance, redundancy, and provider detection.
 */
import type { CheckResult, Finding } from '../lib/scoring';
import { createFinding, buildCheckResult } from '../lib/scoring';
import { queryDnsRecords } from '../lib/dns';

/** Check MX record configuration for a domain */
export async function checkMx(domain: string): Promise<CheckResult> {
	let answers;
	try {
		answers = await queryDnsRecords(domain, 'MX');
	} catch {
		return buildCheckResult('mx', [createFinding('mx', 'DNS query failed', 'high', 'MX record lookup failed')]);
	}

	if (!answers || answers.length === 0) {
		return buildCheckResult('mx', [
			createFinding(
				'mx',
				'No MX records found',
				'medium',
				'No mail exchange records present. If this domain does not handle email, consider publishing a null MX record (RFC 7505).',
			),
		]);
	}

	const findings: Finding[] = [];

	// Parse MX records into priority + exchange pairs
	const mxRecords = answers.map((a) => {
		const parts = a.split(' ');
		const priority = parseInt(parts[0], 10);
		const exchange = (parts.slice(1).join(' ') || '').replace(/\.$/, '').toLowerCase();
		return { priority, exchange, raw: a };
	});

	// Check for null MX (RFC 7505: priority 0, exchange ".")
	const nullMx = mxRecords.find((r) => r.exchange === '' || r.exchange === '.');
	if (nullMx) {
		findings.push(
			createFinding('mx', 'Null MX record (RFC 7505)', 'info', 'Domain explicitly declares it does not accept email via null MX record.'),
		);
		return buildCheckResult('mx', findings);
	}

	findings.push(createFinding('mx', 'MX records found', 'info', `${mxRecords.length} mail exchange record(s) present.`));

	// Check for MX pointing to IP address (invalid per RFC 5321 §5.1)
	const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
	for (const mx of mxRecords) {
		if (ipPattern.test(mx.exchange)) {
			findings.push(
				createFinding(
					'mx',
					'MX points to IP address',
					'high',
					`MX record "${mx.raw}" points to an IP address. MX targets must be hostnames per RFC 5321.`,
				),
			);
		}
	}

	// Check for single MX (no redundancy)
	if (mxRecords.length === 1) {
		findings.push(createFinding('mx', 'Single MX record', 'low', 'Only one MX record found. Consider adding a backup MX for redundancy.'));
	}

	// Check for duplicate priorities
	const priorities = mxRecords.map((r) => r.priority);
	const uniquePriorities = new Set(priorities);
	if (uniquePriorities.size < priorities.length && mxRecords.length > 1) {
		findings.push(
			createFinding(
				'mx',
				'Duplicate MX priorities',
				'low',
				'Multiple MX records share the same priority. This provides round-robin load balancing but no clear failover order.',
			),
		);
	}

	// Detect known outbound email providers
	const outboundProviders = [
		'google.com',
		'googlemail.com',
		'outlook.com',
		'mailgun.org',
		'sendgrid.net',
		'amazonses.com',
		'pphosted.com',
		'mimecast.com',
	];
	const mxTargets = mxRecords.map((r) => r.exchange);
	const outbound = mxTargets.some((t) => outboundProviders.some((p) => t.endsWith(p)));
	if (outbound) {
		findings.push(createFinding('mx', 'Managed email provider detected', 'info', 'MX points to a known managed email provider.'));
	}

	return buildCheckResult('mx', findings);
}
