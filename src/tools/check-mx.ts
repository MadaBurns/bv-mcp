/**
 * MX record check tool for MCP server.
 * Validates presence and quality of MX records for a domain.
 * Returns CheckResult with findings and outbound email usage assessment.
 */
import type { CheckResult, Finding } from '../lib/scoring';
import { createFinding, buildCheckResult } from '../lib/scoring';
import { queryDnsRecords } from '../lib/dns';

export async function checkMx(domain: string): Promise<CheckResult> {
	let answers;
	try {
		answers = await queryDnsRecords(domain, 'MX');
	} catch {
		return buildCheckResult('mx', [createFinding('mx', 'DNS query failed', 'high', 'MX record lookup failed')]);
	}

	if (!answers || answers.length === 0) {
		return buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'high', 'No mail exchange records present')]);
	}

	const findings: Finding[] = [];
	findings.push(createFinding('mx', 'MX records found', 'info', 'Mail exchange records present'));

	const outboundProviders = ['google.com', 'outlook.com', 'mailgun.org', 'sendgrid.net', 'amazonses.com'];
	const mxTargets = answers.map((a) => a.split(' ').pop() || '').map((t) => t.replace(/\.$/, '').toLowerCase());
	const outbound = mxTargets.some((t) => outboundProviders.some((p) => t.endsWith(p)));
	if (outbound) {
		findings.push(createFinding('mx', 'Likely outbound email usage', 'info', 'MX points to known outbound provider'));
	}

	return buildCheckResult('mx', findings);
}
