/**
 * MX record check tool for MCP server.
 * Validates presence and quality of MX records for a domain.
 * Returns CheckResult with findings and outbound email usage assessment.
 */
import type { CheckResult } from '../lib/scoring';
import { createFinding, buildCheckResult } from '../lib/scoring';
import { validateDomain } from '../lib/sanitize';
import { queryDnsRecords } from '../lib/dns';

export async function checkMx(domain: string): Promise<CheckResult> {
	const validation = validateDomain(domain);
	if (!validation.valid) return buildCheckResult(domain, 'MX', [createFinding('fail', 'MX', 'Domain validation failed', 'Invalid domain')]);
	let answers;
	try {
		answers = await queryDnsRecords(domain, 'MX');
	} catch (err) {
		return buildCheckResult(domain, 'MX', [createFinding('fail', 'MX', 'DNS query failed', 'MX record lookup failed', 'high')]);
	}
	if (!answers || answers.length === 0) {
		return buildCheckResult(domain, 'MX', [createFinding('fail', 'MX', 'No MX records found', 'No mail exchange records present', 'high')]);
	}
	const findings = [];
	findings.push(createFinding('pass', 'MX', 'MX records found', 'Mail exchange records present', 'low'));
	const outboundProviders = ['google.com', 'outlook.com', 'mailgun.org', 'sendgrid.net', 'amazonses.com'];
	const mxTargets = answers.map(a => a.data.split(' ').pop() || '').map(t => t.toLowerCase());
	const outbound = mxTargets.some(t => outboundProviders.some(p => t.endsWith(p)));
	if (outbound) {
		findings.push(createFinding('info', 'MX', 'Likely outbound email usage', 'MX points to known outbound provider'));
	}
	return buildCheckResult(domain, 'MX', findings);
}
