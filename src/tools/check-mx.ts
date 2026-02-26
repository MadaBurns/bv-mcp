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
	if (!validation.valid) {
		return buildCheckResult('MX', 'fail', [
			createFinding('fail', 'MX', 'Domain validation failed', validation.error || 'Invalid domain')
		]);
	}

	const answers = await queryDnsRecords(domain, 'MX');
	if (!answers || answers.length === 0) {
		return buildCheckResult('MX', 'fail', [
			createFinding('fail', 'MX', 'No MX records found', 'Domain does not accept email')
		]);
	}

	const findings = [];
	findings.push(createFinding('pass', 'MX', 'MX records found', `MX records: ${answers.map(a => a.data).join(', ')}`));

	// Heuristic: If MX points to common outbound providers, flag as likely outbound
	const outboundProviders = ['google.com', 'outlook.com', 'mailgun.org', 'sendgrid.net', 'amazonses.com'];
	const mxTargets = answers.map(a => a.data.split(' ').pop() || '').map(t => t.toLowerCase());
	const outbound = mxTargets.some(t => outboundProviders.some(p => t.endsWith(p)));
	if (outbound) {
		findings.push(createFinding('info', 'MX', 'Likely outbound email usage', 'MX points to known outbound provider'));
	}

	return buildCheckResult('MX', 'pass', findings);
}
