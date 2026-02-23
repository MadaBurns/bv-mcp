/**
 * Explain Finding tool.
 * Provides static explanations for DNS security findings.
 * No AI binding required - uses a built-in knowledge base.
 */

export interface ExplanationResult {
	checkType: string;
	status: string;
	details?: string;
	title: string;
	severity: string;
	explanation: string;
	recommendation: string;
	references: string[];
}

type ExplanationEntry = Omit<ExplanationResult, 'checkType' | 'status' | 'details'>;

const EXPLANATIONS: Record<string, ExplanationEntry> = {
	SPF_PASS: {
		title: 'SPF Validated',
		severity: 'pass',
		explanation:
			'SPF (Sender Policy Framework) is properly configured. The domain specifies which mail servers are authorized to send email on its behalf.',
		recommendation: 'Maintain your current SPF configuration. Ensure you update it when adding new email sending sources.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
	},
	SPF_FAIL: {
		title: 'SPF Validation Failed',
		severity: 'fail',
		explanation: 'SPF validation failed - emails from this domain are being rejected because the sending server is not authorized.',
		recommendation:
			'Review your SPF record and ensure all legitimate email sources are included. Common issue: using -all but missing include statements.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208', 'https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/'],
	},
	SPF_WARNING: {
		title: 'SPF Soft Fail',
		severity: 'warning',
		explanation: 'SPF uses a soft fail (~all) policy. Emails that fail SPF will be accepted but may be flagged as suspicious.',
		recommendation: 'Upgrade to hard fail (-all) after verifying all legitimate sources are in your SPF record.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-8.1'],
	},
	SPF_MISSING: {
		title: 'No SPF Record Found',
		severity: 'fail',
		explanation:
			'SPF (Sender Policy Framework) is a DNS TXT record that specifies which mail servers are authorized to send email on behalf of your domain. Without SPF, any server can send email pretending to be from your domain.',
		recommendation: "Add a TXT record to your domain's DNS with a valid SPF policy. Start with: v=spf1 include:<your-email-provider> -all",
		references: ['https://datatracker.ietf.org/doc/html/rfc7208', 'https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/'],
	},
	DMARC_PASS: {
		title: 'DMARC Policy Validated',
		severity: 'pass',
		explanation:
			'DMARC (Domain-based Message Authentication, Reporting & Conformance) is properly configured with a policy that provides protection against email spoofing.',
		recommendation:
			'Monitor your DMARC reports to ensure legitimate email is not being blocked. Consider enabling reject policy for stronger protection.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489'],
	},
	DMARC_FAIL: {
		title: 'No DMARC Record Found',
		severity: 'fail',
		explanation:
			'DMARC builds on SPF and DKIM to provide email authentication policy. Without DMARC, receivers have no policy guidance for handling authentication failures.',
		recommendation: 'Add a TXT record at _dmarc.<domain> with at minimum: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489', 'https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/'],
	},
	DMARC_WARNING: {
		title: 'DMARC Policy Not Enforcing',
		severity: 'warning',
		explanation: "DMARC policy is set to 'none' (monitoring only) or 'quarantine'. This provides limited protection against spoofing.",
		recommendation: "After reviewing DMARC reports, upgrade the policy to 'reject' to actively protect against email spoofing.",
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DKIM_PASS: {
		title: 'DKIM Validated',
		severity: 'pass',
		explanation:
			'DKIM (DomainKeys Identified Mail) is properly configured. Outgoing emails are digitally signed and can be verified by receivers.',
		recommendation: 'Maintain your DKIM configuration. Rotate keys periodically as per your security policy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376'],
	},
	DKIM_FAIL: {
		title: 'No DKIM Records Found',
		severity: 'fail',
		explanation:
			"DKIM adds a digital signature to outgoing emails, allowing receivers to verify the email was sent by an authorized server and wasn't modified in transit.",
		recommendation: 'Configure DKIM signing with your email provider. They will provide the DKIM DNS records to publish.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376', 'https://www.cloudflare.com/learning/dns/dns-records/dns-dkim-record/'],
	},
	DNSSEC_PASS: {
		title: 'DNSSEC Enabled',
		severity: 'pass',
		explanation:
			'DNSSEC is properly configured with valid cryptographic signatures. This protects against DNS spoofing and cache poisoning attacks.',
		recommendation: 'Maintain your DNSSEC configuration. Monitor for any validation failures in your logs.',
		references: ['https://datatracker.ietf.org/doc/html/rfc4033'],
	},
	DNSSEC_FAIL: {
		title: 'DNSSEC Not Validated',
		severity: 'fail',
		explanation:
			"DNSSEC adds cryptographic signatures to DNS records, preventing DNS spoofing and cache poisoning attacks. Without DNSSEC, attackers can redirect your domain's traffic.",
		recommendation: 'Enable DNSSEC through your domain registrar and DNS provider. Most providers offer one-click DNSSEC activation.',
		references: ['https://datatracker.ietf.org/doc/html/rfc4033', 'https://www.cloudflare.com/dns/dnssec/how-dnssec-works/'],
	},
	SSL_PASS: {
		title: 'SSL/TLS Validated',
		severity: 'pass',
		explanation: 'The domain properly serves content over HTTPS with a valid certificate.',
		recommendation: 'Maintain your SSL certificate. Consider implementing HSTS for additional security.',
		references: ['https://https.cio.gov/hsts/'],
	},
	SSL_FAIL: {
		title: 'HTTPS Not Available',
		severity: 'fail',
		explanation:
			'The domain does not have a valid SSL/TLS certificate or the HTTPS server is not responding. This means traffic to the domain is not encrypted.',
		recommendation: "Install a valid SSL/TLS certificate. Free certificates are available from Let's Encrypt or Cloudflare.",
		references: ['https://letsencrypt.org/', 'https://www.cloudflare.com/ssl/'],
	},
	SSL_WARNING: {
		title: 'Mixed Content or Redirect Issues',
		severity: 'warning',
		explanation: 'HTTPS is available but there may be issues with redirects or mixed content.',
		recommendation: 'Ensure all resources load over HTTPS and implement proper redirects from HTTP to HTTPS.',
		references: ['https://www.cloudflare.com/ssl/'],
	},
	MTA_STS_PASS: {
		title: 'MTA-STS Enabled',
		severity: 'pass',
		explanation: 'MTA-STS (Mail Transfer Agent Strict Transport Security) is properly configured and enforces TLS for incoming email.',
		recommendation: 'Monitor your MTA-STS reports to ensure legitimate mail servers can deliver successfully.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	MTA_STS_FAIL: {
		title: 'No MTA-STS Record Found',
		severity: 'fail',
		explanation:
			'MTA-STS enforces TLS encryption for incoming email, preventing downgrade attacks where an attacker forces email to be sent unencrypted.',
		recommendation:
			'Publish an MTA-STS TXT record at _mta-sts.<domain> and host a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	MTA_STS_WARNING: {
		title: 'MTA-STS in Testing Mode',
		severity: 'warning',
		explanation: 'MTA-STS is configured but in testing mode (mode=testing) rather than enforcement mode.',
		recommendation: 'After verifying all mail servers can successfully deliver over TLS, upgrade to mode=enforce.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
};

const DEFAULT_EXPLANATION: ExplanationEntry = {
	title: 'Security Check Complete',
	severity: 'info',
	explanation: "This check has been completed. Review the findings above for details on your domain's security posture.",
	recommendation: 'Refer to the specific check documentation for detailed remediation steps.',
	references: ['https://www.cloudflare.com/learning/dns/what-is-dns/'],
};

const CHECK_TYPE_MAPPING: Record<string, string> = {
	SPF: 'SPF',
	DMARC: 'DMARC',
	DKIM: 'DKIM',
	DNSSEC: 'DNSSEC',
	SSL: 'SSL',
	MTA_STS: 'MTA_STS',
	NS: 'NS',
	CAA: 'CAA',
};

export function explainFinding(checkType: string, status: string, details?: string): ExplanationResult {
	const normalizedType = CHECK_TYPE_MAPPING[checkType.toUpperCase()] || checkType.toUpperCase();
	const key = `${normalizedType}_${status.toUpperCase()}`;

	const entry = EXPLANATIONS[key] ?? DEFAULT_EXPLANATION;

	return {
		checkType: normalizedType,
		status,
		details,
		...entry,
	};
}

export function formatExplanation(result: ExplanationResult): string {
	const lines = [`## ${result.title}`, `**Check Type:** ${result.checkType} | **Status:** ${result.status}`, ''];

	if (result.details) {
		lines.push(`**Details:** ${result.details}`, '');
	}

	lines.push(
		`### What this means`,
		result.explanation,
		'',
		`### Recommendation`,
		result.recommendation,
		'',
		`### References`,
		...result.references.map((r) => `- ${r}`),
	);
	return lines.join('\n');
}
