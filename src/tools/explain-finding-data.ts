export interface ExplanationTemplate {
	title: string;
	severity: string;
	explanation: string;
	impact?: string;
	adverseConsequences?: string;
	recommendation: string;
	references: string[];
}

export interface ImpactNarrative {
	impact?: string;
	adverseConsequences?: string;
}

export interface SpecificImpactRule extends ImpactNarrative {
	checkType?: string;
	titleIncludes?: string[];
	detailIncludes?: string[];
}

export const EXPLANATIONS: Record<string, ExplanationTemplate> = {
	SUBDOMAIN_TAKEOVER_CRITICAL: {
		title: 'Dangling CNAME — Subdomain Takeover Risk',
		severity: 'critical',
		explanation:
			'A subdomain points to a third-party service (e.g., CloudFront, Heroku) that does not resolve. This is a potential subdomain takeover vector, allowing attackers to claim the orphaned resource and control the subdomain.',
		impact: 'Attackers may host malicious content or capture traffic on a trusted subdomain, enabling phishing and session abuse.',
		adverseConsequences:
			'Brand trust can be damaged, users can be redirected to attacker infrastructure, and incident response costs can increase.',
		recommendation: 'Remove or update the CNAME record to point to a valid, owned resource. Regularly audit DNS for orphaned records.',
		references: [
			'https://github.com/EdOverflow/can-i-take-over-xyz',
			'https://www.hackerone.com/blog/Guide-Subdomain-Takeover',
			'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html',
		],
	},
	SUBDOMAIN_TAKEOVER_HIGH: {
		title: 'CNAME Resolution Failed — Manual Review Needed',
		severity: 'high',
		explanation:
			'A subdomain CNAME points to a third-party service but the target could not be resolved. This may indicate a takeover risk or DNS misconfiguration.',
		impact: 'If the target is orphaned, an attacker may be able to claim it and gain control of the affected subdomain.',
		adverseConsequences: 'Users may be exposed to fraudulent pages and the organization may face reputation damage until DNS is remediated.',
		recommendation: 'Manually review the CNAME target and remove or update if orphaned. Use DNS monitoring tools for ongoing checks.',
		references: [
			'https://github.com/EdOverflow/can-i-take-over-xyz',
			'https://www.hackerone.com/blog/Guide-Subdomain-Takeover',
		],
	},
	SUBDOMAIN_TAKEOVER_INFO: {
		title: 'No Dangling CNAME Records Found',
		severity: 'info',
		explanation: 'No subdomain takeover vectors detected among known/active subdomains. DNS configuration is secure for this check.',
		recommendation: 'Continue regular DNS audits and monitoring for new subdomains or changes.',
		references: ['https://github.com/EdOverflow/can-i-take-over-xyz'],
	},
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
		impact: 'Email authentication becomes unreliable, and spoofed or misrouted messages may evade expected controls.',
		adverseConsequences:
			'Legitimate email delivery can degrade, while impersonation attempts can increase helpdesk and abuse handling load.',
		recommendation:
			'Review your SPF record and ensure all legitimate email sources are included. Common issue: using -all but missing include statements.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208', 'https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/'],
	},
	SPF_WARNING: {
		title: 'SPF Soft Fail',
		severity: 'warning',
		explanation: 'SPF uses a soft fail (~all) policy. Emails that fail SPF will be accepted but may be flagged as suspicious. However, when DMARC enforcement (p=reject or p=quarantine) is active, ~all is the recommended setting because it allows DMARC to verify DKIM before making a reject decision.',
		impact: 'Without DMARC enforcement, failing SPF messages are often still accepted, so spoofed mail may continue reaching recipients. With DMARC enforcement, this is a non-issue.',
		adverseConsequences: 'Without DMARC, phishing risk remains elevated. With DMARC enforcement active, ~all is correct and -all could cause premature rejection before DKIM verification.',
		recommendation: 'If DMARC is configured with p=reject or p=quarantine, keep ~all — it is the recommended setting. Otherwise, upgrade to hard fail (-all) after verifying all legitimate sources are in your SPF record.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-8.1', 'https://www.mailhardener.com/kb/spf'],
	},
	SPF_MISSING: {
		title: 'No SPF Record Found',
		severity: 'fail',
		explanation:
			'SPF (Sender Policy Framework) is a DNS TXT record that specifies which mail servers are authorized to send email on behalf of your domain. Without SPF, any server can send email pretending to be from your domain.',
		impact: 'Any internet host can attempt to send email as your domain, making sender impersonation significantly easier.',
		adverseConsequences: 'Spoofing and phishing campaigns can harm brand trust, increase abuse complaints, and impair deliverability.',
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
		impact: 'Receiving systems cannot consistently quarantine or reject forged messages that fail authentication.',
		adverseConsequences: 'Domain spoofing can reach inboxes more often, increasing phishing exposure and reputational damage.',
		recommendation: 'Add a TXT record at _dmarc.<domain> with at minimum: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489', 'https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/'],
	},
	DMARC_WARNING: {
		title: 'DMARC Policy Not Enforcing',
		severity: 'warning',
		explanation: "DMARC policy is set to 'none' (monitoring only) or 'quarantine'. This provides limited protection against spoofing.",
		impact: 'Authentication failures may not be fully blocked, allowing some malicious mail to be delivered.',
		adverseConsequences: 'Attackers can still impersonate the domain in recipient inboxes, leading to fraud and support overhead.',
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
		impact: 'Receivers lose a key authenticity signal, which weakens anti-spoofing and anti-tampering protections.',
		adverseConsequences:
			'Legitimate email may be distrusted while fraudulent messages are harder to distinguish, hurting deliverability and trust.',
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
		impact: 'DNS responses can be forged in transit, enabling redirection to attacker-controlled infrastructure.',
		adverseConsequences: 'Users may be sent to malicious destinations, causing credential theft, service disruption, and incident response costs.',
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
		impact: 'Network attackers can intercept or tamper with data exchanged between users and the site.',
		adverseConsequences: 'Credentials and sensitive data may be exposed, and browser trust warnings can reduce conversion and user confidence.',
		recommendation: "Install a valid SSL/TLS certificate. Free certificates are available from Let's Encrypt or Cloudflare.",
		references: ['https://letsencrypt.org/', 'https://www.cloudflare.com/ssl/'],
	},
	SSL_WARNING: {
		title: 'Mixed Content or Redirect Issues',
		severity: 'warning',
		explanation: 'HTTPS is available but there may be issues with redirects or mixed content.',
		impact: 'Some resources may still load insecurely, creating opportunities for content manipulation or privacy leakage.',
		adverseConsequences: 'User sessions and page integrity can be weakened, and security posture may fail audit expectations.',
		recommendation: 'Ensure all resources load over HTTPS and implement proper redirects from HTTP to HTTPS.',
		references: ['https://www.cloudflare.com/ssl/'],
	},
	SSL_MEDIUM: {
		title: 'HSTS or Redirect Issues',
		severity: 'medium',
		explanation:
			'HTTPS is available but the domain is missing HSTS (Strict-Transport-Security) headers or does not redirect HTTP to HTTPS. Without HSTS, browsers may still attempt insecure connections.',
		impact: 'Clients may be downgraded to insecure HTTP connections, especially on first visit or hostile networks.',
		adverseConsequences: 'Session data can be exposed in transit and users remain vulnerable to downgrade or interception attacks.',
		recommendation:
			'Add a Strict-Transport-Security header with max-age of at least 1 year (31536000). Configure your web server to redirect all HTTP requests to HTTPS.',
		references: ['https://https.cio.gov/hsts/', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
	},
	SSL_LOW: {
		title: 'HSTS Configuration Suboptimal',
		severity: 'low',
		explanation:
			'HSTS is configured but could be improved. Common issues include a short max-age value or missing includeSubDomains directive.',
		impact: 'Partial HSTS coverage leaves windows where transport security guarantees are weaker than expected.',
		adverseConsequences: 'Subdomains or returning sessions may still face avoidable downgrade exposure and policy non-compliance findings.',
		recommendation:
			'Set max-age to at least 31536000 (1 year) and include the includeSubDomains directive. Consider adding your domain to the HSTS preload list.',
		references: [
			'https://hstspreload.org/',
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
		],
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
		impact: 'Inbound SMTP sessions are more susceptible to TLS downgrade and interception attempts.',
		adverseConsequences: 'Sensitive email content can be exposed in transit, raising confidentiality and compliance risks.',
		recommendation:
			'Publish an MTA-STS TXT record at _mta-sts.<domain> and host a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	MTA_STS_WARNING: {
		title: 'MTA-STS in Testing Mode',
		severity: 'warning',
		explanation: 'MTA-STS is configured but in testing mode (mode=testing) rather than enforcement mode.',
		impact: 'Delivery behavior is monitored but not enforced, so some insecure transport paths may still be accepted.',
		adverseConsequences: 'Security gaps can persist longer and confidentiality controls for inbound mail remain partially effective.',
		recommendation: 'After verifying all mail servers can successfully deliver over TLS, upgrade to mode=enforce.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	NS_PASS: {
		title: 'Nameservers Validated',
		severity: 'pass',
		explanation: 'The domain has properly configured nameservers that are responding to queries.',
		recommendation: 'Maintain your current nameserver configuration. Use at least two geographically distributed nameservers for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035'],
	},
	NS_FAIL: {
		title: 'Nameserver Issues Detected',
		severity: 'fail',
		explanation: 'One or more nameservers for this domain are not responding or are misconfigured, which can cause DNS resolution failures.',
		impact: 'Resolvers may fail to resolve the domain, degrading access to web, API, and mail services.',
		adverseConsequences: 'Users can experience outages, failed transactions, and business continuity disruptions.',
		recommendation: 'Verify all listed nameservers are operational and properly configured. Ensure NS records match those at the registrar.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035', 'https://www.cloudflare.com/learning/dns/dns-records/dns-ns-record/'],
	},
	NS_WARNING: {
		title: 'Nameserver Configuration Suboptimal',
		severity: 'warning',
		explanation: 'Nameservers are functional but the configuration could be improved for better reliability or security.',
		impact: 'Single points of failure or weak diversity can reduce DNS resilience during provider or network incidents.',
		adverseConsequences: 'Availability and latency can degrade under stress, increasing user-facing instability.',
		recommendation: 'Consider adding additional nameservers for redundancy and ensuring they are geographically distributed.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035'],
	},
	CAA_PASS: {
		title: 'CAA Records Configured',
		severity: 'pass',
		explanation: 'CAA (Certificate Authority Authorization) records are properly configured, restricting which CAs can issue certificates for this domain.',
		recommendation: 'Maintain your CAA records. Review periodically to ensure they reflect your current certificate issuance needs.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
	},
	CAA_FAIL: {
		title: 'No CAA Records Found',
		severity: 'fail',
		explanation: 'No CAA records are present for this domain. Without CAA, any certificate authority can issue certificates for your domain.',
		impact: 'Certificate issuance controls are broad, increasing the chance of unauthorized or misissued certificates.',
		adverseConsequences: 'Attackers may abuse misissuance for impersonation and interception, with trust and compliance implications.',
		recommendation: 'Add CAA DNS records to restrict certificate issuance to your authorized CAs (e.g., "0 issue letsencrypt.org").',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659', 'https://www.cloudflare.com/learning/dns/dns-records/dns-caa-record/'],
	},
	CAA_WARNING: {
		title: 'CAA Configuration Incomplete',
		severity: 'warning',
		explanation: 'CAA records exist but may not fully restrict certificate issuance. Consider adding iodef or wildcard policies.',
		impact: 'Incomplete CAA policy can leave gaps in issuance constraints for wildcard or incident-reporting scenarios.',
		adverseConsequences: 'Certificate governance may be weaker than intended, increasing operational and audit risk.',
		recommendation: 'Review your CAA records and add an iodef tag for incident reporting. Consider restricting wildcard certificate issuance separately.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
	},
	MX_PASS: {
		title: 'MX Records Validated',
		severity: 'pass',
		explanation: 'MX (Mail Exchange) records are properly configured, directing email to the correct mail servers.',
		recommendation: 'Maintain your MX records. Ensure backup MX entries exist for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_FAIL: {
		title: 'No MX Records Found',
		severity: 'fail',
		explanation: 'No MX records are present for this domain. Without MX records, email delivery to this domain will fail or fall back to A record delivery.',
		impact: 'Mail routing is unreliable or unavailable for intended recipients on this domain.',
		adverseConsequences: 'Inbound communications may be lost, causing business disruption and missed security notifications.',
		recommendation: 'Add MX records pointing to your mail server. If this domain does not handle email, consider adding a null MX record (0 .).',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321', 'https://datatracker.ietf.org/doc/html/rfc7505'],
	},
	MX_WARNING: {
		title: 'MX Configuration Suboptimal',
		severity: 'warning',
		explanation: 'MX records exist but the configuration could be improved, such as missing backup MX or unusual priority values.',
		impact: 'Mail delivery reliability is reduced during server failures or routing anomalies.',
		adverseConsequences: 'Message delays and intermittent delivery failures can affect operations and customer support.',
		recommendation: 'Review MX priorities and add at least one backup MX record for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_INFO: {
		title: 'MX Records Present',
		severity: 'info',
		explanation: 'Mail exchange records are properly configured for this domain.',
		recommendation: 'No action required. Ensure backup MX records exist for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_LOW: {
		title: 'MX Configuration Could Be Improved',
		severity: 'low',
		explanation: 'MX records are present but the configuration has minor issues such as missing backup MX records.',
		impact: 'Resilience to mail infrastructure outages is lower than recommended.',
		adverseConsequences: 'Short outages can become user-visible delivery delays and increase operational toil.',
		recommendation: 'Add at least one backup MX record with a different priority for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_HIGH: {
		title: 'MX Configuration Error',
		severity: 'medium',
		explanation:
			'MX records have a configuration error such as pointing to an IP address instead of a hostname (violating RFC 5321) or referencing a hostname that does not resolve to any address record.',
		impact: 'Standards-incompatible or unresolvable MX targets can cause mail rejection or routing failures across sending systems.',
		adverseConsequences: 'Business-critical messages may bounce, delaying incident response and external communication.',
		recommendation:
			'Update MX records to point to valid hostnames, not IP addresses. Ensure all MX targets resolve to valid A/AAAA records.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_MEDIUM: {
		title: 'No MX Records Found',
		severity: 'medium',
		explanation:
			'No MX records are present for this domain. Email delivery will fall back to A record delivery or fail entirely.',
		impact: 'Email reception may fail or behave inconsistently depending on sender fallback behavior.',
		adverseConsequences: 'Organizations may miss customer, partner, or security messages, creating operational and reputational risk.',
		recommendation:
			'If this domain should receive email, add MX records. If not, publish a null MX record per RFC 7505 to explicitly declare that.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321', 'https://datatracker.ietf.org/doc/html/rfc7505'],
	},
	DANE_HTTPS_PASS: {
		title: 'DANE TLSA Configured for HTTPS',
		severity: 'pass',
		explanation:
			'TLSA records at _443._tcp.{domain} pin the web server certificate to DNS, providing an additional layer of TLS trust beyond the CA system. Combined with DNSSEC, this prevents unauthorized CAs from issuing fraudulent certificates for the domain.',
		recommendation: 'Maintain your DANE HTTPS configuration. Ensure TLSA records are updated whenever TLS certificates are renewed.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc6698',
			'https://datatracker.ietf.org/doc/html/rfc7671',
		],
	},
	DANE_HTTPS_FAIL: {
		title: 'No DANE TLSA for HTTPS',
		severity: 'fail',
		explanation:
			'No TLSA records were found at _443._tcp.{domain}. DANE certificate pinning for HTTPS provides an additional trust anchor beyond the CA system, preventing unauthorized certificate issuance attacks.',
		impact: 'Certificate issuance for this domain relies solely on the CA trust hierarchy.',
		adverseConsequences:
			'A compromised or rogue CA can issue a valid certificate for the domain, enabling MITM attacks that bypass standard browser trust checks.',
		recommendation:
			'Implement DANE-EE (usage 3) TLSA records at _443._tcp.{domain} and ensure DNSSEC is enabled. Use SHA-256 (matching type 1) or SHA-512 (matching type 2) for the certificate data hash.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc6698',
			'https://datatracker.ietf.org/doc/html/rfc7671',
		],
	},
	DANE_HTTPS_WARNING: {
		title: 'DANE HTTPS Configuration Warning',
		severity: 'warning',
		explanation:
			'DANE TLSA records exist for the HTTPS endpoint but the configuration has issues that reduce their security value, such as DANE without DNSSEC or weak matching types.',
		impact: 'DANE protection is partially effective but can be bypassed or subverted.',
		adverseConsequences:
			'Attackers may be able to spoof or modify TLSA records if DNSSEC is absent, negating the security benefit of DANE.',
		recommendation:
			'Enable DNSSEC on the domain and use DANE-EE (usage 3) with SHA-256 matching (type 1) for best security.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc6698',
			'https://datatracker.ietf.org/doc/html/rfc7671',
		],
	},
	DANE_HTTPS_INFO: {
		title: 'DANE HTTPS Record Present',
		severity: 'info',
		explanation: 'A TLSA record is configured at _443._tcp.{domain}, enabling DANE certificate pinning for HTTPS.',
		recommendation: 'Keep TLSA records synchronized with your TLS certificate. Automate renewal if possible.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6698'],
	},
	SVCB_HTTPS_PASS: {
		title: 'HTTPS Record Configured',
		severity: 'pass',
		explanation:
			'HTTPS/SVCB records (RFC 9460) are present and advertise modern transport capabilities. This enables clients to negotiate HTTP/2 or HTTP/3 without an initial redirect and optionally distributes ECH parameters for privacy.',
		recommendation: 'Maintain your HTTPS records. Consider enabling ECH for enhanced connection privacy.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc9460',
			'https://datatracker.ietf.org/doc/html/rfc8446',
		],
	},
	SVCB_HTTPS_FAIL: {
		title: 'No HTTPS Record Found',
		severity: 'fail',
		explanation:
			'No HTTPS record (type 65, RFC 9460) was found for this domain. HTTPS records advertise modern transport capabilities (ALPN, ECH) and allow clients to connect securely and efficiently without an initial redirect round-trip.',
		impact: 'Clients cannot discover HTTP/2 or HTTP/3 support via DNS, requiring an additional round-trip.',
		adverseConsequences:
			'Connection setup is slower, privacy from ECH is unavailable, and the domain misses opportunities for TLS optimization.',
		recommendation:
			'Publish an HTTPS record with at minimum alpn="h2,h3" to enable HTTP/2 and HTTP/3 advertisement. If using Cloudflare or similar CDN, this may be automatically managed.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc9460',
			'https://blog.cloudflare.com/speeding-up-https-and-http-3-negotiation-with-dns/',
		],
	},
	SVCB_HTTPS_WARNING: {
		title: 'HTTPS Record Configuration Warning',
		severity: 'warning',
		explanation:
			'HTTPS records are present but the configuration is suboptimal — for example, no ALPN parameters or missing HTTP/2 support.',
		impact: 'Clients cannot fully leverage the capabilities advertised in the HTTPS record.',
		adverseConsequences:
			'Performance benefits from SVCB are partially lost and ECH privacy may be unavailable.',
		recommendation:
			'Update HTTPS records to include alpn="h2,h3" and consider adding ECH parameters. Ensure alias mode targets also have valid HTTPS records.',
		references: ['https://datatracker.ietf.org/doc/html/rfc9460'],
	},
	SVCB_HTTPS_INFO: {
		title: 'HTTPS Record Present',
		severity: 'info',
		explanation: 'An HTTPS/SVCB record is configured, advertising modern connection capabilities for this domain.',
		recommendation: 'No action required. Consider adding ECH for enhanced privacy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc9460'],
	},
};

export const DEFAULT_EXPLANATION: ExplanationTemplate = {
	title: 'Security Check Complete',
	severity: 'info',
	explanation: "This check has been completed. Review the findings above for details on your domain's security posture.",
	recommendation: 'Refer to the specific check documentation for detailed remediation steps.',
	references: ['https://www.cloudflare.com/learning/dns/what-is-dns/'],
};

export const CATEGORY_TO_CHECKTYPE: Record<string, string> = {
	spf: 'SPF',
	dmarc: 'DMARC',
	dkim: 'DKIM',
	dnssec: 'DNSSEC',
	ssl: 'SSL',
	mta_sts: 'MTA_STS',
	ns: 'NS',
	caa: 'CAA',
	mx: 'MX',
	subdomain_takeover: 'SUBDOMAIN_TAKEOVER',
	dane_https: 'DANE_HTTPS',
	svcb_https: 'SVCB_HTTPS',
};

export const CATEGORY_FALLBACK_IMPACT: Record<string, ImpactNarrative> = {
	SPF: {
		impact: 'SPF coverage is weak, so unauthorized senders can spoof domain identity more easily.',
		adverseConsequences: 'Phishing attempts and deliverability disputes increase security and support workload.',
	},
	DMARC: {
		impact: 'DMARC enforcement is reduced or absent at receiving systems.',
		adverseConsequences: 'Forged messages are more likely to reach users and erode brand trust.',
	},
	DKIM: {
		impact: 'DKIM assurance is weak, reducing message integrity and sender-authenticity confidence.',
		adverseConsequences: 'Legitimate messages may be distrusted while impersonation attempts become harder to detect.',
	},
	DNSSEC: {
		impact: 'DNS answers are more exposed to spoofing and tampering in transit.',
		adverseConsequences: 'Users can be redirected to attacker infrastructure, causing security and availability incidents.',
	},
	SSL: {
		impact: 'Transport security guarantees are reduced, increasing interception and tampering risk.',
		adverseConsequences: 'Sensitive user data may be exposed and browser trust can decline.',
	},
	MTA_STS: {
		impact: 'Inbound SMTP delivery is not consistently protected from downgrade attacks.',
		adverseConsequences: 'Confidential email content may be exposed in transit, increasing compliance risk.',
	},
	NS: {
		impact: 'DNS resolution reliability is reduced, which weakens service reachability.',
		adverseConsequences: 'Users may experience outages and business transactions may fail.',
	},
	CAA: {
		impact: 'Certificate issuance controls are weak, raising unauthorized issuance risk.',
		adverseConsequences: 'Domain impersonation and TLS trust incidents become more likely.',
	},
	MX: {
		impact: 'Mail routing reliability is reduced by MX configuration gaps or errors.',
		adverseConsequences: 'Important communications can be delayed, bounced, or lost.',
	},
	SUBDOMAIN_TAKEOVER: {
		impact: 'An orphaned delegated subdomain may be claimable by an attacker.',
		adverseConsequences: 'Users can be redirected to malicious content hosted under a trusted hostname.',
	},
	DANE_HTTPS: {
		impact: 'HTTPS certificate pinning via DANE is absent or misconfigured, leaving TLS trust dependent solely on the CA system.',
		adverseConsequences: 'A rogue or compromised CA can issue a fraudulent certificate, enabling undetected MITM attacks.',
	},
	SVCB_HTTPS: {
		impact: 'Modern transport capabilities (ALPN, ECH) cannot be advertised via DNS, reducing connection efficiency and privacy.',
		adverseConsequences: 'Clients require additional round-trips to negotiate protocols, and ECH-based privacy is unavailable.',
	},
};

export const SEVERITY_FALLBACK_IMPACT: Record<string, ImpactNarrative> = {
	critical: {
		impact: 'This is a high-likelihood weakness with immediate exploitation potential.',
		adverseConsequences: 'Compromise, disruption, or abuse can occur without prompt remediation.',
	},
	high: {
		impact: 'This weakness materially increases attack surface and failure risk.',
		adverseConsequences: 'Business operations, user trust, and response workload can be negatively affected.',
	},
	medium: {
		impact: 'This issue weakens defenses and compounds risk when paired with other gaps.',
		adverseConsequences: 'Over time it can degrade reliability, security assurance, and compliance posture.',
	},
	warning: {
		impact: 'This configuration is partially protective but leaves avoidable exposure.',
		adverseConsequences: 'If unresolved, incidents become harder to prevent or contain.',
	},
	fail: {
		impact: 'A required control is missing or not functioning as intended.',
		adverseConsequences: 'Security and availability incidents become more likely until it is corrected.',
	},
	low: {
		impact: 'This is a minor weakness that still reduces resilience.',
		adverseConsequences: 'Operational friction and audit findings can increase over time.',
	},
};

export const SPECIFIC_IMPACT_RULES: SpecificImpactRule[] = [
	{
		checkType: 'DKIM',
		titleIncludes: ['weak rsa key'],
		impact: 'Weak DKIM keys are easier to forge, reducing message authenticity assurance.',
		adverseConsequences: 'Attackers can impersonate trusted senders more easily, increasing fraud and phishing risk.',
	},
	{
		checkType: 'SSL',
		titleIncludes: ['no hsts header', 'no http to https redirect', 'mixed content'],
		impact: 'Users are exposed to insecure transport paths that permit interception or downgrade attacks.',
		adverseConsequences: 'Sensitive sessions and data can leak on hostile networks, weakening trust and compliance posture.',
	},
	{
		checkType: 'DMARC',
		titleIncludes: ['no aggregate reporting'],
		impact: 'Authentication failures and spoofing activity become harder to observe at scale.',
		adverseConsequences: 'Threats can persist longer without detection, increasing response time and abuse volume.',
	},
	{
		checkType: 'MX',
		titleIncludes: ['no mx records found', 'mx configuration error'],
		impact: 'Inbound email delivery becomes unreliable or fails for recipients on this domain.',
		adverseConsequences: 'Critical business and security communications may be delayed, bounced, or silently lost.',
	},
	{
		checkType: 'NS',
		titleIncludes: ['no soa record', 'nameserver', 'low nameserver diversity'],
		impact: 'DNS resilience and consistency are reduced, increasing partial or full resolution outage risk.',
		adverseConsequences: 'Availability incidents can affect websites, APIs, and transactional workflows.',
	},
	{
		checkType: 'CAA',
		titleIncludes: ['no caa records', 'issuewild', 'iodef'],
		impact: 'Certificate governance controls are weakened, especially for unauthorized or wildcard issuance.',
		adverseConsequences: 'TLS trust incidents and audit findings become more likely if certificate misuse occurs.',
	},
	{
		checkType: 'SPF',
		titleIncludes: ['permissive spf: +all', 'multiple spf records'],
		detailIncludes: ['+all', 'multiple records'],
		impact: 'SPF policy becomes ineffective or ambiguous, allowing unauthorized senders to appear legitimate.',
		adverseConsequences: 'Spoofing, phishing, and deliverability failures can increase simultaneously.',
	},
	{
		checkType: 'MTA_STS',
		titleIncludes: ['no mta-sts', 'testing mode', 'tls-rpt'],
		impact: 'SMTP transport protections are not consistently enforced for inbound mail delivery.',
		adverseConsequences: 'Confidential email may traverse weaker paths, increasing confidentiality and regulatory risk.',
	},
];