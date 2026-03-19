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
			'SPF (Sender Policy Framework) is properly configured. Think of it as a guest list for your domain — it specifies which mail servers are authorized to send email on its behalf.',
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
		explanation: 'SPF uses a soft fail (~all) policy. Emails that fail SPF will be accepted but may be flagged as suspicious.',
		impact: 'Failing SPF messages are often still accepted, so spoofed mail may continue reaching recipients.',
		adverseConsequences: 'Phishing risk remains elevated and security teams may need to manually triage suspicious mail.',
		recommendation: 'Upgrade to hard fail (-all) after verifying all legitimate sources are in your SPF record.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-8.1'],
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

	// --- DKIM detail-specific entries ---
	DKIM_LEGACY_RSA: {
		title: 'Legacy DKIM RSA Key',
		severity: 'high',
		explanation: 'The DKIM signing key uses a legacy 1024-bit RSA key, which is considered weak by modern standards and may be vulnerable to factoring attacks.',
		recommendation: 'Upgrade to a 2048-bit or stronger RSA key, or consider using Ed25519 for DKIM signing.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376', 'https://datatracker.ietf.org/doc/html/rfc8463'],
	},
	DKIM_REVOKED: {
		title: 'Revoked DKIM Key',
		severity: 'medium',
		explanation: 'A DKIM selector has an empty public key (p=), indicating the key has been explicitly revoked. Messages signed with this selector will fail DKIM verification.',
		recommendation: 'If this selector is still in use, publish a new key. If intentionally revoked, ensure no mail system still references it.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1'],
	},
	DKIM_BELOW_RECOMMENDED: {
		title: 'Below Recommended DKIM Key Size',
		severity: 'medium',
		explanation: 'The DKIM RSA key is below the recommended 2048-bit minimum. Shorter keys are more vulnerable to brute-force factoring.',
		recommendation: 'Upgrade the DKIM key to at least 2048 bits for adequate security margins.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376'],
	},
	DKIM_MISSING_VERSION: {
		title: 'Missing DKIM Version Tag',
		severity: 'medium',
		explanation: 'The DKIM record is missing the v=DKIM1 version tag. While some implementations tolerate this, it is required for strict compliance.',
		recommendation: 'Add v=DKIM1 to the beginning of the DKIM TXT record.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1'],
	},
	DKIM_TESTING_MODE: {
		title: 'DKIM in Testing Mode',
		severity: 'low',
		explanation: 'The DKIM record contains t=y, indicating testing mode. Receivers may not enforce DKIM failures for this domain.',
		recommendation: 'After confirming DKIM signing works correctly, remove the t=y flag to enable full enforcement.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1'],
	},
	DKIM_NO_RECORDS: {
		title: 'No DKIM Records Found',
		severity: 'high',
		explanation: 'No DKIM records were found among the tested selectors. Without DKIM, receivers cannot verify message integrity or sender authenticity.',
		recommendation: 'Configure DKIM signing with your email provider and publish the corresponding DNS records.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376', 'https://www.cloudflare.com/learning/dns/dns-records/dns-dkim-record/'],
	},
	DKIM_WEAK_RSA: {
		title: 'Weak DKIM RSA Key',
		severity: 'medium',
		explanation: 'The DKIM RSA key is weak and may be vulnerable to factoring attacks. Modern security standards require stronger keys.',
		recommendation: 'Upgrade to a 2048-bit or stronger RSA key.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376'],
	},
	DKIM_UNKNOWN_KEY_TYPE: {
		title: 'Unknown DKIM Key Type',
		severity: 'medium',
		explanation: 'The DKIM record specifies an unrecognized key type. This may indicate a misconfiguration or use of a non-standard algorithm.',
		recommendation: 'Verify the DKIM record key type is set to rsa or ed25519.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376', 'https://datatracker.ietf.org/doc/html/rfc8463'],
	},
	DKIM_SHORT_KEY: {
		title: 'Short DKIM Key Material',
		severity: 'high',
		explanation: 'The DKIM key material is too short for the declared algorithm, rendering the signature cryptographically weak or invalid.',
		recommendation: 'Regenerate the DKIM key with appropriate key length for the chosen algorithm.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376'],
	},

	// --- SPF detail-specific entries ---
	SPF_SOFT_FAIL: {
		title: 'SPF Soft Fail (~all)',
		severity: 'low',
		explanation: 'The SPF record uses ~all (soft fail), meaning unauthorized senders are flagged but not rejected. This provides limited protection.',
		recommendation: 'Upgrade to -all (hard fail) after verifying all legitimate sending sources are included in the SPF record.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-8.1'],
	},
	SPF_PERMISSIVE_ALL: {
		title: 'Permissive SPF Policy (+all)',
		severity: 'critical',
		explanation: 'The domain publishes an SPF policy with +all, which explicitly allows any server to send email on its behalf. This completely negates SPF protection.',
		recommendation: 'Replace +all with -all and explicitly list authorized senders via include, ip4, or ip6 mechanisms.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
	},
	SPF_TOO_MANY_LOOKUPS: {
		title: 'Too Many SPF DNS Lookups',
		severity: 'critical',
		explanation: 'The SPF record exceeds the 10-lookup limit defined in RFC 7208. Receivers will return a permerror, effectively disabling SPF.',
		recommendation: 'Flatten the SPF record by replacing include mechanisms with direct IP ranges, or use an SPF flattening service.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4'],
	},
	SPF_MULTIPLE_RECORDS: {
		title: 'Multiple SPF Records',
		severity: 'high',
		explanation: 'Multiple SPF TXT records were found. RFC 7208 requires exactly one SPF record per domain; multiple records cause a permerror.',
		recommendation: 'Merge all SPF records into a single TXT record. Remove duplicates.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-3.2'],
	},
	SPF_NO_RECORD: {
		title: 'No SPF Record Found',
		severity: 'critical',
		explanation: 'No SPF record was found for this domain. Without SPF, any server can send email pretending to be from your domain.',
		recommendation: 'Add a TXT record with a valid SPF policy: v=spf1 include:<your-email-provider> -all',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208', 'https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/'],
	},
	SPF_BROAD_IP: {
		title: 'Overly Broad SPF IP Range',
		severity: 'high',
		explanation: 'The SPF record includes an overly broad IP range that authorizes millions of IP addresses, significantly weakening sender restrictions.',
		recommendation: 'Narrow the IP ranges to only include your actual mail server IPs. Avoid CIDR blocks larger than /24.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
	},
	SPF_DEPRECATED_PTR: {
		title: 'Deprecated SPF ptr Mechanism',
		severity: 'medium',
		explanation: 'The SPF record uses the ptr mechanism, which is deprecated by RFC 7208 due to performance and reliability concerns.',
		recommendation: 'Replace ptr mechanisms with explicit ip4, ip6, or include mechanisms.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-5.5'],
	},

	// --- DMARC detail-specific entries ---
	DMARC_NO_SUBDOMAIN_POLICY: {
		title: 'No DMARC Subdomain Policy',
		severity: 'low',
		explanation: 'No explicit subdomain policy (sp=) is specified in the DMARC record. Subdomains inherit the parent domain policy by default.',
		recommendation: 'Add sp=reject or sp=quarantine to your DMARC record to explicitly control subdomain email authentication.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_RELAXED_DKIM: {
		title: 'Relaxed DKIM Alignment',
		severity: 'low',
		explanation: 'DKIM alignment is set to relaxed (adkim=r or default), allowing DKIM signatures from subdomains to pass for the parent domain.',
		recommendation: 'Set adkim=s for strict alignment if your mail architecture supports it.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-3.1'],
	},
	DMARC_RELAXED_SPF: {
		title: 'Relaxed SPF Alignment',
		severity: 'low',
		explanation: 'SPF alignment is set to relaxed (aspf=r or default), allowing SPF results from subdomains to pass for the parent domain.',
		recommendation: 'Set aspf=s for strict alignment if your mail architecture supports it.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-3.1'],
	},
	DMARC_NO_FORENSIC: {
		title: 'No DMARC Forensic Reporting',
		severity: 'low',
		explanation: 'No forensic reporting URI (ruf=) is configured in the DMARC record. Forensic reports provide detailed per-message failure information.',
		recommendation: 'Add ruf=mailto:dmarc-forensic@yourdomain.com to receive per-message failure reports.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_POLICY_NONE: {
		title: 'DMARC Policy Set to None',
		severity: 'high',
		explanation: 'The DMARC policy is set to p=none (monitoring only). Receiving systems will not quarantine or reject messages that fail authentication.',
		recommendation: 'After reviewing DMARC aggregate reports, upgrade the policy to p=quarantine or p=reject.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_NO_AGGREGATE: {
		title: 'No DMARC Aggregate Reporting',
		severity: 'medium',
		explanation: 'No aggregate report URI (rua=) is specified in the DMARC record. Without aggregate reports, you have no visibility into authentication results.',
		recommendation: 'Add rua=mailto:dmarc@yourdomain.com to receive daily aggregate reports from receivers.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_MULTIPLE: {
		title: 'Multiple DMARC Records',
		severity: 'high',
		explanation: 'Multiple DMARC TXT records were found. RFC 7489 requires exactly one DMARC record; multiple records cause undefined behavior.',
		recommendation: 'Remove duplicate DMARC records, keeping only the intended policy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.6.3'],
	},
	DMARC_SUBDOMAIN_WEAKER: {
		title: 'Subdomain Policy Weaker Than Organization Policy',
		severity: 'medium',
		explanation: 'The subdomain policy (sp=) is weaker than the organization-level policy (p=), creating an inconsistency that attackers may exploit.',
		recommendation: 'Align the subdomain policy with the organization policy, or set sp= to at least the same enforcement level.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_PARTIAL_COVERAGE: {
		title: 'DMARC Partial Coverage',
		severity: 'medium',
		explanation: 'The DMARC pct= tag is set to less than 100, meaning the policy only applies to a fraction of messages. The remainder is unprotected.',
		recommendation: 'Increase pct= to 100 after confirming legitimate mail passes authentication.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_INVALID_POLICY: {
		title: 'Invalid DMARC Policy Value',
		severity: 'high',
		explanation: 'The DMARC record contains an invalid policy value. Valid values are none, quarantine, or reject.',
		recommendation: 'Correct the p= tag to one of: none, quarantine, reject.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_MISSING_POLICY: {
		title: 'DMARC Record Missing Policy Tag',
		severity: 'high',
		explanation: 'A DMARC record was found but it is missing the required p= policy tag. Without a policy, the record is invalid.',
		recommendation: 'Add a p= tag to the DMARC record (e.g., p=quarantine or p=reject).',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},

	// --- DNSSEC detail-specific entries ---
	DNSSEC_NO_DNSKEY: {
		title: 'No DNSKEY Records',
		severity: 'high',
		explanation: 'No DNSKEY records were found for this domain. Without DNSKEY records, DNSSEC validation cannot be performed.',
		recommendation: 'Enable DNSSEC through your DNS provider to publish DNSKEY records.',
		references: ['https://datatracker.ietf.org/doc/html/rfc4033', 'https://www.cloudflare.com/dns/dnssec/how-dnssec-works/'],
	},
	DNSSEC_NO_DS: {
		title: 'No DS Records',
		severity: 'medium',
		explanation: 'No DS (Delegation Signer) records were found. DS records are required at the parent zone to establish the DNSSEC chain of trust.',
		recommendation: 'Add DS records at your domain registrar to complete the DNSSEC chain of trust.',
		references: ['https://datatracker.ietf.org/doc/html/rfc4033'],
	},
	DNSSEC_DEPRECATED_ALGO: {
		title: 'Deprecated DNSSEC Algorithm',
		severity: 'high',
		explanation: 'The DNSSEC signing algorithm is deprecated (e.g., RSASHA1) and may be vulnerable to cryptographic attacks.',
		recommendation: 'Migrate to a stronger algorithm such as ECDSAP256SHA256 (algorithm 13) or Ed25519 (algorithm 15).',
		references: ['https://datatracker.ietf.org/doc/html/rfc8624'],
	},
	DNSSEC_UNKNOWN_ALGO: {
		title: 'Unknown DNSSEC Algorithm',
		severity: 'medium',
		explanation: 'The DNSSEC signing algorithm is not recognized. This may indicate a misconfiguration or use of a non-standard algorithm.',
		recommendation: 'Verify the DNSSEC algorithm is one of the IANA-registered algorithms.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8624'],
	},
	DNSSEC_DEPRECATED_DS_DIGEST: {
		title: 'Deprecated DS Digest Type',
		severity: 'medium',
		explanation: 'The DS record uses a SHA-1 digest type, which is cryptographically weak. Modern implementations should use SHA-256 or stronger.',
		recommendation: 'Update the DS record to use digest type 2 (SHA-256) or higher.',
		references: ['https://datatracker.ietf.org/doc/html/rfc4509'],
	},

	// --- SSL detail-specific entries ---
	SSL_NO_HSTS: {
		title: 'No HSTS Header',
		severity: 'medium',
		explanation: 'No HTTP Strict-Transport-Security header was found. Without HSTS, browsers may still attempt insecure HTTP connections.',
		recommendation: 'Add a Strict-Transport-Security header with max-age of at least 31536000 (1 year).',
		references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
	},
	SSL_NO_REDIRECT: {
		title: 'No HTTP to HTTPS Redirect',
		severity: 'medium',
		explanation: 'The domain does not redirect HTTP requests to HTTPS. Users accessing the site via HTTP will have their traffic sent unencrypted.',
		recommendation: 'Configure your web server to redirect all HTTP requests to HTTPS with a 301 permanent redirect.',
		references: ['https://https.cio.gov/hsts/'],
	},
	SSL_HSTS_SHORT: {
		title: 'HSTS Max-Age Too Short',
		severity: 'low',
		explanation: 'The HSTS max-age value is shorter than recommended. A short max-age reduces the protection window against downgrade attacks.',
		recommendation: 'Set max-age to at least 31536000 (1 year). Consider adding your domain to the HSTS preload list.',
		references: ['https://hstspreload.org/', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
	},
	SSL_HSTS_NO_SUBDOMAINS: {
		title: 'HSTS Missing includeSubDomains',
		severity: 'low',
		explanation: 'The HSTS header does not include the includeSubDomains directive, leaving subdomains vulnerable to downgrade attacks.',
		recommendation: 'Add includeSubDomains to the HSTS header to protect all subdomains.',
		references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
	},

	// --- MTA-STS detail-specific entries ---
	MTA_STS_NO_RECORDS: {
		title: 'No MTA-STS Records Found',
		severity: 'medium',
		explanation: 'Neither MTA-STS nor TLS-RPT records are present. Without these, inbound email transport security is not enforced.',
		recommendation: 'Publish an MTA-STS TXT record and host a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	MTA_STS_TESTING: {
		title: 'MTA-STS in Testing Mode',
		severity: 'low',
		explanation: 'MTA-STS policy is in testing mode (mode=testing). Mail servers will report but not enforce TLS requirements.',
		recommendation: 'After verifying all mail servers deliver successfully over TLS, upgrade to mode=enforce.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	MTA_STS_INACCESSIBLE: {
		title: 'MTA-STS Policy File Inaccessible',
		severity: 'high',
		explanation: 'The MTA-STS policy file could not be retrieved. Sending servers will be unable to enforce TLS for your domain.',
		recommendation: 'Ensure the policy file is accessible at https://mta-sts.<domain>/.well-known/mta-sts.txt with a valid HTTPS certificate.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	MTA_STS_TLSRPT_MISSING: {
		title: 'TLS-RPT Record Missing',
		severity: 'low',
		explanation: 'No TLS-RPT record was found. Without TLS-RPT, you will not receive reports about TLS delivery failures from sending servers.',
		recommendation: 'Add a _smtp._tls TXT record with v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.com',
		references: ['https://datatracker.ietf.org/doc/html/rfc8460'],
	},
	MTA_STS_DISABLED: {
		title: 'MTA-STS Disabled',
		severity: 'medium',
		explanation: 'MTA-STS policy is set to mode:none, explicitly disabling TLS enforcement for inbound mail delivery.',
		recommendation: 'Set the MTA-STS policy mode to testing or enforce to enable TLS protections.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	MTA_STS_SHORT_MAX_AGE: {
		title: 'MTA-STS Max Age Too Short',
		severity: 'low',
		explanation: 'The MTA-STS max_age value is too short, reducing the duration that sending servers cache the TLS enforcement policy.',
		recommendation: 'Set max_age to at least 86400 (1 day), ideally 604800 (1 week) or more.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},

	// --- NS detail-specific entries ---
	NS_LOW_DIVERSITY: {
		title: 'Low Nameserver Diversity',
		severity: 'low',
		explanation: 'All nameservers are under the same domain, providing low diversity. If that domain has issues, all DNS resolution fails.',
		recommendation: 'Use nameservers from at least two different providers or networks for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035'],
	},
	NS_SOA_EXPIRE_SHORT: {
		title: 'SOA Expire Too Short',
		severity: 'medium',
		explanation: 'The SOA expire value is below the recommended minimum of one week (604800 seconds). Secondary nameservers will stop serving the zone too quickly if the primary becomes unavailable.',
		recommendation: 'Set the SOA expire value to at least 604800 seconds (1 week).',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035'],
	},
	NS_SINGLE: {
		title: 'Single Nameserver',
		severity: 'high',
		explanation: 'Only one nameserver was found, violating RFC 1035 which requires at least two nameservers for redundancy.',
		recommendation: 'Add at least one additional nameserver, preferably on a different network.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035#section-2.2'],
	},
	NS_NO_SOA: {
		title: 'No SOA Record Found',
		severity: 'high',
		explanation: 'No SOA (Start of Authority) record was found. The SOA record is required for every DNS zone and defines key zone parameters.',
		recommendation: 'Ensure your DNS zone has a valid SOA record. Contact your DNS provider if it is missing.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035'],
	},
	NS_SOA_REFRESH_SHORT: {
		title: 'SOA Refresh Interval Too Short',
		severity: 'low',
		explanation: 'The SOA refresh interval is very short, causing secondary nameservers to query the primary too frequently.',
		recommendation: 'Set the SOA refresh interval to at least 3600 seconds (1 hour) for most zones.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035'],
	},
	NS_SOA_NEGATIVE_TTL_LONG: {
		title: 'SOA Negative TTL Too Long',
		severity: 'low',
		explanation: 'The SOA negative TTL (minimum field) is too long, causing resolvers to cache NXDOMAIN responses for an extended period.',
		recommendation: 'Set the SOA minimum (negative TTL) to between 300 and 3600 seconds per RFC 2308.',
		references: ['https://datatracker.ietf.org/doc/html/rfc2308'],
	},

	// --- CAA detail-specific entries ---
	CAA_NO_ISSUE: {
		title: 'No CAA Issue Tag',
		severity: 'medium',
		explanation: 'CAA records exist but no "issue" tag was found. Without an issue tag, the CAA records do not restrict which CAs can issue certificates.',
		recommendation: 'Add a CAA issue record restricting certificate issuance to your authorized CAs.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
	},
	CAA_NO_ISSUEWILD: {
		title: 'No CAA Issuewild Tag',
		severity: 'low',
		explanation: 'No "issuewild" CAA tag was found. Without it, wildcard certificate issuance inherits the "issue" policy.',
		recommendation: 'Add a CAA issuewild record to explicitly control wildcard certificate issuance.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
	},
	CAA_NO_IODEF: {
		title: 'No CAA Iodef Tag',
		severity: 'low',
		explanation: 'No "iodef" CAA tag was found. Without it, you will not receive notifications when a CA denies a certificate request based on CAA.',
		recommendation: 'Add a CAA iodef record (e.g., iodef "mailto:security@yourdomain.com") for incident reporting.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
	},
	CAA_NO_RECORDS: {
		title: 'No CAA Records',
		severity: 'medium',
		explanation: 'No CAA records are present for this domain. Any certificate authority can issue certificates for your domain.',
		recommendation: 'Add CAA DNS records to restrict certificate issuance to your authorized CAs.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659', 'https://www.cloudflare.com/learning/dns/dns-records/dns-caa-record/'],
	},

	// --- MX detail-specific entries ---
	MX_SINGLE_RECORD: {
		title: 'Single MX Record',
		severity: 'low',
		explanation: 'Only one MX record was found. Without a backup MX, email delivery will fail if the primary mail server goes down.',
		recommendation: 'Add at least one backup MX record with a higher priority value for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_POINTS_TO_IP: {
		title: 'MX Points to IP Address',
		severity: 'medium',
		explanation: 'An MX record points to an IP address instead of a hostname, which violates RFC 5321.',
		recommendation: 'Update the MX record to point to a valid hostname that resolves to an A/AAAA record.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_DANGLING: {
		title: 'Dangling MX Record',
		severity: 'medium',
		explanation: 'An MX record target does not resolve to any IP address. Mail delivery to this target will fail.',
		recommendation: 'Update or remove the MX record pointing to the unresolvable hostname.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_NO_RECORDS: {
		title: 'No MX Records Found',
		severity: 'info',
		explanation: 'No MX records were found for this domain. Email delivery will fall back to A record delivery or fail.',
		recommendation: 'If this domain should receive email, add MX records. Otherwise, publish a null MX record per RFC 7505.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321', 'https://datatracker.ietf.org/doc/html/rfc7505'],
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
		impact: 'A weak DKIM key is like a wax seal that can be easily duplicated — it no longer guarantees message authenticity.',
		adverseConsequences: 'Attackers can forge DKIM signatures and send fake emails that pass verification, enabling phishing and fraud.',
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
		impact: 'Without aggregate reports you lose the big picture view of who is sending email as your domain.',
		adverseConsequences: 'Spoofing campaigns and configuration drift can go unnoticed until real damage is done.',
	},
	{
		checkType: 'DMARC',
		titleIncludes: ['no subdomain policy'],
		impact: 'Without an explicit sp= tag, subdomains inherit the parent policy which may not be appropriate for all subdomains.',
		adverseConsequences: 'Attackers can target subdomain spoofing where the inherited policy is too lenient.',
	},
	{
		checkType: 'DMARC',
		titleIncludes: ['no forensic reporting'],
		detailIncludes: ['ruf='],
		impact: 'Forensic reports provide per-message failure details that go beyond aggregate summaries.',
		adverseConsequences: 'Without forensic data it is harder to diagnose individual authentication failures and targeted attacks.',
	},
	{
		checkType: 'DMARC',
		titleIncludes: ['relaxed dkim alignment', 'relaxed spf alignment'],
		impact: 'Relaxed alignment allows any subdomain under the organizational domain to pass DMARC checks.',
		adverseConsequences: 'Attackers can send from a subdomain and still pass alignment, enabling subdomain spoofing.',
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

export interface DetailsPattern {
	checkType: string;
	pattern: RegExp;
	key: string;
}

export const DETAILS_PATTERNS: DetailsPattern[] = [
	// DKIM patterns
	{ checkType: 'DKIM', pattern: /legacy\s+1024[- ]bit\s+rsa/i, key: 'DKIM_LEGACY_RSA' },
	{ checkType: 'DKIM', pattern: /empty public key.*revoked|revoked.*empty public key|p=\).*revoked/i, key: 'DKIM_REVOKED' },
	{ checkType: 'DKIM', pattern: /below recommended/i, key: 'DKIM_BELOW_RECOMMENDED' },
	{ checkType: 'DKIM', pattern: /missing the v= tag|missing.*version tag/i, key: 'DKIM_MISSING_VERSION' },
	{ checkType: 'DKIM', pattern: /testing mode/i, key: 'DKIM_TESTING_MODE' },
	{ checkType: 'DKIM', pattern: /no dkim records found/i, key: 'DKIM_NO_RECORDS' },
	{ checkType: 'DKIM', pattern: /weak/i, key: 'DKIM_WEAK_RSA' },
	{ checkType: 'DKIM', pattern: /unrecognized key type/i, key: 'DKIM_UNKNOWN_KEY_TYPE' },
	{ checkType: 'DKIM', pattern: /key material too short/i, key: 'DKIM_SHORT_KEY' },

	// SPF patterns
	{ checkType: 'SPF', pattern: /~all.*soft fail|soft fail.*~all/i, key: 'SPF_SOFT_FAIL' },
	{ checkType: 'SPF', pattern: /\+all/i, key: 'SPF_PERMISSIVE_ALL' },
	{ checkType: 'SPF', pattern: /too many.*dns.*lookup|dns.*lookup.*>\s*10/i, key: 'SPF_TOO_MANY_LOOKUPS' },
	{ checkType: 'SPF', pattern: /multiple spf records/i, key: 'SPF_MULTIPLE_RECORDS' },
	{ checkType: 'SPF', pattern: /no spf record found/i, key: 'SPF_NO_RECORD' },
	{ checkType: 'SPF', pattern: /overly broad.*ip range|broad.*ip.*range/i, key: 'SPF_BROAD_IP' },
	{ checkType: 'SPF', pattern: /deprecated.*ptr/i, key: 'SPF_DEPRECATED_PTR' },

	// DMARC patterns
	{ checkType: 'DMARC', pattern: /no subdomain policy|sp=\)/i, key: 'DMARC_NO_SUBDOMAIN_POLICY' },
	{ checkType: 'DMARC', pattern: /dkim alignment.*relaxed|adkim=r/i, key: 'DMARC_RELAXED_DKIM' },
	{ checkType: 'DMARC', pattern: /spf alignment.*relaxed|aspf=r/i, key: 'DMARC_RELAXED_SPF' },
	{ checkType: 'DMARC', pattern: /forensic reporting.*not configured|ruf=\).*not configured/i, key: 'DMARC_NO_FORENSIC' },
	{ checkType: 'DMARC', pattern: /policy set to none|policy.*none.*monitoring/i, key: 'DMARC_POLICY_NONE' },
	{ checkType: 'DMARC', pattern: /no aggregate report|rua=\).*not|no.*rua=/i, key: 'DMARC_NO_AGGREGATE' },
	{ checkType: 'DMARC', pattern: /multiple dmarc/i, key: 'DMARC_MULTIPLE' },
	{ checkType: 'DMARC', pattern: /subdomain.*weaker.*organization|subdomain policy.*weaker/i, key: 'DMARC_SUBDOMAIN_WEAKER' },
	{ checkType: 'DMARC', pattern: /pct=.*less than 100|percentage tag.*pct/i, key: 'DMARC_PARTIAL_COVERAGE' },
	{ checkType: 'DMARC', pattern: /invalid.*dmarc.*policy|invalid.*policy value/i, key: 'DMARC_INVALID_POLICY' },
	{ checkType: 'DMARC', pattern: /missing p= tag|missing.*policy tag/i, key: 'DMARC_MISSING_POLICY' },

	// DNSSEC patterns
	{ checkType: 'DNSSEC', pattern: /no dnskey/i, key: 'DNSSEC_NO_DNSKEY' },
	{ checkType: 'DNSSEC', pattern: /no ds.*delegation signer|no ds.*records/i, key: 'DNSSEC_NO_DS' },
	{ checkType: 'DNSSEC', pattern: /deprecated.*algorithm/i, key: 'DNSSEC_DEPRECATED_ALGO' },
	{ checkType: 'DNSSEC', pattern: /unrecognized.*algorithm|unknown.*algorithm/i, key: 'DNSSEC_UNKNOWN_ALGO' },
	{ checkType: 'DNSSEC', pattern: /sha-1.*digest|ds.*uses sha-1/i, key: 'DNSSEC_DEPRECATED_DS_DIGEST' },

	// SSL patterns
	{ checkType: 'SSL', pattern: /no hsts header/i, key: 'SSL_NO_HSTS' },
	{ checkType: 'SSL', pattern: /no http to https redirect|no.*redirect/i, key: 'SSL_NO_REDIRECT' },
	{ checkType: 'SSL', pattern: /hsts max-age.*short|max-age.*less than/i, key: 'SSL_HSTS_SHORT' },
	{ checkType: 'SSL', pattern: /missing includesubdomains/i, key: 'SSL_HSTS_NO_SUBDOMAINS' },

	// MTA-STS patterns
	{ checkType: 'MTA_STS', pattern: /neither mta-sts nor tls-rpt|no.*mta-sts.*tls-rpt/i, key: 'MTA_STS_NO_RECORDS' },
	{ checkType: 'MTA_STS', pattern: /testing mode/i, key: 'MTA_STS_TESTING' },
	{ checkType: 'MTA_STS', pattern: /policy.*not accessible|policy file.*inaccessible|policy.*http/i, key: 'MTA_STS_INACCESSIBLE' },
	{ checkType: 'MTA_STS', pattern: /tls-rpt.*missing/i, key: 'MTA_STS_TLSRPT_MISSING' },
	{ checkType: 'MTA_STS', pattern: /mode:none|mode.*none.*disabl/i, key: 'MTA_STS_DISABLED' },
	{ checkType: 'MTA_STS', pattern: /max_age.*too short/i, key: 'MTA_STS_SHORT_MAX_AGE' },

	// NS patterns
	{ checkType: 'NS', pattern: /low.*nameserver.*diversity|all nameservers.*under/i, key: 'NS_LOW_DIVERSITY' },
	{ checkType: 'NS', pattern: /soa expire.*short|expire.*<\s*604800/i, key: 'NS_SOA_EXPIRE_SHORT' },
	{ checkType: 'NS', pattern: /single nameserver/i, key: 'NS_SINGLE' },
	{ checkType: 'NS', pattern: /no soa record/i, key: 'NS_NO_SOA' },
	{ checkType: 'NS', pattern: /soa refresh.*too short|refresh interval.*too short/i, key: 'NS_SOA_REFRESH_SHORT' },
	{ checkType: 'NS', pattern: /negative ttl.*too long|soa.*minimum.*too long/i, key: 'NS_SOA_NEGATIVE_TTL_LONG' },

	// CAA patterns (issuewild before issue to avoid false match on "issuewild")
	{ checkType: 'CAA', pattern: /no.*"issuewild"|no.*issuewild.*tag/i, key: 'CAA_NO_ISSUEWILD' },
	{ checkType: 'CAA', pattern: /no.*"issue".*tag|no.*issue.*tag found/i, key: 'CAA_NO_ISSUE' },
	{ checkType: 'CAA', pattern: /no.*"iodef"|no.*iodef.*tag/i, key: 'CAA_NO_IODEF' },
	{ checkType: 'CAA', pattern: /no caa records/i, key: 'CAA_NO_RECORDS' },

	// MX patterns
	{ checkType: 'MX', pattern: /only one mx|single mx/i, key: 'MX_SINGLE_RECORD' },
	{ checkType: 'MX', pattern: /points to ip|mx.*ip address/i, key: 'MX_POINTS_TO_IP' },
	{ checkType: 'MX', pattern: /dangling mx|target does not resolve/i, key: 'MX_DANGLING' },
	{ checkType: 'MX', pattern: /no mx records/i, key: 'MX_NO_RECORDS' },
];