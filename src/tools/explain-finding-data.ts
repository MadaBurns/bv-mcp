// SPDX-License-Identifier: BUSL-1.1
// bv-oversize-ok: knowledge-base data table (explanation templates + finding
// signatures). Length is content, not logic — the only code here is type
// declarations; all matching/resolution lives in explain-finding.ts.

export interface ExplanationTemplate {
	title: string;
	severity: string;
	explanation: string;
	impact?: string;
	adverseConsequences?: string;
	recommendation: string;
	references: string[];
	/**
	 * Wording used when the caller SUPPLIED a `details` string that matched no
	 * known signature in {@link DETAIL_SIGNATURES}.
	 *
	 * The default `explanation` / `recommendation` on a per-(type, severity)
	 * bucket entry enumerates the causes that commonly land in that bucket
	 * ("for example multiple SPF records ... or an overly broad IP range").
	 * That enumeration is honest when no detail was supplied, but when a detail
	 * IS supplied and we could not recognise it, asserting those causes states a
	 * specific defect we do not know to be present. These fields carry the
	 * de-specified wording used in that case: still useful general guidance,
	 * but no invented cause.
	 */
	genericExplanation?: string;
	genericRecommendation?: string;
}

/**
 * A recognised finding signature within a checkType.
 *
 * `explain_finding` receives `details` (the finding's own detail text) but
 * historically keyed only on `checkType + status`, so every finding in a bucket
 * got the bucket's enumerated-example wording — which contradicts the actual
 * finding whenever the real cause is not one of the enumerated ones. A matching
 * signature replaces the bucket wording wholesale (title/explanation/impact/
 * consequences/recommendation/references) so the remediation matches the finding.
 *
 * Templates here MUST be self-contained: they never inherit impact or
 * consequences from the bucket entry, because bucket narratives describe the
 * enumerated causes rather than this one.
 */
export interface DetailSignatureTemplate {
	title: string;
	explanation: string;
	impact: string;
	adverseConsequences: string;
	recommendation: string;
	references: string[];
}

export interface DetailSignatureRule {
	/** Stable identifier, surfaced as `ExplanationResult.matchedSignature`. */
	id: string;
	/** Uppercased checkType this rule applies to. */
	checkType: string;
	/**
	 * Optional restriction to specific caller statuses (lowercased). Omit to
	 * apply to any non-passing status — the same defect can be reported at
	 * different severities depending on profile and corroborating context.
	 */
	statuses?: string[];
	/** Matched against the raw `details` string. Never use the /g flag (stateful lastIndex). */
	pattern: RegExp;
	template: DetailSignatureTemplate;
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
		adverseConsequences:
			'Users may be exposed to fraudulent pages and the organization may face reputation damage until DNS is remediated.',
		recommendation: 'Manually review the CNAME target and remove or update if orphaned. Use DNS monitoring tools for ongoing checks.',
		references: ['https://github.com/EdOverflow/can-i-take-over-xyz', 'https://www.hackerone.com/blog/Guide-Subdomain-Takeover'],
	},
	SUBDOMAIN_TAKEOVER_INFO: {
		title: 'No Dangling CNAME Records Found',
		severity: 'info',
		explanation: 'No subdomain takeover vectors detected among known/active subdomains. DNS configuration is secure for this check.',
		recommendation: 'Continue regular DNS audits and monitoring for new subdomains or changes.',
		references: ['https://github.com/EdOverflow/can-i-take-over-xyz'],
	},
	SUBDOMAILING_CRITICAL: {
		title: 'Dangling CNAME in SPF Include Chain — SubdoMailing Risk',
		severity: 'critical',
		explanation:
			'An SPF include domain has a dangling CNAME record pointing to a third-party service that does not resolve. An attacker could register the orphaned resource, gain control of the SPF include, and send authenticated email as the target domain.',
		impact: 'Full email authentication bypass — attacker-sent messages pass SPF checks and may pass DMARC alignment.',
		adverseConsequences: 'Targeted phishing campaigns sent from a trusted domain identity, bypassing email security filters at scale.',
		recommendation:
			'Remove the include mechanism from the SPF record or update it to point to a valid, owned resource. Audit all SPF includes periodically.',
		references: [
			'https://guardio.co/blog/subdomailing',
			'https://datatracker.ietf.org/doc/html/rfc7208',
			'https://github.com/EdOverflow/can-i-take-over-xyz',
		],
	},
	SUBDOMAILING_HIGH: {
		title: 'Dangling NS Delegation in SPF Include Chain',
		severity: 'high',
		explanation:
			'An SPF include domain has nameservers that do not resolve. An attacker could register the NS target domains and take control of DNS for the include domain, enabling SPF authorization hijacking.',
		impact: 'Potential email authentication bypass if the attacker registers the unresolvable nameserver domains.',
		adverseConsequences: 'Spoofed emails could pass SPF validation, eroding trust and enabling impersonation attacks.',
		recommendation:
			'Remove the include mechanism or ensure its nameservers resolve correctly. Consider consolidating SPF includes to domains under your direct control.',
		references: ['https://guardio.co/blog/subdomailing', 'https://datatracker.ietf.org/doc/html/rfc7208'],
	},
	SUBDOMAILING_LOW: {
		title: 'Void SPF Include',
		severity: 'low',
		explanation:
			'An SPF include domain has no SPF record. While not immediately exploitable, this wastes a DNS lookup and could become a risk if the domain is abandoned or expires.',
		recommendation: 'Remove unused include mechanisms from the SPF record to reduce lookup waste and attack surface.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
	},
	SUBDOMAILING_INFO: {
		title: 'No SubdoMailing Risk Detected',
		severity: 'info',
		explanation:
			'All SPF include and redirect domains resolve correctly with no takeover indicators. The SPF include chain is secure for this check.',
		recommendation: 'Continue periodic audits of SPF include domains, especially after vendor changes.',
		references: ['https://guardio.co/blog/subdomailing', 'https://datatracker.ietf.org/doc/html/rfc7208'],
	},
	AUTHORITATIVE_DNS_INFRA_CRITICAL: {
		title: 'Authoritative DNS Infrastructure Exposure',
		severity: 'critical',
		explanation:
			'Authoritative DNS infrastructure evidence indicates a control failure such as route hijack signals, recursion exposure, missing authoritative response behavior, or unsafe zone-transfer handling.',
		impact:
			'Attackers may be able to disrupt or redirect authoritative DNS answers, weakening every service that depends on the affected name.',
		adverseConsequences:
			'Resolution outages, traffic interception, cache poisoning, and incident response escalation can occur if authoritative DNS remains exposed.',
		recommendation:
			'Review routing announcements, RPKI ROAs, authoritative server configuration, recursion policy, and zone-transfer ACLs. Confirm the issue from multiple vantage points before closing the incident.',
		references: [
			'https://www.rfc-editor.org/rfc/rfc1034',
			'https://www.rfc-editor.org/rfc/rfc1035',
			'https://www.rfc-editor.org/rfc/rfc8906',
			'https://datatracker.ietf.org/doc/html/rfc9115',
		],
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
		adverseConsequences:
			'Users may be sent to malicious destinations, causing credential theft, service disruption, and incident response costs.',
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
		adverseConsequences:
			'Credentials and sensitive data may be exposed, and browser trust warnings can reduce conversion and user confidence.',
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
		references: ['https://hstspreload.org/', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
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
		recommendation:
			'Maintain your current nameserver configuration. Use at least two geographically distributed nameservers for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035'],
	},
	NS_FAIL: {
		title: 'Nameserver Issues Detected',
		severity: 'fail',
		explanation:
			'One or more nameservers for this domain are not responding or are misconfigured, which can cause DNS resolution failures.',
		impact: 'Resolvers may fail to resolve the domain, degrading access to web, API, and mail services.',
		adverseConsequences: 'Users can experience outages, failed transactions, and business continuity disruptions.',
		recommendation:
			'Verify all listed nameservers are operational and properly configured. Ensure NS records match those at the registrar.',
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
		explanation:
			'CAA (Certificate Authority Authorization) records are properly configured, restricting which CAs can issue certificates for this domain.',
		recommendation: 'Maintain your CAA records. Review periodically to ensure they reflect your current certificate issuance needs.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
	},
	CAA_FAIL: {
		title: 'No CAA Records Found',
		severity: 'fail',
		explanation:
			'No CAA records are present for this domain. Without CAA, any certificate authority can issue certificates for your domain.',
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
		recommendation:
			'Review your CAA records and add an iodef tag for incident reporting. Consider restricting wildcard certificate issuance separately.',
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
		explanation:
			'No MX records are present for this domain. Without MX records, email delivery to this domain will fail or fall back to A record delivery.',
		impact: 'Mail routing is unreliable or unavailable for intended recipients on this domain.',
		adverseConsequences: 'Inbound communications may be lost, causing business disruption and missed security notifications.',
		recommendation:
			'Add MX records pointing to your mail server. If this domain does not handle email, consider adding a null MX record (0 .).',
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
		explanation: 'No MX records are present for this domain. Email delivery will fall back to A record delivery or fail entirely.',
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
		references: ['https://datatracker.ietf.org/doc/html/rfc6698', 'https://datatracker.ietf.org/doc/html/rfc7671'],
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
		references: ['https://datatracker.ietf.org/doc/html/rfc6698', 'https://datatracker.ietf.org/doc/html/rfc7671'],
	},
	DANE_HTTPS_WARNING: {
		title: 'DANE HTTPS Configuration Warning',
		severity: 'warning',
		explanation:
			'DANE TLSA records exist for the HTTPS endpoint but the configuration has issues that reduce their security value, such as DANE without DNSSEC or weak matching types.',
		impact: 'DANE protection is partially effective but can be bypassed or subverted.',
		adverseConsequences:
			'Attackers may be able to spoof or modify TLSA records if DNSSEC is absent, negating the security benefit of DANE.',
		recommendation: 'Enable DNSSEC on the domain and use DANE-EE (usage 3) with SHA-256 matching (type 1) for best security.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6698', 'https://datatracker.ietf.org/doc/html/rfc7671'],
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
		references: ['https://datatracker.ietf.org/doc/html/rfc9460', 'https://datatracker.ietf.org/doc/html/rfc8446'],
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
		adverseConsequences: 'Performance benefits from SVCB are partially lost and ECH privacy may be unavailable.',
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
	// --- Intelligence tools ---
	DBL_LISTED: {
		title: 'Domain Listed on Blocklist',
		severity: 'high',
		explanation:
			'The domain appears on one or more DNS-based Domain Block Lists (DBLs), indicating it has been flagged for spam, phishing, or malware distribution.',
		impact: 'Listed domains may have email deliverability issues and are often blocked by recipient mail servers.',
		adverseConsequences: 'Legitimate email from this domain may be silently dropped or quarantined.',
		recommendation:
			'Investigate the listing reason. For Spamhaus DBL, check https://check.spamhaus.org/. Request delisting after resolving the underlying issue.',
		references: ['https://www.spamhaus.org/dbl/', 'https://uribl.com/', 'https://www.surbl.org/'],
	},
	RBL_LISTED: {
		title: 'IP Listed on Real-time Blocklist',
		severity: 'high',
		explanation:
			'One or more mail server IPs are listed on DNS-based Real-time Blocklists, indicating the IP has been flagged for sending spam or malicious traffic.',
		impact: 'Email from listed IPs is likely to be rejected or quarantined by recipient servers.',
		adverseConsequences: 'Significant email deliverability degradation. May require IP change or delisting process.',
		recommendation:
			'Check Spamhaus at https://check.spamhaus.org/. For shared hosting, contact your provider. For dedicated IPs, resolve the abuse issue and request delisting.',
		references: ['https://www.spamhaus.org/zen/', 'https://www.spamcop.net/'],
	},
	REALTIME_THREAT_FEED_HIT: {
		title: 'Realtime Threat-Feed Match',
		severity: 'high',
		explanation:
			'BlackVeil realtime threat intelligence has matched this domain against a curated intel-gateway feed. This indicates active or recent malicious activity observed across the threat landscape.',
		impact:
			'Domains matching the realtime threat feed may be engaged in phishing, malware distribution, C2 communication, or other active threat campaigns.',
		adverseConsequences:
			'Continued operation on a threat-feed matched domain risks automated blocking by security products, email delivery failures, and reputational damage.',
		recommendation:
			'Investigate the specific finding detail for context on the threat type. If this is a false positive, use the BlackVeil threat intelligence portal to submit a review request.',
		references: ['https://blackveilsecurity.com/threat-intelligence'],
	},
	ASN_HIGH_RISK: {
		title: 'High-Risk ASN Detected',
		severity: 'medium',
		explanation:
			'The domain resolves to IP addresses in an Autonomous System commonly associated with abuse infrastructure (bulletproof hosting, botnets).',
		recommendation:
			'Verify the hosting choice is intentional. High-risk ASNs are not inherently malicious but are statistically over-represented in abuse reports.',
		references: ['https://www.team-cymru.com/ip-asn-mapping'],
	},
	FAST_FLUX_DETECTED: {
		title: 'Fast-Flux Behavior Detected',
		severity: 'high',
		explanation:
			'The domain shows rapidly rotating IP addresses with very low TTLs, a technique commonly used by botnets and phishing operations to evade takedown.',
		impact: 'Fast-flux domains are a strong indicator of malicious infrastructure.',
		adverseConsequences: 'Associating with fast-flux infrastructure damages domain reputation and may trigger automated blocking.',
		recommendation:
			'Investigate immediately. If this is a CDN or legitimate load balancer, TTLs are typically higher and rotation patterns are predictable.',
		references: ['https://en.wikipedia.org/wiki/Fast_flux'],
	},
	DNSSEC_CHAIN_BROKEN: {
		title: 'DNSSEC Chain of Trust Broken',
		severity: 'high',
		explanation:
			'The DNSSEC chain of trust has a gap — a DS record exists at the parent zone but the corresponding DNSKEY is missing or mismatched at the child zone.',
		impact:
			'DNSSEC-validating resolvers will return SERVFAIL for this domain, causing complete resolution failure for security-conscious clients.',
		adverseConsequences: 'Domain may be unreachable for users behind DNSSEC-validating resolvers.',
		recommendation:
			'Ensure the DS record at the parent matches a DNSKEY at the child zone. Use `delv +vtrace` for detailed chain debugging.',
		references: ['https://datatracker.ietf.org/doc/html/rfc4033'],
	},
	NSEC_WALKABLE: {
		title: 'Zone Walkable (No NSEC3)',
		severity: 'high',
		explanation:
			'The zone does not appear to use NSEC3, meaning it likely uses plain NSEC records which allow full zone enumeration (zone walking).',
		impact: 'Attackers can discover all hostnames in the zone without brute-forcing, exposing internal infrastructure.',
		adverseConsequences: 'Complete zone enumeration reveals the attack surface — internal hosts, staging environments, and service names.',
		recommendation:
			'Deploy NSEC3 with at least algorithm 1 (SHA-1) and consider using salt. RFC 9276 recommends 0 iterations with no salt as the minimum.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5155', 'https://datatracker.ietf.org/doc/html/rfc9276'],
	},
	// ── Severity-keyed entries ───────────────────────────────────────────
	// Real scan findings carry a SEVERITY status (critical/high/medium/low/info),
	// not pass/fail/warning. These provide accurate, general-per-(type,severity)
	// content so explain_finding does not fall through to the generic DEFAULT
	// stub for the common check types. Each is phrased to be TRUE across every
	// distinct finding the corresponding check emits at that severity. We avoid
	// cross-family fallback (a "high" severity finding must not resolve a "_FAIL"
	// entry) because FAIL/MISSING means "control absent" while a severity finding
	// usually means "control present but weak" — conflating them is a falsehood.

	// DNSSEC — check emits high / medium / info.
	DNSSEC_HIGH: {
		title: 'DNSSEC Not Providing Protection',
		severity: 'high',
		explanation:
			'DNSSEC is not effectively protecting this domain — for example no DNSKEY records are published, the chain of trust is incomplete, or a deprecated signing algorithm (e.g. RSASHA1) is in use. Without working DNSSEC, DNS responses are not cryptographically authenticated.',
		impact: 'DNS responses can be forged in transit, enabling redirection to attacker-controlled infrastructure.',
		adverseConsequences:
			'Users may be sent to malicious destinations, causing credential theft, service disruption, and incident-response costs.',
		recommendation:
			'Enable DNSSEC at your registrar and DNS provider, ensure the parent DS record matches a published DNSKEY, and use a modern algorithm (e.g. ECDSAP256SHA256 / algorithm 13).',
		genericExplanation:
			'A high-severity DNSSEC issue was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match a defect this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Remediate the specific issue named in the finding detail. General DNSSEC guidance: keep a complete chain of trust (parent DS matching a published DNSKEY), sign with a modern algorithm, and verify validation from an external resolver after any change.',
		references: ['https://datatracker.ietf.org/doc/html/rfc4033', 'https://www.cloudflare.com/dns/dnssec/how-dnssec-works/'],
	},
	DNSSEC_MEDIUM: {
		title: 'DNSSEC Configuration Weakness',
		severity: 'medium',
		explanation:
			'DNSSEC is configured but a weakness was detected — for example a missing DS record at the parent, an unrecognized signing algorithm, or a SHA-1 DS digest. These reduce the strength or completeness of the chain of trust.',
		impact: 'The cryptographic assurance of DNS responses is weaker than intended and may not validate everywhere.',
		adverseConsequences: 'Some resolvers may fail validation or accept weakly-protected responses, partially undermining DNSSEC.',
		recommendation:
			'Publish a DS record at the parent that matches a current DNSKEY, use a modern algorithm, and prefer SHA-256 (digest type 2) over SHA-1 for DS records.',
		genericExplanation:
			'A medium-severity DNSSEC weakness was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match a weakness this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Remediate the specific weakness named in the finding detail. General DNSSEC guidance: keep the parent DS in sync with a current DNSKEY, use a modern signing algorithm, and prefer SHA-256 DS digests.',
		references: ['https://datatracker.ietf.org/doc/html/rfc4033', 'https://datatracker.ietf.org/doc/html/rfc8624'],
	},

	// SPF — check emits critical / high / medium / low / info.
	SPF_CRITICAL: {
		title: 'SPF Policy Critically Permissive or Broken',
		severity: 'critical',
		explanation:
			'A critical SPF problem was detected — for example a "+all" mechanism that authorizes every server on the internet, or the record exceeding the 10 DNS-lookup limit (which causes a PermError that voids the policy). Either way the SPF policy fails to constrain who may send as the domain.',
		impact: 'Unauthorized senders can pass SPF as the domain, or SPF evaluation fails entirely.',
		adverseConsequences:
			'Spoofing and phishing from the domain become trivial, and legitimate mail may also be rejected when SPF PermErrors.',
		recommendation:
			'Remove "+all" (use "-all" or "~all"), and consolidate includes/flattening so the record stays under 10 DNS lookups (RFC 7208 §4.6.4).',
		genericExplanation:
			'A critical SPF problem was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match a defect this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Remediate the specific problem named in the finding detail. General SPF guidance: publish exactly one v=spf1 record, keep the recursive DNS-lookup count within the RFC 7208 §4.6.4 limit of 10, scope ip4/ip6 mechanisms to hosts you actually send from, and terminate with "-all" (or "~all" alongside an enforcing DMARC policy).',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
	},
	SPF_HIGH: {
		title: 'SPF Policy Weakness',
		severity: 'high',
		explanation:
			'A high-severity SPF issue was detected — for example multiple SPF records (RFC 7208 permits exactly one, so receivers behave unpredictably) or an overly broad IP range that authorizes far more hosts than intended.',
		impact: 'SPF becomes ambiguous or over-permissive, letting unauthorized senders appear legitimate.',
		adverseConsequences: 'Spoofing risk rises and deliverability can become inconsistent across receivers.',
		recommendation:
			'Publish exactly one SPF record and tighten over-broad ip4/ip6 ranges to the specific sending hosts your providers use.',
		genericExplanation:
			'A high-severity SPF issue was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match a defect this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Remediate the specific issue named in the finding detail. General SPF guidance: publish exactly one v=spf1 record, keep the recursive DNS-lookup count within the RFC 7208 §4.6.4 limit of 10, scope ip4/ip6 mechanisms to hosts you actually send from, and terminate with "-all" (or "~all" alongside an enforcing DMARC policy).',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
	},
	SPF_MEDIUM: {
		title: 'SPF Hardening Recommended',
		severity: 'medium',
		explanation:
			'A medium-severity SPF issue was detected — for example use of the deprecated "ptr" mechanism (RFC 7208 §5.5) or a configuration that weakens the policy without breaking it.',
		impact: 'SPF protection is weaker or less reliable than recommended.',
		adverseConsequences: 'Edge-case authentication failures and unnecessary attack surface can persist over time.',
		recommendation:
			'Remove deprecated mechanisms such as "ptr" and prefer explicit ip4/ip6/include mechanisms with a "-all" or "~all" terminator.',
		genericExplanation:
			'A medium-severity SPF issue was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match a defect this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Remediate the specific issue named in the finding detail. General SPF guidance: prefer explicit ip4/ip6/include mechanisms over deprecated ones, keep the record within the RFC 7208 §4.6.4 10-lookup limit, and terminate with "-all" or "~all".',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
	},
	SPF_LOW: {
		title: 'SPF Soft Fail / Minor Issue',
		severity: 'low',
		explanation:
			'A low-severity SPF observation — typically a "~all" soft-fail terminator. Soft fail accepts but flags failing mail; it is acceptable alongside an enforcing DMARC policy but is weaker than "-all" on its own.',
		impact: 'Mail that fails SPF may still be accepted rather than rejected at the SMTP layer.',
		adverseConsequences: 'Some spoofed mail can reach recipients unless DMARC enforcement compensates.',
		recommendation: 'Use "-all" for strict enforcement, or keep "~all" only when a DMARC policy of quarantine/reject handles failures.',
		genericExplanation:
			'A low-severity SPF observation was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match an observation this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Address the specific observation named in the finding detail. General SPF guidance: keep the record to a single v=spf1 TXT entry, within the RFC 7208 §4.6.4 10-lookup limit, with tightly scoped mechanisms and an explicit "-all" or "~all" terminator.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-8.1'],
	},

	// DMARC — check emits critical / high / medium / low / info.
	DMARC_CRITICAL: {
		title: 'DMARC Critically Misconfigured',
		severity: 'critical',
		explanation:
			'A critical DMARC problem was detected that leaves the domain effectively unprotected against spoofing despite a record being present.',
		impact: 'Forged messages failing authentication are not reliably blocked by receivers.',
		adverseConsequences: 'Large-scale impersonation of the domain becomes feasible, harming users and brand trust.',
		recommendation:
			'Correct the DMARC record to a single valid policy with an explicit, enforcing p= tag (quarantine or reject) and monitor aggregate reports.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489'],
	},
	DMARC_HIGH: {
		title: 'DMARC Not Enforcing or Invalid',
		severity: 'high',
		explanation:
			'A high-severity DMARC issue was detected — for example p=none (monitoring only), multiple DMARC records, a missing p= tag, or an invalid policy value. In each case the domain is not actively protected against spoofing.',
		impact: 'Receiving systems are not instructed to reject or quarantine forged messages that fail authentication.',
		adverseConsequences: 'Domain spoofing reaches inboxes more often, increasing phishing exposure and reputational damage.',
		recommendation:
			'Publish exactly one valid DMARC record with an explicit p= tag and progress toward p=quarantine then p=reject after reviewing aggregate reports.',
		genericExplanation:
			'A high-severity DMARC issue was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match a defect this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Remediate the specific issue named in the finding detail. General DMARC guidance: publish exactly one valid record at _dmarc.<domain> with an explicit enforcing p= tag and an rua= address, and review aggregate reports before tightening further.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489', 'https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/'],
	},
	DMARC_MEDIUM: {
		title: 'DMARC Coverage Gap',
		severity: 'medium',
		explanation:
			'A medium-severity DMARC gap was detected — for example no aggregate report URI (rua=), pct< 100 (partial enforcement), or a subdomain policy (sp=) weaker than the organizational policy.',
		impact: 'DMARC enforcement or visibility is incomplete, leaving observable or exploitable gaps.',
		adverseConsequences: 'Spoofing activity is harder to detect or only partially blocked, and subdomains may remain exposed.',
		recommendation: 'Add a rua= aggregate-reporting address, set pct=100, and ensure sp= is at least as strict as the parent policy.',
		genericExplanation:
			'A medium-severity DMARC gap was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match a gap this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Close the specific gap named in the finding detail. General DMARC guidance: keep a single valid record with an enforcing p=, full coverage (pct=100), an explicit sp= no weaker than the parent policy, and an rua= address for visibility.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_LOW: {
		title: 'DMARC Alignment / Reporting Refinement',
		severity: 'low',
		explanation:
			'A low-severity DMARC refinement was detected — for example relaxed alignment (adkim=r / aspf=r), no subdomain policy specified, or forensic reporting (ruf=) not configured. These do not disable DMARC but tighten or improve it.',
		impact: 'Alignment is looser or reporting is less complete than the strictest posture.',
		adverseConsequences: 'Borderline spoofing techniques may pass alignment and some diagnostic detail is unavailable.',
		recommendation:
			'Consider strict alignment (adkim=s, aspf=s), set an explicit sp=, and add a ruf= address if forensic reporting is desired and privacy-permissible.',
		genericExplanation:
			'A low-severity DMARC refinement was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match a refinement this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Apply the refinement named in the finding detail. General DMARC guidance: prefer strict alignment (adkim=s, aspf=s), set an explicit sp=, and keep reporting addresses current.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489'],
	},

	// DKIM — "key/configuration present but weak/revoked", NOT "no DKIM" (DKIM_FAIL).
	DKIM_CRITICAL: {
		title: 'DKIM Critically Weak Key',
		severity: 'critical',
		explanation:
			'A critically weak DKIM signing key was detected (for example an obsolete, trivially factorable key length). The signature provides little to no real authenticity assurance.',
		impact: 'DKIM signatures can be forged, defeating message-integrity protection.',
		adverseConsequences: 'Attackers can sign mail as the domain, enabling high-credibility impersonation.',
		recommendation: 'Immediately rotate to a strong key (RSA 2048-bit minimum or Ed25519) and revoke the weak selector.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376'],
	},
	DKIM_HIGH: {
		title: 'DKIM Key Weakness',
		severity: 'high',
		explanation:
			'A high-severity DKIM problem was detected with a published key — for example a key whose material is too short for its declared algorithm, or a similarly weak signing key. Weak keys undermine the integrity guarantee DKIM is meant to provide.',
		impact: 'DKIM signatures are easier to forge, weakening message-authenticity assurance.',
		adverseConsequences: 'Attackers can more plausibly impersonate the domain, increasing fraud and phishing risk.',
		recommendation:
			'Rotate to a strong key (RSA 2048-bit minimum, or Ed25519) that matches the declared algorithm, and retire weak selectors.',
		genericExplanation:
			'A high-severity DKIM issue was reported against a published selector. The finding detail supplied with this request is the authoritative description of what was observed — it does not match a defect this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Remediate the specific issue named in the finding detail. General DKIM guidance: sign with RSA 2048-bit (or Ed25519) keys, publish a well-formed v=DKIM1 record per active selector, and retire selectors that are no longer in use.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376', 'https://datatracker.ietf.org/doc/html/rfc8463'],
	},
	DKIM_MEDIUM: {
		title: 'DKIM Configuration Issue',
		severity: 'medium',
		explanation:
			'A medium-severity DKIM issue was detected on a published selector — for example a below-recommended (sub-2048-bit) RSA key, a revoked key (empty p=), a missing v= tag, or an unrecognized key type.',
		impact: 'DKIM verification may be weaker, ambiguous, or fail for the affected selector.',
		adverseConsequences: 'Message-authenticity confidence drops and some legitimate mail may be distrusted.',
		recommendation:
			'Use a 2048-bit RSA key (or Ed25519), include the v=DKIM1 tag, remove revoked/empty selectors, and use a recognized key type.',
		genericExplanation:
			'A medium-severity DKIM issue was reported against a published selector. The finding detail supplied with this request is the authoritative description of what was observed — it does not match a defect this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Remediate the specific issue named in the finding detail. General DKIM guidance: sign with RSA 2048-bit (or Ed25519) keys, publish a well-formed v=DKIM1 record per active selector, and remove selectors that are revoked or unused.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376'],
	},
	DKIM_LOW: {
		title: 'DKIM Testing Mode / Minor Issue',
		severity: 'low',
		explanation:
			'A low-severity DKIM observation — typically a selector left in testing mode (t=y), which tells receivers to treat signatures as experimental.',
		impact: 'Receivers may not fully act on DKIM results for the affected selector.',
		adverseConsequences: 'The intended authentication benefit is reduced while testing mode remains set.',
		recommendation: 'Remove the t=y testing flag once the selector is verified to be signing correctly.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376'],
	},

	// MTA-STS — check emits high / medium / low / info.
	MTA_STS_HIGH: {
		title: 'MTA-STS Policy Broken',
		severity: 'high',
		explanation:
			'A high-severity MTA-STS problem was detected — for example the policy file is not accessible over HTTPS (e.g. HTTP 404) despite a TXT record advertising it. A broken policy cannot enforce TLS for inbound mail.',
		impact: 'Inbound SMTP cannot be reliably protected against TLS downgrade attacks.',
		adverseConsequences: 'Email content may traverse the network unencrypted and be exposed to interception.',
		recommendation:
			'Host a valid policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt with a matching id in the TXT record, served with a valid certificate.',
		genericExplanation:
			'A high-severity MTA-STS problem was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match a defect this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Remediate the specific problem named in the finding detail. General MTA-STS guidance: the _mta-sts TXT record, the policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt, and the MX hosts it lists must all agree, and the policy host must serve a valid certificate.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	MTA_STS_MEDIUM: {
		title: 'MTA-STS Not Enforcing',
		severity: 'medium',
		explanation:
			'A medium-severity MTA-STS issue was detected — for example neither MTA-STS nor TLS-RPT is present, or the policy mode is "none". TLS for inbound mail is therefore not enforced.',
		impact: 'Inbound mail transport is not protected against active downgrade to cleartext.',
		adverseConsequences: 'Confidential email can be intercepted in transit, raising compliance and privacy risk.',
		recommendation: 'Publish an MTA-STS policy in mode=testing then mode=enforce, and add TLS-RPT (_smtp._tls) for visibility.',
		genericExplanation:
			'A medium-severity MTA-STS issue was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match an issue this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Remediate the specific issue named in the finding detail. General MTA-STS guidance: publish a policy in mode=testing, promote it to mode=enforce once reports are clean, and keep TLS-RPT (_smtp._tls) published for visibility.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461', 'https://datatracker.ietf.org/doc/html/rfc8460'],
	},
	MTA_STS_LOW: {
		title: 'MTA-STS Refinement',
		severity: 'low',
		explanation:
			'A low-severity MTA-STS observation — for example mode=testing (monitoring only), a short max_age, or a missing TLS-RPT record. The control is present but not at its strongest.',
		impact: 'TLS enforcement is partial or short-lived, or reporting visibility is missing.',
		adverseConsequences: 'Downgrade protection is weaker than it could be until the policy is fully enforced.',
		recommendation: 'Move to mode=enforce, set a max_age of at least 604800 (1 week), and publish a TLS-RPT record.',
		genericExplanation:
			'A low-severity MTA-STS observation was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match an observation this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Address the specific observation named in the finding detail. General MTA-STS guidance: run mode=enforce with a max_age of at least 604800 (1 week) and keep a TLS-RPT record published.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},

	// CAA — check emits medium / low.
	CAA_MEDIUM: {
		title: 'CAA Issuance Controls Incomplete',
		severity: 'medium',
		explanation:
			'A medium-severity CAA issue was detected — for example no CAA records at all, or CAA records present without a usable "issue" tag. Without effective CAA, any certificate authority may issue certificates for the domain.',
		impact: 'Certificate-issuance controls are broad, increasing the chance of unauthorized or mis-issued certificates.',
		adverseConsequences: 'Attackers could obtain a valid certificate for impersonation or interception.',
		recommendation:
			'Publish CAA records restricting issuance to your authorized CAs (e.g. 0 issue "letsencrypt.org") and add an iodef contact.',
		genericExplanation:
			'A medium-severity CAA issue was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match an issue this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Remediate the specific issue named in the finding detail. General CAA guidance: restrict issuance to the CAs you actually use, keep the record set in step with every certificate source, and add an iodef contact.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659', 'https://www.cloudflare.com/learning/dns/dns-records/dns-caa-record/'],
	},
	CAA_LOW: {
		title: 'CAA Hardening Recommended',
		severity: 'low',
		explanation:
			'A low-severity CAA observation — for example a missing "issuewild" restriction or no "iodef" incident-reporting tag. The base policy works but could be tightened.',
		impact: 'Wildcard issuance or incident reporting is not fully constrained.',
		adverseConsequences: 'Certificate governance is slightly weaker than recommended.',
		recommendation: 'Add an issuewild restriction and an iodef tag for incident notifications.',
		genericExplanation:
			'A low-severity CAA observation was reported. The finding detail supplied with this request is the authoritative description of what was observed — it does not match an observation this library recognises, so no specific cause is asserted here.',
		genericRecommendation:
			'Address the specific observation named in the finding detail. General CAA guidance: keep issuance restricted to the CAs you use, constrain wildcard issuance, and publish an iodef contact.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
	},

	// DANE — check emits medium / low.
	DANE_MEDIUM: {
		title: 'DANE TLSA Missing or Misconfigured',
		severity: 'medium',
		explanation:
			'A medium-severity DANE issue was detected — for example no TLSA records pinning the service certificate/key, or TLSA present without DNSSEC (which leaves the pins unauthenticated and spoofable).',
		impact: 'Certificate trust relies on the public CA system without an authenticated DNS-level pin.',
		adverseConsequences: 'A compromised or mis-issuing CA could present a fraudulent certificate, enabling MITM attacks.',
		recommendation:
			'Enable DNSSEC and publish DANE-EE (usage 3) TLSA records with SHA-256 matching (type 1) for the relevant service ports.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6698', 'https://datatracker.ietf.org/doc/html/rfc7671'],
	},
	DANE_LOW: {
		title: 'DANE Hardening Recommended',
		severity: 'low',
		explanation:
			'A low-severity DANE observation — TLSA records are present but a parameter could be improved (for example a weaker matching type or non-EE usage).',
		impact: 'DANE protection is effective but not at its strongest, widely-interoperable configuration.',
		adverseConsequences: 'Minor reduction in the robustness of certificate pinning.',
		recommendation: 'Prefer DANE-EE (usage 3) with SHA-256 matching (type 1).',
		references: ['https://datatracker.ietf.org/doc/html/rfc7671'],
	},

	// TLS-RPT — check emits medium / low / info.
	TLSRPT_MEDIUM: {
		title: 'TLS-RPT Reporting Absent',
		severity: 'medium',
		explanation:
			'A medium-severity TLS-RPT issue was detected — typically no SMTP TLS Reporting (RFC 8460) record at _smtp._tls.<domain>. TLS-RPT is operational telemetry, not an enforcement control: it does not block anything, it tells you when senders failed to negotiate TLS or when your MTA-STS policy could not be applied.',
		impact:
			'Inbound TLS negotiation failures and MTA-STS policy failures are not reported back to you, so there is no feedback loop for operating MTA-STS or DANE.',
		adverseConsequences:
			'An MTA-STS or DANE rollout is run blind — breakage surfaces only as mail that silently fails to arrive, which is the usual reason enforcement gets rolled back instead of fixed. The security benefit is indirect: reports are what make it safe to keep the enforcing controls turned on.',
		recommendation:
			'Publish a TXT record at _smtp._tls.<domain> such as: v=TLSRPTv1; rua=mailto:tls-reports@<domain>, and review the reports when moving MTA-STS from testing to enforce.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8460'],
	},
	TLSRPT_LOW: {
		title: 'TLS-RPT Refinement',
		severity: 'low',
		explanation:
			'A low-severity TLS-RPT observation — a reporting record exists but a detail (such as the reporting destination) could be improved.',
		impact: 'Reporting coverage is present but incomplete, so some TLS/MTA-STS failure telemetry may not reach you.',
		adverseConsequences:
			'Delivery-security regressions may take longer to notice. TLS-RPT blocks nothing on its own — its value is the operational feedback that keeps MTA-STS and DANE safely enforced.',
		recommendation: 'Ensure the rua= destination is monitored and correctly formatted.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8460'],
	},

	// BIMI — check emits high / medium / low / info.
	BIMI_HIGH: {
		title: 'BIMI Logo Invalid or Unsafe',
		severity: 'high',
		explanation:
			'A high-severity BIMI logo problem was detected — for example the SVG logo contains prohibited <script> elements. BIMI logos must be script-free SVG Tiny PS; mail clients will reject a non-conformant or unsafe logo.',
		impact: 'The brand logo will be rejected by mail clients, and a script-bearing SVG is a content-safety concern.',
		adverseConsequences:
			'BIMI provides no brand-presentation benefit, and serving an unsafe SVG could expose downstream consumers to script content. Note that BIMI is a brand-presentation control: there is no controlled evidence that it reduces phishing susceptibility, and a verified logo renders on any message that passes DMARC for the domain — including mail sent from a compromised mailbox.',
		recommendation:
			'Serve a valid SVG Tiny PS logo with no <script> elements over HTTPS, and re-validate it against the BIMI logo profile.',
		references: ['https://datatracker.ietf.org/doc/html/draft-blank-ietf-bimi', 'https://bimigroup.org/'],
	},
	BIMI_MEDIUM: {
		title: 'BIMI Not Effective',
		severity: 'medium',
		explanation:
			'A medium-severity BIMI issue was detected — for example a BIMI record present but DMARC not enforcing (p=quarantine/reject is required for BIMI to display), a logo that is too large (>32 KB), a wrong Content-Type, or a missing SVG Tiny PS baseProfile.',
		impact: 'The brand logo will not display at supporting mailbox providers despite a BIMI record being present.',
		adverseConsequences:
			'The intended brand-presentation benefit of BIMI is not realized until the prerequisite (enforcing DMARC) and logo requirements are met. Note that BIMI is a brand-presentation control: there is no controlled evidence that it reduces phishing susceptibility, and a verified logo renders on any message that passes DMARC for the domain — including mail sent from a compromised mailbox.',
		recommendation:
			'Bring DMARC to an enforcing policy (p=quarantine or p=reject), and serve a conformant SVG Tiny PS logo (<32 KB, correct Content-Type, baseProfile="tiny-ps").',
		references: ['https://datatracker.ietf.org/doc/html/draft-blank-ietf-bimi', 'https://bimigroup.org/'],
	},
	BIMI_LOW: {
		title: 'BIMI Refinement',
		severity: 'low',
		explanation:
			'A low-severity BIMI observation — the record is largely in place but a detail (such as an optional mark certificate or logo metadata) could be improved.',
		impact: 'BIMI works but is not at its most complete configuration.',
		adverseConsequences:
			'Minor reduction in display coverage across providers. Note that BIMI is a brand-presentation control: there is no controlled evidence that it reduces phishing susceptibility, and a verified logo renders on any message that passes DMARC for the domain — including mail sent from a compromised mailbox. Weigh the mark-certificate cost against that, and keep BIMI as a brand-presentation investment rather than an anti-phishing one.',
		recommendation:
			'Consider adding a mark certificate, and ensure the logo metadata meets each target provider requirements. Gmail displays BIMI logos backed by either a Verified Mark Certificate (VMC) or the lower-cost Common Mark Certificate (CMC); Apple Mail accepts a VMC only, so pick the certificate type from the providers you need to cover. Check current issuers (DigiCert, for example) before purchasing, as the market changes.',
		references: ['https://bimigroup.org/'],
	},
	BRAND_DISCOVERY_INFO: {
		title: 'Candidate Brand Domain Surfaced',
		severity: 'info',
		explanation:
			'A discovery signal (TLS SAN co-ownership, NS-record overlap, DMARC RUA addressee, or DKIM key reuse) suggests this domain is part of the same brand portfolio as the seed.',
		recommendation:
			"Add the candidate to the customer's known portfolio after confirming ownership via the registrar account or a side-channel. Schedule a security scan once it is confirmed in scope.",
		references: ['https://crt.sh', 'https://datatracker.ietf.org/doc/html/rfc7489', 'https://datatracker.ietf.org/doc/html/rfc6376'],
	},
	BRAND_DISCOVERY_LOW: {
		title: 'High-Confidence Brand Domain Match',
		severity: 'low',
		explanation:
			'Multiple independent discovery signals corroborate that this domain shares operational ownership with the seed (combined confidence ≥ 0.85). Examples include matching DKIM public keys plus shared NS pools, or SAN co-issuance plus DMARC RUA reuse.',
		impact:
			'Without expanding the security scope to include this domain, deficiencies (DMARC, DKIM, certificate hygiene) on it can still be exploited to spoof or attack the parent brand.',
		recommendation:
			"Verify ownership with the registrar account holder. If owned, run a full scan and apply the customer's baseline hardening policy. If not owned but using shared mail/cert infrastructure, audit the shared-tenant boundary.",
		references: ['https://crt.sh', 'https://datatracker.ietf.org/doc/html/rfc6376', 'https://datatracker.ietf.org/doc/html/rfc7489'],
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
	realtime_threat_feed: 'REALTIME_THREAT_FEED',
	bucket_scan: 'BUCKET_SCAN',
	osint_investigation: 'OSINT_INVESTIGATION',
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
	subdomailing: 'SUBDOMAILING',
	dane_https: 'DANE_HTTPS',
	dane: 'DANE',
	ptr: 'PTR',
	tlsrpt: 'TLSRPT',
	bimi: 'BIMI',
	svcb_https: 'SVCB_HTTPS',
	brand_discovery: 'BRAND_DISCOVERY',
	dnskey_strength: 'DNSKEY_STRENGTH',
};

export const CATEGORY_FALLBACK_IMPACT: Record<string, ImpactNarrative> = {
	DNSKEY_STRENGTH: {
		impact: 'DNSKEY signing algorithms are weak or deprecated, reducing the cryptographic assurance DNSSEC provides.',
		adverseConsequences:
			'Forged DNS responses become easier to construct, allowing attackers to redirect traffic despite DNSSEC being deployed.',
	},
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
	SUBDOMAILING: {
		impact: 'SPF include chain references a takeover-vulnerable domain, potentially allowing unauthorized email sending.',
		adverseConsequences: 'Attackers could send authenticated phishing emails from the trusted domain, bypassing email security controls.',
	},
	DANE_HTTPS: {
		impact: 'HTTPS certificate pinning via DANE is absent or misconfigured, leaving TLS trust dependent solely on the CA system.',
		adverseConsequences: 'A rogue or compromised CA can issue a fraudulent certificate, enabling undetected MITM attacks.',
	},
	SVCB_HTTPS: {
		impact: 'Modern transport capabilities (ALPN, ECH) cannot be advertised via DNS, reducing connection efficiency and privacy.',
		adverseConsequences: 'Clients require additional round-trips to negotiate protocols, and ECH-based privacy is unavailable.',
	},
	DANE: {
		impact: 'Certificate/key pinning via DANE is absent or weak, leaving TLS trust dependent solely on the public CA system.',
		adverseConsequences: 'A rogue or compromised CA can issue a fraudulent certificate, enabling undetected MITM attacks.',
	},
	PTR: {
		impact: 'Mail-server IPs lack forward-confirmed reverse DNS (PTR/FCrDNS), weakening sender reputation.',
		adverseConsequences: 'Outbound mail is more likely to be greylisted, throttled, or rejected by strict receivers.',
	},
	TLSRPT: {
		impact:
			'TLS negotiation failures and MTA-STS policy failures for inbound mail are not reported, so there is no feedback loop for operating MTA-STS or DANE.',
		adverseConsequences:
			'Delivery-security regressions surface as silently undelivered mail rather than as a report. TLS-RPT is telemetry, not enforcement — it blocks nothing itself, but without it an enforcing transport policy is operated blind and tends to get rolled back after an outage.',
	},
	BIMI: {
		impact: 'No verified brand logo is displayed on authenticated mail, so the domain gains no branded inbox presentation.',
		adverseConsequences:
			'Brand recognizability in the inbox is reduced. BIMI is a brand-presentation control: there is no controlled evidence that it reduces phishing susceptibility, and a verified logo renders on any message that passes DMARC for the domain — including mail sent from a compromised mailbox.',
	},
	RBL: {
		impact: 'Mail server IPs are listed on one or more DNS blocklists, likely degrading email deliverability.',
		adverseConsequences: 'Outbound email may be silently dropped or quarantined by recipient servers.',
	},
	DBL: {
		impact: 'Domain is flagged on DNS-based domain blocklists, indicating prior spam or abuse association.',
		adverseConsequences: 'Domain reputation is damaged. Email and web traffic may be blocked by security tools.',
	},
	FAST_FLUX: {
		impact: 'DNS resolution shows fast-flux patterns — rapidly rotating IPs with low TTLs.',
		adverseConsequences: 'Strong indicator of botnet or phishing infrastructure. Domain reputation will be severely impacted.',
	},
	DNSSEC_CHAIN: {
		impact: 'DNSSEC chain structure has gaps or uses weak algorithms, reducing trust in DNS responses.',
		adverseConsequences: 'DNSSEC-validating resolvers may fail to resolve the domain or accept spoofed responses.',
	},
	NSEC_WALKABILITY: {
		impact: 'Zone denial-of-existence parameters allow enumeration of zone contents.',
		adverseConsequences: 'Attackers can map the full attack surface by walking the zone without brute-forcing.',
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

/**
 * Recognised finding signatures, matched against the caller-supplied `details`
 * string within a checkType. FIRST MATCH WINS, so order more specific patterns
 * before broader ones (e.g. the DMARC subdomain-policy rule precedes the
 * p=none rule, because the sp= finding detail also quotes the inherited policy).
 *
 * Patterns must not carry the /g flag — a global regex keeps `lastIndex`
 * between `.test()` calls and would match intermittently.
 */
export const DETAIL_SIGNATURES: DetailSignatureRule[] = [
	// ---------------------------------------------------------------- SPF ---
	{
		id: 'SPF_LOOKUP_LIMIT',
		checkType: 'SPF',
		// "SPF record requires 12 DNS lookups (limit: 10)" / "requires 10/10 DNS lookups"
		// / "Too many DNS lookups" / "SPF lookup budget near limit" / PermError wording.
		pattern: /too many dns lookups|\d+\s*\/\s*10\s*dns lookups|dns lookups?\s*\(limit|lookup (?:budget|limit)|permerror/i,
		template: {
			title: 'SPF DNS-Lookup Limit Reached or Exceeded',
			explanation:
				'RFC 7208 §4.6.4 caps an SPF evaluation at 10 DNS-querying mechanisms (include, a, mx, ptr, exists and redirect, counted recursively through every included record). This record is at or over that budget. Once the limit is exceeded receivers return PermError and the SPF policy is treated as unusable — it stops authorising legitimate senders as well as blocking forged ones. At exactly the limit there is no headroom: the next sender added anywhere in the include chain (including inside a provider record you do not control) pushes the domain into permanent failure.',
			impact:
				'SPF evaluation is one added include away from PermError — or already failing — so the domain gets no reliable SPF result at receivers.',
			adverseConsequences:
				'Legitimate mail can be rejected or spam-foldered, and because DMARC cannot rely on an SPF PermError the domain also loses that half of its anti-spoofing protection.',
			recommendation:
				'Reduce the recursive DNS-lookup count below 10: remove includes for providers you no longer send from, replace deep include chains with the specific ip4/ip6 ranges they resolve to (flattening, with a process to refresh them), and consolidate multiple provider includes onto one sending platform where possible. Use resolve_spf_chain to see which include contributes each lookup. Do NOT add a second SPF record to make room — RFC 7208 permits exactly one.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4', 'https://datatracker.ietf.org/doc/html/rfc7208'],
		},
	},
	{
		id: 'SPF_MULTIPLE_RECORDS',
		checkType: 'SPF',
		pattern: /multiple spf records|more than one spf record|found \d+ spf records/i,
		template: {
			title: 'Multiple SPF Records Published',
			explanation:
				'More than one v=spf1 TXT record is published for this domain. RFC 7208 permits exactly one; when receivers find several they must treat the result as PermError, so the domain effectively has no usable SPF policy.',
			impact: 'SPF evaluation is ambiguous or fails outright, so neither authorised senders nor forged ones are reliably distinguished.',
			adverseConsequences: 'Spoofed mail passes unchallenged while legitimate mail can be rejected, and DMARC loses its SPF input.',
			recommendation:
				'Merge every mechanism into a single v=spf1 TXT record and delete the others, keeping the merged record within the RFC 7208 §4.6.4 10-lookup limit.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-3.2', 'https://datatracker.ietf.org/doc/html/rfc7208'],
		},
	},
	{
		id: 'SPF_PERMISSIVE_ALL',
		checkType: 'SPF',
		pattern: /\+all|permissive spf|allows? any (?:server|host)/i,
		template: {
			title: 'SPF Authorises Every Sender ("+all")',
			explanation:
				'The record terminates with "+all" (or an equivalent permissive qualifier), which explicitly authorises every host on the internet to send mail as this domain. This is strictly worse than publishing no SPF record at all, because forged mail collects an SPF pass.',
			impact: 'Any sender anywhere passes SPF for the domain.',
			adverseConsequences:
				'Phishing that appears authenticated is trivial to send, and an SPF-aligned pass can satisfy DMARC, defeating enforcement entirely.',
			recommendation:
				'Replace "+all" with "-all" (hard fail) after confirming every legitimate sending source is listed, or "~all" while a DMARC policy of quarantine/reject handles failures.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-5.1', 'https://datatracker.ietf.org/doc/html/rfc7208'],
		},
	},
	{
		id: 'SPF_BROAD_IP_RANGE',
		checkType: 'SPF',
		pattern: /overly broad ip|extremely large ip(?:v6)? range|broad ip(?:v6)? range/i,
		template: {
			title: 'SPF Authorises an Over-Broad IP Range',
			explanation:
				'The record contains an ip4/ip6 mechanism with a very short prefix, authorising far more hosts than the domain actually sends from — often an entire hosting provider or transit network whose addresses are shared with unrelated tenants.',
			impact: 'Any host inside the authorised range — including systems the domain does not operate — can pass SPF as the domain.',
			adverseConsequences: 'A neighbour or compromised host in the same range can send authenticated-looking mail as the domain.',
			recommendation:
				"Narrow each ip4/ip6 mechanism to the specific addresses or small prefixes your sending hosts use, or replace the literal range with the provider's own include: mechanism so they maintain it.",
			references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-5.6', 'https://datatracker.ietf.org/doc/html/rfc7208'],
		},
	},
	{
		id: 'SPF_CIRCULAR_INCLUDE',
		checkType: 'SPF',
		pattern: /circular (?:spf )?include|circular reference/i,
		template: {
			title: 'Circular SPF Include Chain',
			explanation:
				'An include chain loops back on itself, so evaluation never terminates normally. Receivers abort with PermError, and the SPF policy provides no result.',
			impact: 'SPF cannot be evaluated for this domain at all.',
			adverseConsequences:
				'Legitimate mail loses SPF authentication and DMARC loses its SPF input, while forged mail is not blocked by SPF.',
			recommendation:
				'Trace the include chain (resolve_spf_chain) and break the loop by removing the include that points back into an ancestor record.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4', 'https://datatracker.ietf.org/doc/html/rfc7208'],
		},
	},
	{
		id: 'SPF_NO_RECORD',
		checkType: 'SPF',
		pattern: /no spf(?: \(v=spf1\))? (?:txt )?record found|no spf record/i,
		template: {
			title: 'No SPF Record Published',
			explanation:
				"No v=spf1 TXT record was found for this domain. Without one, receivers have no list of authorised sending hosts, so nothing distinguishes the domain's own mail from mail forged in its name.",
			impact: 'Any host on the internet can send mail claiming to be from this domain with no SPF failure.',
			adverseConsequences: 'Spoofing and phishing are unconstrained, and DMARC cannot reach an SPF-based pass for legitimate mail.',
			recommendation:
				'Publish a single TXT record listing your sending sources and terminating in "-all" — for example: v=spf1 include:<your-email-provider> -all. If the domain never sends mail, publish "v=spf1 -all".',
			references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
		},
	},
	{
		id: 'SPF_DEPRECATED_PTR',
		checkType: 'SPF',
		pattern: /"ptr" mechanism|deprecated ptr|ptr mechanism/i,
		template: {
			title: 'SPF Uses the Deprecated "ptr" Mechanism',
			explanation:
				'The record uses the "ptr" mechanism, which RFC 7208 §5.5 deprecates: it forces receivers into slow reverse-DNS lookups whose results are frequently unavailable or attacker-influenced, so many receivers skip or fail it.',
			impact: 'Authentication results become slow and inconsistent across receivers, and may not evaluate as intended.',
			adverseConsequences: 'Legitimate mail can fail SPF at some receivers while the mechanism adds no reliable protection.',
			recommendation: 'Remove the "ptr" mechanism and list the sending hosts explicitly with ip4/ip6 or include mechanisms.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-5.5'],
		},
	},
	{
		id: 'SPF_SOFT_FAIL',
		checkType: 'SPF',
		pattern: /~all|soft ?fail/i,
		template: {
			title: 'SPF Ends in Soft Fail ("~all")',
			explanation:
				'The record terminates with "~all", which tells receivers to accept mail that fails SPF while marking it suspicious. That is the recommended terminator when an enforcing DMARC policy handles failures, but on its own it asks receivers to deliver unauthenticated mail anyway.',
			impact: 'Mail failing SPF is generally still delivered rather than rejected at the SMTP layer.',
			adverseConsequences: 'Some spoofed mail reaches recipients unless DMARC enforcement compensates.',
			recommendation:
				'Either move to "-all" once every legitimate source is listed, or keep "~all" and publish a DMARC policy of p=quarantine or p=reject so failures are acted upon.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-8.1'],
		},
	},
	{
		id: 'SPF_NO_ALL_MECHANISM',
		checkType: 'SPF',
		pattern: /no ['"]?all['"]? mechanism|does not end with an ["“]?all/i,
		template: {
			title: 'SPF Record Has No "all" Mechanism',
			explanation:
				'The record does not end with an "all" mechanism, so senders not matched by any listed mechanism get a neutral result — treated much like having no policy for those senders.',
			impact: 'Unlisted senders are neither authorised nor rejected, leaving the policy open-ended.',
			adverseConsequences:
				'Forged mail from unlisted hosts produces no SPF failure, weakening both SPF and any DMARC decision that depends on it.',
			recommendation: 'Append an explicit terminator: "-all" for strict enforcement, or "~all" alongside an enforcing DMARC policy.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-5.1'],
		},
	},
	{
		id: 'SPF_TXT_UDP_LIMIT',
		checkType: 'SPF',
		pattern: /udp limit|512[- ]byte|tcp fallback/i,
		template: {
			title: 'SPF TXT Response Near or Over the UDP Limit',
			explanation:
				'The TXT record set at this name is large enough that DNS responses approach or exceed a single UDP packet, forcing TCP fallback. Resolvers and middleboxes that do not retry over TCP may see a truncated answer and evaluate SPF against incomplete data.',
			impact: 'Some receivers may not see the full SPF record, producing inconsistent authentication results.',
			adverseConsequences: 'Mail can fail authentication at a subset of receivers in a way that is hard to reproduce or diagnose.',
			recommendation:
				'Shrink the TXT record set at this name: remove stale verification tokens and retired SPF terms, and keep the SPF record itself compact (RFC 7208 §3.4).',
			references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-3.4'],
		},
	},

	// -------------------------------------------------------------- DMARC ---
	{
		id: 'DMARC_NO_RECORD',
		checkType: 'DMARC',
		pattern: /no dmarc record found/i,
		template: {
			title: 'No DMARC Record Published',
			explanation:
				'No DMARC record was found at _dmarc.<domain>. Without one, receivers have no instruction about what to do with mail that fails SPF and DKIM alignment, and the domain owner receives no authentication reporting.',
			impact: "Forged mail failing authentication is delivered at each receiver's discretion, and spoofing goes unreported.",
			adverseConsequences: 'Impersonation of the domain is easier and effectively invisible to the domain owner.',
			recommendation:
				'Publish a TXT record at _dmarc.<domain> starting at "v=DMARC1; p=none; rua=mailto:<your-report-address>", review the aggregate reports, then move to p=quarantine and p=reject.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7489'],
		},
	},
	{
		id: 'DMARC_MULTIPLE_RECORDS',
		checkType: 'DMARC',
		pattern: /multiple dmarc (?:txt )?records|found \d+ dmarc records/i,
		template: {
			title: 'Multiple DMARC Records Published',
			explanation:
				'More than one DMARC record exists at _dmarc.<domain>. Receivers treat multiple records as no policy at all, so the domain is unprotected despite appearing configured.',
			impact: 'The DMARC policy is ignored entirely by conforming receivers.',
			adverseConsequences: 'Spoofed mail is neither quarantined nor rejected, and aggregate reporting may also be lost.',
			recommendation:
				'Delete the duplicates so exactly one DMARC TXT record remains at _dmarc.<domain>, merging any tags you need to keep.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.6.3'],
		},
	},
	{
		id: 'DMARC_MISSING_POLICY_TAG',
		checkType: 'DMARC',
		pattern: /missing (?:the )?(?:required )?"?p="? tag|missing dmarc policy/i,
		template: {
			title: 'DMARC Record Missing the p= Tag',
			explanation:
				'The DMARC record omits the required p= tag. Without a policy the record is invalid, so receivers have no instruction to act on even though a record exists.',
			impact: 'DMARC provides no enforcement despite a record being published.',
			adverseConsequences: 'The domain looks protected in a cursory audit while forged mail continues to be delivered.',
			recommendation:
				'Add an explicit p= tag (start at p=none for monitoring, then p=quarantine, then p=reject) as the first tag after v=DMARC1.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
		},
	},
	{
		id: 'DMARC_INVALID_POLICY_VALUE',
		checkType: 'DMARC',
		pattern: /policy value ".*" is invalid|invalid dmarc policy/i,
		template: {
			title: 'DMARC Policy Value Is Invalid',
			explanation:
				'The p= (or sp=) tag carries a value outside the allowed set of none, quarantine and reject. Receivers cannot parse the policy and will fall back to treating the domain as unprotected.',
			impact: 'The intended enforcement level is not applied by receivers.',
			adverseConsequences: 'The domain is effectively at p=none regardless of what the record was meant to express.',
			recommendation: 'Set p= (and sp=, if present) to exactly one of none, quarantine or reject, in lower case.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
		},
	},
	{
		id: 'DMARC_SUBDOMAIN_POLICY',
		checkType: 'DMARC',
		pattern: /\bsp=|subdomain polic|non-existent subdomains|\bnp=/i,
		template: {
			title: 'DMARC Subdomain Coverage Gap',
			explanation:
				'The subdomain policy is absent or weaker than the organisational policy (sp=, or np= for non-existent subdomains under DMARCbis). Subdomains inherit whatever sp= specifies, so a weak or unset value leaves them less protected than the parent domain — including subdomains that do not exist and are therefore free for an attacker to invent.',
			impact: 'Mail forged from subdomains is subject to a weaker policy than the parent domain.',
			adverseConsequences:
				"Attackers pick a plausible subdomain (e.g. payroll or billing) precisely because it escapes the parent policy, and the mail still carries the organisation's domain.",
			recommendation:
				'Set sp= explicitly to at least the strictness of p= (sp=reject alongside p=reject), and set np=reject to cover non-existent subdomains.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
		},
	},
	{
		id: 'DMARC_POLICY_NONE',
		checkType: 'DMARC',
		pattern: /p=none|policy (?:is |set to )?["']?none/i,
		template: {
			title: 'DMARC Policy Is Monitoring-Only (p=none)',
			explanation:
				'A valid DMARC record is published but the policy is p=none, which asks receivers only to report — never to quarantine or reject. Authentication is being measured, not enforced.',
			impact: 'Mail that fails DMARC alignment is still delivered normally.',
			adverseConsequences:
				'Spoofed mail reaches inboxes despite SPF and DKIM being in place, so the anti-impersonation benefit is not realised.',
			recommendation:
				'Use the aggregate (rua=) reports to confirm every legitimate sender aligns, then move to p=quarantine and finally p=reject. Keep pct= at 100 so the policy applies to all mail once enforced.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
		},
	},
	{
		id: 'DMARC_NO_AGGREGATE_REPORTING',
		checkType: 'DMARC',
		pattern: /rua=|aggregate report/i,
		template: {
			title: 'DMARC Aggregate Reporting Not Configured',
			explanation:
				'The record has no usable rua= address, so receivers have nowhere to send aggregate authentication reports. Enforcement can still work, but the domain owner is blind to which senders pass and fail.',
			impact: 'There is no visibility into authentication results or spoofing attempts against the domain.',
			adverseConsequences:
				'Tightening the policy becomes risky because legitimate senders cannot be identified first, and abuse of the domain goes unnoticed.',
			recommendation:
				'Add rua=mailto:<your-report-address> (a mailbox or DMARC-reporting service) and review the reports before tightening p=.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
		},
	},
	{
		id: 'DMARC_PARTIAL_COVERAGE',
		checkType: 'DMARC',
		pattern: /pct=|percentage/i,
		template: {
			title: 'DMARC Policy Applies to Only Part of the Mail Stream',
			explanation:
				'The pct= tag is below 100, so receivers apply the policy to only that percentage of failing messages and treat the rest at the next-weaker policy. This is a rollout mechanism, not an end state.',
			impact: 'A proportion of forged mail is exempt from the policy.',
			adverseConsequences: 'Spoofing succeeds at the exempt fraction, and reporting understates the true enforcement gap.',
			recommendation: 'Set pct=100 once aggregate reports show legitimate senders aligning; use lower values only as a temporary ramp.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
		},
	},
	{
		id: 'DMARC_TEST_MODE',
		checkType: 'DMARC',
		pattern: /\bt=y\b|test mode/i,
		template: {
			title: 'DMARC Test Mode Disables Enforcement (t=y)',
			explanation:
				'The record carries t=y, the DMARCbis test-mode flag. Receivers honouring DMARCbis will report on failures but will not quarantine or reject them, so the configured policy is not actually applied.',
			impact: 'The published policy is advertised but not enforced by conforming receivers.',
			adverseConsequences: 'The domain appears to enforce DMARC while spoofed mail continues to be delivered.',
			recommendation: 'Remove the t=y tag once you have verified legitimate senders align, so the configured p= takes effect.',
			references: ['https://datatracker.ietf.org/doc/html/rfc7489'],
		},
	},

	// --------------------------------------------------------------- DKIM ---
	{
		id: 'DKIM_NO_RECORDS',
		checkType: 'DKIM',
		pattern: /no dkim (?:records|selectors|keys)|no dkim record found/i,
		template: {
			title: 'No DKIM Records Found for the Tested Selectors',
			explanation:
				'No DKIM public key was found at any selector probed for this domain. Selector names are not discoverable from DNS, so this means the common selectors were absent — either the domain does not sign its mail, or it signs with a selector outside the probed set.',
			impact: 'Outbound mail cannot be verified as unaltered and genuinely from this domain via DKIM.',
			adverseConsequences:
				'DMARC then depends on SPF alone, which breaks across forwarding and mailing lists, so legitimate mail fails and forged mail is harder to distinguish.',
			recommendation:
				"Enable DKIM signing at every sending platform and publish the selector each one gives you (RSA 2048-bit or Ed25519). If signing is already enabled, confirm the selector name in your provider's console and verify the record resolves at <selector>._domainkey.<domain>.",
			references: ['https://datatracker.ietf.org/doc/html/rfc6376'],
		},
	},
	{
		id: 'DKIM_REVOKED_KEY',
		checkType: 'DKIM',
		pattern: /revoked|empty (?:public )?key/i,
		template: {
			title: 'DKIM Selector Published With a Revoked (Empty) Key',
			explanation:
				'A selector record is published with an empty p= value, which RFC 6376 defines as revocation: receivers must treat any signature from that selector as invalid. This is correct for a retired key, but harmful if the selector is still being used to sign mail.',
			impact: 'Every signature made with this selector fails verification.',
			adverseConsequences:
				'If the selector is still in use, legitimate mail fails DKIM and, where SPF does not align, fails DMARC as well.',
			recommendation:
				'Confirm no sending platform still signs with this selector. If one does, republish its real public key; if the key is genuinely retired, remove the selector record once no in-flight mail relies on it.',
			references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1'],
		},
	},
	{
		id: 'DKIM_WEAK_KEY',
		checkType: 'DKIM',
		pattern: /1024|below recommended|weak|key material too short|short key/i,
		template: {
			title: 'DKIM Signing Key Is Weaker Than Recommended',
			explanation:
				'A published selector uses an RSA key below the 2048-bit strength RFC 8301 requires (commonly a legacy 1024-bit key). Short keys are increasingly within reach of offline factoring, which would let an attacker forge signatures that verify as genuine.',
			impact: 'The authenticity guarantee DKIM provides for this selector is weaker than intended.',
			adverseConsequences: 'A forged but validly-signed message would pass DKIM and DMARC, making impersonation highly credible.',
			recommendation:
				'Rotate the selector to a 2048-bit RSA key (or Ed25519 per RFC 8463) at the sending platform, publish the new selector, and retire the old one once mail signed with it has aged out.',
			references: ['https://datatracker.ietf.org/doc/html/rfc8301', 'https://datatracker.ietf.org/doc/html/rfc6376'],
		},
	},
	{
		id: 'DKIM_TESTING_MODE',
		checkType: 'DKIM',
		pattern: /testing mode|\bt=y\b/i,
		template: {
			title: 'DKIM Selector Left in Testing Mode (t=y)',
			explanation:
				'The selector record carries t=y, which tells receivers to treat signatures as experimental and not to penalise unsigned or failing mail from the domain. It is meant for initial rollout only.',
			impact: 'Receivers may not act on DKIM results for this selector.',
			adverseConsequences:
				'The authentication benefit is reduced for as long as the flag remains, without any visible failure to prompt a fix.',
			recommendation: 'Remove the t=y tag from the selector record once you have confirmed the selector is signing correctly.',
			references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1'],
		},
	},
	{
		id: 'DKIM_MISSING_VERSION_TAG',
		checkType: 'DKIM',
		pattern: /missing the v= tag|missing v=/i,
		template: {
			title: 'DKIM Record Missing the v=DKIM1 Tag',
			explanation:
				'The selector record does not begin with v=DKIM1. Strict verifiers may reject the record as malformed, so signatures from this selector can fail even though a key is present.',
			impact: 'Signature verification for this selector is unreliable across receivers.',
			adverseConsequences: 'Legitimate signed mail may fail DKIM at some receivers with no consistent pattern.',
			recommendation: 'Republish the selector record starting with "v=DKIM1;" followed by the k= and p= tags.',
			references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1'],
		},
	},

	// ------------------------------------------------------------- DNSSEC ---
	{
		id: 'DNSSEC_NO_DNSKEY',
		checkType: 'DNSSEC',
		pattern: /no dnskey/i,
		template: {
			title: 'Zone Is Not Signed (No DNSKEY)',
			explanation:
				'No DNSKEY record was found, so the zone is not DNSSEC-signed and its responses carry no cryptographic proof of origin. Validating resolvers have nothing to verify.',
			impact: 'DNS answers for this domain cannot be authenticated, so forged responses are indistinguishable from real ones.',
			adverseConsequences: 'Cache-poisoning or on-path tampering can redirect mail and web traffic to attacker-controlled hosts.',
			recommendation:
				'Enable DNSSEC signing at your DNS provider (one click on most managed providers), then publish the matching DS record at the registrar so the chain of trust completes. Use a modern algorithm such as ECDSAP256SHA256 (algorithm 13).',
			references: ['https://datatracker.ietf.org/doc/html/rfc4033'],
		},
	},
	{
		id: 'DNSSEC_NO_DS',
		checkType: 'DNSSEC',
		pattern: /no ds \(|no ds record|missing ds|ds record.*not (?:found|published)/i,
		template: {
			title: 'No DS Record at the Parent — Chain of Trust Incomplete',
			explanation:
				'The zone publishes keys but the parent zone has no DS record delegating trust to them, so validating resolvers cannot link this zone to the DNSSEC root. Signing is in place but unverifiable — a very common half-finished state after enabling DNSSEC at the DNS provider without completing the registrar step.',
			impact: 'Resolvers treat the domain as unsigned, so the signing effort delivers no protection.',
			adverseConsequences: 'Forged DNS responses are still accepted, while operators believe DNSSEC is active.',
			recommendation:
				'Take the DS record (or the DNSKEY details) from your DNS provider and publish it at the registrar for this domain, then re-verify that validation succeeds from an external resolver.',
			references: ['https://datatracker.ietf.org/doc/html/rfc4033', 'https://datatracker.ietf.org/doc/html/rfc4035'],
		},
	},
	{
		id: 'DNSSEC_WEAK_ALGORITHM',
		checkType: 'DNSSEC',
		pattern: /rsasha1|sha-?1|deprecated .*algorithm|unrecognized .*algorithm|unknown .*algorithm/i,
		template: {
			title: 'DNSSEC Uses a Deprecated or Unrecognised Algorithm',
			explanation:
				'The signing algorithm or DS digest in use is deprecated (for example RSASHA1, or a SHA-1 DS digest) or is not one validators recognise. RFC 8624 discourages these; some validators already refuse them, and a weak digest undermines the integrity of the delegation.',
			impact: 'Validation may fail at some resolvers, or succeed against cryptography weaker than intended.',
			adverseConsequences:
				'The domain can be treated as bogus by strict validators, or its chain of trust can be attacked more cheaply than expected.',
			recommendation:
				'Roll the zone to a modern algorithm (ECDSAP256SHA256 / algorithm 13 is the common choice) and publish a SHA-256 (digest type 2) DS record at the parent, retiring the old key and digest after the rollover completes.',
			references: ['https://datatracker.ietf.org/doc/html/rfc8624'],
		},
	},
	{
		id: 'DNSSEC_CHAIN_BROKEN',
		checkType: 'DNSSEC',
		pattern: /chain of trust|validation fail|bogus/i,
		template: {
			title: 'DNSSEC Chain of Trust Is Broken',
			explanation:
				'A DS or signature link in the chain does not validate — typically a DS at the parent that no longer matches any published DNSKEY (a mismatched or half-completed key rollover), or expired signatures.',
			impact: 'Validating resolvers return SERVFAIL rather than the real answer, so the domain can become unreachable for their users.',
			adverseConsequences:
				'A broken chain is an outage, not just a weakness: mail and web traffic from validating networks fail entirely until it is fixed.',
			recommendation:
				'Compare the DS published at the registrar with the current DNSKEY set at the DNS provider and republish the DS so they match, or remove the DS to go insecure while you fix signing. Re-check signature validity and expiry after the change.',
			references: ['https://datatracker.ietf.org/doc/html/rfc4035'],
		},
	},

	// ------------------------------------------------------------ MTA-STS ---
	{
		id: 'MTA_STS_POLICY_UNREACHABLE',
		checkType: 'MTA_STS',
		pattern: /policy (?:file )?(?:not|un)(?: |-)?(?:accessible|reachable)|http 4\d\d|http 5\d\d|could not (?:be )?fetch/i,
		template: {
			title: 'MTA-STS Policy File Unreachable',
			explanation:
				'The _mta-sts TXT record advertises a policy, but the policy file could not be fetched from https://mta-sts.<domain>/.well-known/mta-sts.txt. Senders that cannot retrieve the policy fall back to opportunistic TLS, so the advertised protection is not applied.',
			impact: 'Inbound mail is not protected against TLS downgrade despite MTA-STS appearing to be configured.',
			adverseConsequences: 'Message content can be intercepted on a downgraded connection while the domain believes STS is enforcing.',
			recommendation:
				'Serve the policy file over HTTPS at mta-sts.<domain> with a valid certificate for that hostname, ensure it lists your real MX hosts, and keep its id in step with the TXT record.',
			references: ['https://datatracker.ietf.org/doc/html/rfc8461#section-3.3'],
		},
	},
	{
		id: 'MTA_STS_NOT_ENFORCING',
		checkType: 'MTA_STS',
		pattern: /mode[:= ]?["']?(?:none|testing)|testing mode/i,
		template: {
			title: 'MTA-STS Policy Is Not Enforcing',
			explanation:
				'The policy is published in mode=testing (report-only) or mode=none (withdrawal). Senders honour the policy only for reporting purposes, so a downgrade or MX-substitution attack is observed but not blocked.',
			impact: 'TLS is not actually enforced for inbound mail.',
			adverseConsequences: 'An on-path attacker can strip TLS or redirect delivery and the mail still flows.',
			recommendation:
				'Once TLS-RPT reports show no legitimate failures, change the policy file to mode=enforce and update its id. Keep max_age at 604800 (1 week) or more.',
			references: ['https://datatracker.ietf.org/doc/html/rfc8461#section-3.2'],
		},
	},
	{
		id: 'MTA_STS_ABSENT',
		checkType: 'MTA_STS',
		pattern: /neither mta-sts nor tls-rpt|no mta-sts (?:txt )?record|mta-sts .*not (?:present|found)/i,
		template: {
			title: 'MTA-STS Not Published',
			explanation:
				'No MTA-STS policy was found for this domain. SMTP therefore falls back to opportunistic TLS, where an on-path attacker can strip the STARTTLS advertisement or substitute an MX host and the sending server will still deliver.',
			impact: 'Inbound mail has no enforced transport-security floor.',
			adverseConsequences: 'Message content can be read or altered in transit without either party detecting the downgrade.',
			recommendation:
				'Publish a _mta-sts TXT record and a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt listing your MX hosts — start at mode=testing, then move to mode=enforce — and add a TLS-RPT record at _smtp._tls for visibility.',
			references: ['https://datatracker.ietf.org/doc/html/rfc8461', 'https://datatracker.ietf.org/doc/html/rfc8460'],
		},
	},
	{
		id: 'MTA_STS_SHORT_MAX_AGE',
		checkType: 'MTA_STS',
		pattern: /max[_-]?age/i,
		template: {
			title: 'MTA-STS max_age Is Too Short',
			explanation:
				"The policy's max_age is short, so senders cache it only briefly. A short cache narrows the window in which a sender remembers to require TLS, which is exactly the window an attacker needs.",
			impact: 'Downgrade protection lapses between policy refreshes.',
			adverseConsequences: 'An attacker who can block policy retrieval can wait out the cache and then downgrade delivery.',
			recommendation: 'Set max_age to at least 604800 (1 week); 2592000 (30 days) is common once the policy is stable.',
			references: ['https://datatracker.ietf.org/doc/html/rfc8461#section-3.2'],
		},
	},

	// ---------------------------------------------------------------- CAA ---
	{
		id: 'CAA_NO_RECORDS',
		checkType: 'CAA',
		pattern: /no caa records/i,
		template: {
			title: 'No CAA Records Published',
			explanation:
				'No CAA records exist for this domain, so any publicly-trusted certificate authority may issue certificates for it. CAA is the DNS-level control that tells CAs which of them you actually use.',
			impact: 'Certificate issuance for the domain is unconstrained.',
			adverseConsequences:
				'A mis-issued or fraudulently-obtained certificate from any CA would be trusted by browsers and mail clients, enabling interception or impersonation.',
			recommendation:
				'Publish CAA records naming only the CAs you use — for example 0 issue "letsencrypt.org" — plus an issuewild entry and an iodef contact so unauthorised attempts are reported to you.',
			references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
		},
	},
	{
		id: 'CAA_NO_ISSUE_TAG',
		checkType: 'CAA',
		pattern: /no "?issue"? tag|without .*issue tag/i,
		template: {
			title: 'CAA Records Present but No Usable issue Tag',
			explanation:
				'CAA records exist but none carries an "issue" property, so no CA is actually authorised or excluded by the record set. The control is present in form but not in effect.',
			impact: 'Issuance remains unconstrained despite CAA records being published.',
			adverseConsequences: 'The domain appears to have certificate governance in an audit while any CA may still issue.',
			recommendation:
				'Add an issue property naming each CA you use (0 issue "<ca-domain>"), and an issuewild property to control wildcard issuance.',
			references: ['https://datatracker.ietf.org/doc/html/rfc8659#section-4.2'],
		},
	},
	{
		id: 'CAA_HARDENING',
		checkType: 'CAA',
		pattern: /issuewild|iodef/i,
		template: {
			title: 'CAA Policy Could Be Tightened',
			explanation:
				'The CAA record set works but omits a hardening property: issuewild (which constrains wildcard-certificate issuance separately from ordinary issuance) or iodef (which gives CAs an address to report unauthorised requests to).',
			impact: 'Wildcard issuance is not separately constrained, or unauthorised issuance attempts go unreported.',
			adverseConsequences:
				'A wildcard certificate covering every subdomain could be issued, or an attempted mis-issuance could pass unnoticed.',
			recommendation:
				'Add 0 issuewild ";" to forbid wildcards (or name the CA permitted to issue them) and 0 iodef "mailto:<security-contact>" so CAs can report unauthorised requests.',
			references: ['https://datatracker.ietf.org/doc/html/rfc8659#section-4.3'],
		},
	},
];
