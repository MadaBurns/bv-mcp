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

export interface DetailsPattern {
	checkType: string;
	pattern: RegExp;
	key: string;
}

export const DETAILS_PATTERNS: DetailsPattern[] = [
	// DKIM patterns
	{ checkType: 'DKIM', pattern: /legacy.*rsa|1024[- ]bit.*rsa|rsa.*1024/i, key: 'DKIM_LEGACY_RSA_KEY' },
	{ checkType: 'DKIM', pattern: /below.*recommend|2048.*bit/i, key: 'DKIM_BELOW_RECOMMENDED_RSA_KEY' },
	{ checkType: 'DKIM', pattern: /revoked|empty.*public.*key|p=\)/i, key: 'DKIM_REVOKED_KEY' },
	{ checkType: 'DKIM', pattern: /missing.*v=|missing.*version/i, key: 'DKIM_MISSING_VERSION_TAG' },
	{ checkType: 'DKIM', pattern: /testing.*mode|t=y/i, key: 'DKIM_TESTING_MODE' },
	{ checkType: 'DKIM', pattern: /no dkim records found/i, key: 'DKIM_NO_RECORDS' },
	{ checkType: 'DKIM', pattern: /weak.*rsa|rsa.*below.*2048|rsa.*1536|rsa.*1280/i, key: 'DKIM_WEAK_RSA_KEY' },
	{ checkType: 'DKIM', pattern: /unknown.*key.*type|unrecognized.*key.*type/i, key: 'DKIM_UNKNOWN_KEY_TYPE' },
	{ checkType: 'DKIM', pattern: /short.*key.*material|key.*material.*too short/i, key: 'DKIM_SHORT_KEY_MATERIAL' },
	// SPF patterns
	{ checkType: 'SPF', pattern: /soft fail|~all/i, key: 'SPF_SOFT_FAIL_DETAILS' },
	{ checkType: 'SPF', pattern: /\+all|permissive/i, key: 'SPF_PERMISSIVE_ALL' },
	{ checkType: 'SPF', pattern: /too many.*lookup|lookup.*exceed/i, key: 'SPF_TOO_MANY_LOOKUPS' },
	{ checkType: 'SPF', pattern: /multiple spf record/i, key: 'SPF_MULTIPLE_RECORDS' },
	{ checkType: 'SPF', pattern: /no spf record/i, key: 'SPF_NO_RECORD' },
	{ checkType: 'SPF', pattern: /broad.*ip|overly broad/i, key: 'SPF_BROAD_IP_RANGE' },
	{ checkType: 'SPF', pattern: /deprecated.*ptr|ptr mechanism/i, key: 'SPF_DEPRECATED_PTR' },
	// DMARC patterns
	{ checkType: 'DMARC', pattern: /no subdomain policy|sp=.*not specified/i, key: 'DMARC_NO_SUBDOMAIN_POLICY' },
	{ checkType: 'DMARC', pattern: /dkim alignment.*relaxed|adkim=r/i, key: 'DMARC_RELAXED_DKIM_ALIGNMENT' },
	{ checkType: 'DMARC', pattern: /spf alignment.*relaxed|aspf=r/i, key: 'DMARC_RELAXED_SPF_ALIGNMENT' },
	{ checkType: 'DMARC', pattern: /forensic.*report|ruf=.*absent|ruf.*not configured/i, key: 'DMARC_NO_FORENSIC_REPORTING' },
	{ checkType: 'DMARC', pattern: /policy.*set to none|p=none/i, key: 'DMARC_POLICY_NONE' },
	{ checkType: 'DMARC', pattern: /no aggregate report|rua.*not specified|rua.*absent/i, key: 'DMARC_NO_AGGREGATE_REPORTING' },
	{ checkType: 'DMARC', pattern: /policy.*quarantine|p=quarantine/i, key: 'DMARC_POLICY_QUARANTINE' },
	{ checkType: 'DMARC', pattern: /multiple dmarc.*record|duplicate dmarc/i, key: 'DMARC_MULTIPLE_RECORDS' },
	{ checkType: 'DMARC', pattern: /subdomain.*policy.*weaker|sp=.*weaker than.*p=/i, key: 'DMARC_SUBDOMAIN_WEAKER' },
	{ checkType: 'DMARC', pattern: /pct=.*less than 100|pct.*not.*100|percentage.*tag/i, key: 'DMARC_PARTIAL_COVERAGE' },
	{ checkType: 'DMARC', pattern: /invalid.*policy|unrecognized.*policy/i, key: 'DMARC_INVALID_POLICY' },
	{ checkType: 'DMARC', pattern: /missing.*p=|no.*p=.*tag/i, key: 'DMARC_MISSING_POLICY' },
	// DNSSEC patterns
	{ checkType: 'DNSSEC', pattern: /no dnskey/i, key: 'DNSSEC_NO_DNSKEY' },
	{ checkType: 'DNSSEC', pattern: /no ds.*record|delegation signer/i, key: 'DNSSEC_NO_DS' },
	{ checkType: 'DNSSEC', pattern: /deprecated.*algorithm/i, key: 'DNSSEC_DEPRECATED_ALGORITHM' },
	{ checkType: 'DNSSEC', pattern: /unknown.*algorithm|unrecognized.*algorithm/i, key: 'DNSSEC_UNKNOWN_ALGORITHM' },
	{ checkType: 'DNSSEC', pattern: /deprecated.*digest|sha-?1.*digest|ds.*digest.*deprecated/i, key: 'DNSSEC_DEPRECATED_DS_DIGEST' },
	// SSL patterns
	{ checkType: 'SSL', pattern: /no hsts header/i, key: 'SSL_NO_HSTS' },
	{ checkType: 'SSL', pattern: /no http to https redirect|does not redirect to https/i, key: 'SSL_NO_REDIRECT' },
	{ checkType: 'SSL', pattern: /hsts max-age.*short|max-age.*less than/i, key: 'SSL_HSTS_SHORT_MAXAGE' },
	{ checkType: 'SSL', pattern: /missing.*includeSubDomains|no.*includeSubDomains|includeSubDomains.*missing/i, key: 'SSL_HSTS_NO_SUBDOMAINS' },
	// MTA-STS patterns (ORDER MATTERS — "no records" before "testing mode")
	{ checkType: 'MTA_STS', pattern: /no mta-sts.*record|neither mta-sts nor tls-rpt/i, key: 'MTA_STS_NO_RECORDS' },
	{ checkType: 'MTA_STS', pattern: /testing mode/i, key: 'MTA_STS_TESTING' },
	{ checkType: 'MTA_STS', pattern: /policy.*not accessible|policy file.*404/i, key: 'MTA_STS_POLICY_INACCESSIBLE' },
	{ checkType: 'MTA_STS', pattern: /tls-rpt.*missing|tls-rpt record missing/i, key: 'MTA_STS_TLSRPT_MISSING' },
	{ checkType: 'MTA_STS', pattern: /mode.*none|mta-sts.*disabled/i, key: 'MTA_STS_DISABLED' },
	{ checkType: 'MTA_STS', pattern: /max_age.*short|max_age.*too short|short.*max_age/i, key: 'MTA_STS_SHORT_MAXAGE' },
	// NS patterns
	{ checkType: 'NS', pattern: /low.*nameserver.*diversity|all nameservers.*under/i, key: 'NS_LOW_DIVERSITY' },
	{ checkType: 'NS', pattern: /soa expire.*short|expire.*< *604800/i, key: 'NS_SOA_EXPIRE_SHORT' },
	{ checkType: 'NS', pattern: /single nameserver/i, key: 'NS_SINGLE_NAMESERVER' },
	{ checkType: 'NS', pattern: /no soa record|soa.*not found/i, key: 'NS_NO_SOA' },
	{ checkType: 'NS', pattern: /soa refresh.*short|refresh.*interval.*short/i, key: 'NS_SOA_REFRESH_SHORT' },
	{ checkType: 'NS', pattern: /negative ttl.*long|nxdomain.*caching.*long|negative.*cache.*long/i, key: 'NS_SOA_NEGATIVE_TTL_LONG' },
	// CAA patterns (issuewild before issue to avoid false match)
	{ checkType: 'CAA', pattern: /no.*issuewild/i, key: 'CAA_NO_ISSUEWILD' },
	{ checkType: 'CAA', pattern: /no.*issue.*tag|no caa issue/i, key: 'CAA_NO_ISSUE_TAG' },
	{ checkType: 'CAA', pattern: /no.*iodef/i, key: 'CAA_NO_IODEF' },
	{ checkType: 'CAA', pattern: /no caa records/i, key: 'CAA_NO_RECORDS' },
	// MX patterns
	{ checkType: 'MX', pattern: /single mx record|only one mx/i, key: 'MX_SINGLE_RECORD' },
	{ checkType: 'MX', pattern: /mx points to ip|mx.*ip address/i, key: 'MX_POINTS_TO_IP' },
	{ checkType: 'MX', pattern: /dangling mx/i, key: 'MX_DANGLING' },
	{ checkType: 'MX', pattern: /no mx records found|no mx records/i, key: 'MX_NO_RECORDS' },
];

export const EXPLANATIONS: Record<string, ExplanationTemplate> = {
	SUBDOMAIN_TAKEOVER_CRITICAL: {
		title: 'Dangling CNAME — Subdomain Takeover Risk',
		severity: 'critical',
		explanation:
			'One of your subdomains points to a service that no longer exists — like an abandoned storefront with your brand still on the sign. Someone else could move in and pretend to be you.',
		impact: 'A stranger could set up shop under your name, tricking visitors into handing over passwords or personal info.',
		adverseConsequences:
			'Your reputation takes a hit, customers get scammed, and cleaning up the mess is expensive and time-consuming.',
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
			'A subdomain points to an outside service, but we could not confirm the service is still active. It may be an abandoned storefront that someone else could claim.',
		impact: 'If the service is truly abandoned, an attacker could take it over and pose as you on that subdomain.',
		adverseConsequences: 'Visitors could land on a fake page under your name and be tricked until the broken link is fixed.',
		recommendation: 'Manually review the CNAME target and remove or update if orphaned. Use DNS monitoring tools for ongoing checks.',
		references: [
			'https://github.com/EdOverflow/can-i-take-over-xyz',
			'https://www.hackerone.com/blog/Guide-Subdomain-Takeover',
		],
	},
	SUBDOMAIN_TAKEOVER_INFO: {
		title: 'No Dangling CNAME Records Found',
		severity: 'info',
		explanation: 'All your subdomains point to active services — no abandoned storefronts for someone else to claim.',
		recommendation: 'Continue regular DNS audits and monitoring for new subdomains or changes.',
		references: ['https://github.com/EdOverflow/can-i-take-over-xyz'],
	},
	SPF_PASS: {
		title: 'SPF Validated',
		severity: 'pass',
		explanation:
			'Your domain has a guest list for email senders, and it looks good. Only approved servers can send mail on your behalf.',
		recommendation: 'Maintain your current SPF configuration. Ensure you update it when adding new email sending sources.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
	},
	SPF_FAIL: {
		title: 'SPF Validation Failed',
		severity: 'fail',
		explanation: 'Your email guest list is broken — legitimate emails are being turned away because the sending server is not on the list.',
		impact: 'Real emails from you get bounced, and fake emails pretending to be from you slip through unchecked.',
		adverseConsequences:
			'Your actual emails stop arriving, while scammers have an easier time impersonating you.',
		recommendation:
			'Review your SPF record and ensure all legitimate email sources are included. Common issue: using -all but missing include statements.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208', 'https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/'],
	},
	SPF_WARNING: {
		title: 'SPF Soft Fail',
		severity: 'warning',
		explanation: 'Your email guest list flags uninvited senders but still lets them in — like a bouncer who warns you about gatecrashers but does not actually stop them.',
		impact: 'Fake emails pretending to be from you still get delivered, just with a small "suspicious" note attached.',
		adverseConsequences: 'Scam emails keep reaching people, and your team has to sort the real mail from the fakes by hand.',
		recommendation: 'Upgrade to hard fail (-all) after verifying all legitimate sources are in your SPF record.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-8.1'],
	},
	SPF_MISSING: {
		title: 'No SPF Record Found',
		severity: 'fail',
		explanation:
			'Your domain has no guest list for email senders. Without one, anyone on the internet can send emails that look like they come from you — like having no bouncer at the door.',
		impact: 'Anybody can send fake emails with your name on the return address, and nobody can tell they are not from you.',
		adverseConsequences: 'Scammers send emails as you, your reputation suffers, and your real emails start getting blocked too.',
		recommendation: "Add a TXT record to your domain's DNS with a valid SPF policy. Start with: v=spf1 include:<your-email-provider> -all",
		references: ['https://datatracker.ietf.org/doc/html/rfc7208', 'https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/'],
	},
	DMARC_PASS: {
		title: 'DMARC Policy Validated',
		severity: 'pass',
		explanation:
			'Your domain has clear instructions telling the post office what to do with suspicious mail — throw it away or flag it. This keeps fake emails from reaching people.',
		recommendation:
			'Monitor your DMARC reports to ensure legitimate email is not being blocked. Consider enabling reject policy for stronger protection.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489'],
	},
	DMARC_FAIL: {
		title: 'No DMARC Record Found',
		severity: 'fail',
		explanation:
			'Your domain has no instructions for the post office about what to do with suspicious mail. Without them, fake emails that fail your guest list check get delivered anyway.',
		impact: 'Mail systems have no idea whether to throw away or deliver forged emails, so most just deliver them.',
		adverseConsequences: 'Scam emails using your name land in people\'s inboxes regularly, damaging your reputation.',
		recommendation: 'Add a TXT record at _dmarc.<domain> with at minimum: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489', 'https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/'],
	},
	DMARC_WARNING: {
		title: 'DMARC Policy Not Enforcing',
		severity: 'warning',
		explanation: 'Your post office instructions say "just take a note" or "put it in the junk pile" when mail fails the check — but they never say "throw it away." That leaves the door partly open.',
		impact: 'Some fake emails still get through because the instructions are not strict enough to block them.',
		adverseConsequences: 'Scammers can still impersonate you in people\'s inboxes, leading to fraud and confusion.',
		recommendation: "After reviewing DMARC reports, upgrade the policy to 'reject' to actively protect against email spoofing.",
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DKIM_PASS: {
		title: 'DKIM Validated',
		severity: 'pass',
		explanation:
			'Your emails carry a tamper-evident wax seal that proves they really came from you and were not changed along the way.',
		recommendation: 'Maintain your DKIM configuration. Rotate keys periodically as per your security policy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376'],
	},
	DKIM_FAIL: {
		title: 'No DKIM Records Found',
		severity: 'fail',
		explanation:
			'Your emails have no wax seal, so there is no way for anyone to tell if a message really came from you or if it was tampered with along the way.',
		impact: 'Without a seal, receivers cannot tell your real emails apart from forgeries.',
		adverseConsequences:
			'Your real emails may get flagged as suspicious, while fake emails pretending to be you look just as believable.',
		recommendation: 'Configure DKIM signing with your email provider. They will provide the DKIM DNS records to publish.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376', 'https://www.cloudflare.com/learning/dns/dns-records/dns-dkim-record/'],
	},
	DNSSEC_PASS: {
		title: 'DNSSEC Enabled',
		severity: 'pass',
		explanation:
			'Your address records have a notarized signature, so nobody can forge them and redirect your visitors or mail to a fake location.',
		recommendation: 'Maintain your DNSSEC configuration. Monitor for any validation failures in your logs.',
		references: ['https://datatracker.ietf.org/doc/html/rfc4033'],
	},
	DNSSEC_FAIL: {
		title: 'DNSSEC Not Validated',
		severity: 'fail',
		explanation:
			'Your address records have no notarized signature. Without one, someone could swap in a fake address and redirect your visitors or mail to a lookalike destination.',
		impact: 'An attacker can forge your address records, sending your visitors and email to an imposter site.',
		adverseConsequences: 'People end up at fake versions of your site, giving away passwords and personal info without realizing it.',
		recommendation: 'Enable DNSSEC through your domain registrar and DNS provider. Most providers offer one-click DNSSEC activation.',
		references: ['https://datatracker.ietf.org/doc/html/rfc4033', 'https://www.cloudflare.com/dns/dnssec/how-dnssec-works/'],
	},
	SSL_PASS: {
		title: 'SSL/TLS Validated',
		severity: 'pass',
		explanation: 'Your website connection has a working padlock — visitors talk to your site through a private, armored channel that keeps eavesdroppers out.',
		recommendation: 'Maintain your SSL certificate. Consider implementing HSTS for additional security.',
		references: ['https://https.cio.gov/hsts/'],
	},
	SSL_FAIL: {
		title: 'HTTPS Not Available',
		severity: 'fail',
		explanation:
			'Your website has no padlock — the connection is wide open, like sending postcards instead of sealed letters. Anyone on the network can read or change what passes through.',
		impact: 'Eavesdroppers can see passwords, credit cards, and anything else visitors send to your site.',
		adverseConsequences: 'Browsers show scary warnings, visitors leave, and sensitive data can be stolen in transit.',
		recommendation: "Install a valid SSL/TLS certificate. Free certificates are available from Let's Encrypt or Cloudflare.",
		references: ['https://letsencrypt.org/', 'https://www.cloudflare.com/ssl/'],
	},
	SSL_WARNING: {
		title: 'Mixed Content or Redirect Issues',
		severity: 'warning',
		explanation: 'Your padlock is there, but some parts of the page still load through the unprotected channel — like locking the front door but leaving a window open.',
		impact: 'Some content loads without protection, so an attacker could swap in fake images, scripts, or data on those pieces.',
		adverseConsequences: 'Visitors get a mixed experience — partly protected, partly exposed — and browsers may show warnings.',
		recommendation: 'Ensure all resources load over HTTPS and implement proper redirects from HTTP to HTTPS.',
		references: ['https://www.cloudflare.com/ssl/'],
	},
	SSL_MEDIUM: {
		title: 'HSTS or Redirect Issues',
		severity: 'medium',
		explanation:
			'Your site has HTTPS, but it does not insist that browsers always use it. On the first visit or on a hostile network, someone could trick the browser into using the unprotected route.',
		impact: 'Visitors can be silently pushed onto the unprotected connection, especially on public Wi-Fi or the first time they visit.',
		adverseConsequences: 'Passwords and session data can be stolen during that brief unprotected moment.',
		recommendation:
			'Add a Strict-Transport-Security header with max-age of at least 1 year (31536000). Configure your web server to redirect all HTTP requests to HTTPS.',
		references: ['https://https.cio.gov/hsts/', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
	},
	SSL_LOW: {
		title: 'HSTS Configuration Suboptimal',
		severity: 'low',
		explanation:
			'Your site tells browsers to always use the padlock, but the instruction expires too quickly or does not cover your subdomains — like a security rule that only applies to the front door, not the side entrances.',
		impact: 'The "always use the padlock" rule wears off too soon or misses some parts of your site.',
		adverseConsequences: 'Returning visitors or subdomain users may briefly lose protection, and your site cannot join the browser preload list.',
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
		explanation: 'Your domain requires the mail truck to use the armored route when delivering email — no shortcuts or unprotected detours allowed.',
		recommendation: 'Monitor your MTA-STS reports to ensure legitimate mail servers can deliver successfully.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	MTA_STS_FAIL: {
		title: 'No MTA-STS Record Found',
		severity: 'fail',
		explanation:
			'Your domain does not require the mail truck to use the armored route. An attacker could force the truck onto an unprotected road and read everything inside.',
		impact: 'Incoming emails can be intercepted because there is no rule requiring the protected delivery route.',
		adverseConsequences: 'Private email content can be read by eavesdroppers while it is in transit to you.',
		recommendation:
			'Publish an MTA-STS TXT record at _mta-sts.<domain> and host a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	MTA_STS_WARNING: {
		title: 'MTA-STS in Testing Mode',
		severity: 'warning',
		explanation: 'Your armored mail truck rule is in "practice run" mode — it logs when the truck takes an unprotected road, but does not actually stop it.',
		impact: 'You can see when email takes the unprotected route, but nothing blocks it from happening.',
		adverseConsequences: 'Email can still be intercepted because the rule is only watching, not acting.',
		recommendation: 'After verifying all mail servers can successfully deliver over TLS, upgrade to mode=enforce.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461'],
	},
	NS_PASS: {
		title: 'Nameservers Validated',
		severity: 'pass',
		explanation: 'Your domain\'s phone book listings are working properly — anyone looking for your site or email gets pointed to the right place.',
		recommendation: 'Maintain your current nameserver configuration. Use at least two geographically distributed nameservers for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035'],
	},
	NS_FAIL: {
		title: 'Nameserver Issues Detected',
		severity: 'fail',
		explanation: 'Some of your domain\'s phone book listings are broken or not answering. When people look up your address, they may not find you.',
		impact: 'Your website, email, and other services may become unreachable if the directory can\'t point people to you.',
		adverseConsequences: 'Visitors get error pages, emails bounce, and your online services go dark.',
		recommendation: 'Verify all listed nameservers are operational and properly configured. Ensure NS records match those at the registrar.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035', 'https://www.cloudflare.com/learning/dns/dns-records/dns-ns-record/'],
	},
	NS_WARNING: {
		title: 'Nameserver Configuration Suboptimal',
		severity: 'warning',
		explanation: 'Your phone book listings work, but they could be more reliable — like having all your backup copies stored in the same building.',
		impact: 'If your single directory provider has an outage, nobody can look up your address.',
		adverseConsequences: 'Your site and email could go down during a provider outage because there is no backup directory elsewhere.',
		recommendation: 'Consider adding additional nameservers for redundancy and ensuring they are geographically distributed.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035'],
	},
	CAA_PASS: {
		title: 'CAA Records Configured',
		severity: 'pass',
		explanation: 'You have a "only these locksmiths can make keys" rule in place, so only your approved providers can create security certificates for your domain.',
		recommendation: 'Maintain your CAA records. Review periodically to ensure they reflect your current certificate issuance needs.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
	},
	CAA_FAIL: {
		title: 'No CAA Records Found',
		severity: 'fail',
		explanation: 'You have no "approved locksmiths" rule — any locksmith in the world can make keys (certificates) for your domain without your permission.',
		impact: 'Any certificate provider can issue a certificate for your domain, even ones you have never heard of.',
		adverseConsequences: 'Someone could get a fake key made for your domain and use it to impersonate your website.',
		recommendation: 'Add CAA DNS records to restrict certificate issuance to your authorized CAs (e.g., "0 issue letsencrypt.org").',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659', 'https://www.cloudflare.com/learning/dns/dns-records/dns-caa-record/'],
	},
	CAA_WARNING: {
		title: 'CAA Configuration Incomplete',
		severity: 'warning',
		explanation: 'You have an approved locksmiths list, but it is incomplete — for example, it may not cover skeleton keys (wildcards) or tell you when someone tries an unapproved locksmith.',
		impact: 'Some types of certificates are not covered by the rule, leaving gaps in who can make keys for you.',
		adverseConsequences: 'An unapproved provider could issue a certificate for your domain in ways your rule does not cover.',
		recommendation: 'Review your CAA records and add an iodef tag for incident reporting. Consider restricting wildcard certificate issuance separately.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
	},
	MX_PASS: {
		title: 'MX Records Validated',
		severity: 'pass',
		explanation: 'Your domain\'s mailbox address is set up correctly — other mail systems know exactly where to deliver email for you.',
		recommendation: 'Maintain your MX records. Ensure backup MX entries exist for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_FAIL: {
		title: 'No MX Records Found',
		severity: 'fail',
		explanation: 'Your domain has no mailbox address listed, so other mail systems do not know where to deliver email for you — like a house with no mailbox on the street.',
		impact: 'Email sent to your domain either bounces back or gets lost because there is no delivery address.',
		adverseConsequences: 'You miss important messages, and people trying to reach you get error messages instead.',
		recommendation: 'Add MX records pointing to your mail server. If this domain does not handle email, consider adding a null MX record (0 .).',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321', 'https://datatracker.ietf.org/doc/html/rfc7505'],
	},
	MX_WARNING: {
		title: 'MX Configuration Suboptimal',
		severity: 'warning',
		explanation: 'Your mailbox address is set up, but there is no backup — like having only one mailbox with no spare. If it goes down, mail piles up or bounces.',
		impact: 'If your mail server has problems, there is nowhere else for incoming email to go.',
		adverseConsequences: 'Email gets delayed or lost during server issues, which can disrupt your business.',
		recommendation: 'Review MX priorities and add at least one backup MX record for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_INFO: {
		title: 'MX Records Present',
		severity: 'info',
		explanation: 'Your mailbox address is set up and working — email gets delivered to the right place.',
		recommendation: 'No action required. Ensure backup MX records exist for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_LOW: {
		title: 'MX Configuration Could Be Improved',
		severity: 'low',
		explanation: 'Your mailbox address works, but you only have one — like a single mailbox with no backup. A small issue could cause delays.',
		impact: 'If your mail server hiccups, there is no backup to catch incoming messages.',
		adverseConsequences: 'Brief server problems turn into noticeable email delays for your users.',
		recommendation: 'Add at least one backup MX record with a different priority for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_HIGH: {
		title: 'MX Configuration Error',
		severity: 'high',
		explanation:
			'Your mailbox address has a mistake — it points to a raw number instead of a name, or points to a name that does not exist. Many mail systems will refuse to deliver to it.',
		impact: 'Some or all email sent to you bounces back because mail systems cannot figure out your delivery address.',
		adverseConsequences: 'Important emails never arrive, and the senders get confusing error messages.',
		recommendation:
			'Update MX records to point to valid hostnames, not IP addresses. Ensure all MX targets resolve to valid A/AAAA records.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_MEDIUM: {
		title: 'No MX Records Found',
		severity: 'medium',
		explanation:
			'Your domain has no mailbox address listed. Email either fails to arrive or takes an unreliable back road to get to you.',
		impact: 'Some emails reach you through a workaround, but many just bounce — it is hit-or-miss.',
		adverseConsequences: 'You may miss important messages from customers, partners, or security alerts.',
		recommendation:
			'If this domain should receive email, add MX records. If not, publish a null MX record per RFC 7505 to explicitly declare that.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321', 'https://datatracker.ietf.org/doc/html/rfc7505'],
	},
	// --- Details-aware DKIM entries ---
	DKIM_LEGACY_RSA_KEY: {
		title: 'Legacy DKIM RSA Key',
		severity: 'high',
		explanation:
			'Your email wax seal uses an old, small stamp that modern tools could copy. Think of it like a flimsy lock that a skilled thief could pick.',
		impact: 'If someone copies your seal, they can stamp fake emails that look perfectly real.',
		adverseConsequences: 'Scam emails with a perfect copy of your seal become impossible to tell apart from your real ones.',
		recommendation:
			'Rotate to a 2048-bit or 4096-bit RSA key, or switch to Ed25519. Update the DNS TXT record and email server configuration simultaneously.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.3'],
	},
	DKIM_BELOW_RECOMMENDED_RSA_KEY: {
		title: 'Below Recommended DKIM Key Size',
		severity: 'medium',
		explanation:
			'Your email wax seal is good enough for today, but a bigger, stronger stamp would keep it safe for longer — like upgrading from a standard lock to a deadbolt.',
		impact: 'The seal works fine now but may become easier to copy as technology improves.',
		adverseConsequences: 'You may need to replace the seal sooner than expected to stay ahead of copycats.',
		recommendation: 'When next rotating keys, upgrade to 4096-bit RSA or Ed25519 for improved future-proofing.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.3'],
	},
	DKIM_REVOKED_KEY: {
		title: 'Revoked DKIM Key',
		severity: 'medium',
		explanation:
			'This wax seal stamp has been cancelled — it is like a key that has been deactivated. Any email still using it will fail the seal check.',
		impact: 'Email systems still trying to use this cancelled stamp will have their messages rejected.',
		adverseConsequences: 'Emails may bounce or get blocked if your mail servers have not switched to the new stamp yet.',
		recommendation:
			'Remove the revoked selector from your email server configuration. Keep the DNS record for a transition period, then remove it.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1'],
	},
	DKIM_MISSING_VERSION_TAG: {
		title: 'Missing DKIM Version Tag',
		severity: 'medium',
		explanation:
			'Your wax seal stamp is missing its label — some post offices will accept it, but others will not recognize it and reject the seal.',
		impact: 'Some email providers may refuse to verify your seal because the label is missing.',
		adverseConsequences: 'Your emails may pass the seal check at some places but fail at others, making delivery unpredictable.',
		recommendation: 'Add "v=DKIM1" to the beginning of the DKIM TXT record value.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1'],
	},
	DKIM_TESTING_MODE: {
		title: 'DKIM in Testing Mode',
		severity: 'low',
		explanation:
			'Your wax seal is in "practice run" mode — receivers check it but will not reject emails that fail. It is like a security camera that records but does not trigger any alarms.',
		impact: 'Fake emails with a broken seal still get delivered because the system is just practicing, not blocking.',
		adverseConsequences: 'Forged emails can slip through while you are still in practice mode.',
		recommendation: 'Once DKIM signing is confirmed working correctly, remove the t=y flag to enable full enforcement.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1'],
	},
	DKIM_NO_RECORDS: {
		title: 'No DKIM Records Found',
		severity: 'high',
		explanation:
			'No wax seal stamps were found for your domain. Your emails go out without any tamper-evident seal, so receivers have no way to verify they are genuine.',
		impact: 'Without a seal, nobody can tell if an email truly came from you or was forged by someone else.',
		adverseConsequences: 'Your real emails may get flagged as suspicious, while fakes pretending to be you look equally believable.',
		recommendation: 'Configure DKIM signing with your email provider. They will provide the DKIM DNS TXT records to publish.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc6376',
			'https://www.cloudflare.com/learning/dns/dns-records/dns-dkim-record/',
		],
	},
	DKIM_WEAK_RSA_KEY: {
		title: 'Weak DKIM RSA Key',
		severity: 'high',
		explanation:
			'Your email wax seal stamp is too small and flimsy — modern tools could make a copy of it. It is like using a cheap padlock that can be cut with bolt cutters.',
		impact: 'A determined attacker could duplicate your seal and stamp fake emails that pass as genuine.',
		adverseConsequences: 'Forged emails with a copied seal look identical to your real ones, making scams very convincing.',
		recommendation:
			'Rotate to a 2048-bit or 4096-bit RSA key, or switch to Ed25519. Update the DNS TXT record and email server configuration simultaneously.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.3'],
	},
	DKIM_UNKNOWN_KEY_TYPE: {
		title: 'Unknown DKIM Key Type',
		severity: 'medium',
		explanation:
			'Your wax seal uses an unusual stamp type that most post offices do not recognize — like writing in a language nobody can read.',
		impact: 'Most email providers cannot verify your seal because they do not understand the stamp format.',
		adverseConsequences: 'Your seal is effectively useless since almost nobody can check it, so your emails look unsigned.',
		recommendation:
			'Use a supported key type: RSA (k=rsa) or Ed25519 (k=ed25519). Verify your email provider supports the chosen algorithm.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1',
			'https://datatracker.ietf.org/doc/html/rfc8463',
		],
	},
	DKIM_SHORT_KEY_MATERIAL: {
		title: 'Short DKIM Key Material',
		severity: 'high',
		explanation:
			'Your wax seal stamp is broken or incomplete — like a key that has been snapped in half. It cannot be used to verify anything.',
		impact: 'Every email using this broken stamp fails the seal check because the stamp is not whole.',
		adverseConsequences: 'All your emails fail the seal check, which can cause them to be blocked or sent to spam.',
		recommendation:
			'Regenerate the DKIM key pair and republish the full public key in the DNS TXT record. Verify the key is not truncated during DNS entry.',
		references: ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1'],
	},
	// --- Details-aware SPF entries ---
	SPF_SOFT_FAIL_DETAILS: {
		title: 'SPF Soft Fail (~all)',
		severity: 'low',
		explanation:
			'Your email guest list flags gatecrashers but still lets them in — like a bouncer who says "I do not recognize you" but steps aside anyway.',
		impact: 'Emails from senders not on your list still get delivered, just with a small note that they look suspicious.',
		adverseConsequences: 'Fake emails reach people\'s inboxes with only a quiet warning most people never see.',
		recommendation:
			'After verifying all legitimate senders are included, upgrade from ~all to -all (hard fail) for strict enforcement.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-8.1'],
	},
	SPF_PERMISSIVE_ALL: {
		title: 'Permissive SPF Policy (+all)',
		severity: 'critical',
		explanation:
			'Your email guest list says "everyone is welcome" — literally every server on the internet is approved to send email as you. It is like posting a sign that says "no bouncer, come on in."',
		impact: 'Anyone can send email pretending to be you and it will pass the guest list check with flying colors.',
		adverseConsequences: 'Scammers can run massive fake email campaigns using your name, and they all look legitimate.',
		recommendation:
			'Immediately change +all to -all and explicitly list authorized senders with include: and ip4:/ip6: mechanisms.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
	},
	SPF_TOO_MANY_LOOKUPS: {
		title: 'Too Many SPF DNS Lookups',
		severity: 'critical',
		explanation:
			'Your email guest list is so long and complicated that the bouncer gives up reading it. Once it gets too complex, the whole list is thrown out and everyone gets in.',
		impact: 'The guest list is ignored entirely, so your domain is treated as having no list at all.',
		adverseConsequences: 'Anyone can send email as you because the system quietly stopped checking the list.',
		recommendation:
			'Reduce DNS lookups by flattening includes into ip4:/ip6: mechanisms, removing unused includes, or using an SPF flattening service.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4'],
	},
	SPF_MULTIPLE_RECORDS: {
		title: 'Multiple SPF Records',
		severity: 'high',
		explanation:
			'You have more than one guest list posted, and the bouncer does not know which one to follow — so they throw both away. You can only have one.',
		impact: 'Having two lists breaks the system entirely — the bouncer stops checking altogether.',
		adverseConsequences: 'All your emails fail the guest list check, which can cause them to be blocked or sent to spam.',
		recommendation: 'Merge all SPF records into a single TXT record. Remove any duplicate or outdated SPF entries.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-3.2'],
	},
	SPF_NO_RECORD: {
		title: 'No SPF Record Found',
		severity: 'critical',
		explanation:
			'Your domain has no guest list at all — there is no bouncer and no list, so anyone can walk in and send email as you.',
		impact: 'Any server on the internet can send emails with your name on them, and nobody can tell they are fake.',
		adverseConsequences: 'Scammers freely use your name, your reputation suffers, and your real emails may start getting blocked too.',
		recommendation: "Add a TXT record with a valid SPF policy: v=spf1 include:<your-email-provider> -all",
		references: [
			'https://datatracker.ietf.org/doc/html/rfc7208',
			'https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/',
		],
	},
	SPF_BROAD_IP_RANGE: {
		title: 'Overly Broad SPF IP Range',
		severity: 'high',
		explanation:
			'Your email guest list approves a huge chunk of the internet instead of specific senders — like saying "anyone from this entire city can send mail as me."',
		impact: 'Millions of servers are on your approved list, including many you do not own or control.',
		adverseConsequences: 'Anyone who controls a server in that huge range can send emails as you and pass the guest list check.',
		recommendation:
			'Narrow the IP range to only include specific IPs or small subnets (/28 or smaller) that your mail servers use.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-5.6'],
	},
	SPF_DEPRECATED_PTR: {
		title: 'Deprecated SPF ptr Mechanism',
		severity: 'medium',
		explanation:
			'Your guest list uses an outdated lookup method that is slow and unreliable — like checking IDs by calling a phone number that sometimes does not answer.',
		impact: 'The guest list check takes longer and sometimes gives wrong answers, so some providers skip it entirely.',
		adverseConsequences: 'Your guest list works at some email providers but not others, making results unpredictable.',
		recommendation:
			'Replace ptr with explicit ip4: or ip6: mechanisms, or use include: to reference your mail provider.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7208#section-5.5'],
	},
	// --- Details-aware DMARC entries ---
	DMARC_NO_SUBDOMAIN_POLICY: {
		title: 'No DMARC Subdomain Policy',
		severity: 'low',
		explanation:
			'Your post office instructions cover the main address but do not specifically mention sub-addresses (subdomains). They inherit the main rules, but it is better to spell it out.',
		impact: 'Subdomains follow the parent rules by default, but without clear instructions the behavior may not be what you expect.',
		adverseConsequences: 'Scammers may target your subdomains, hoping the assumed rules have gaps.',
		recommendation: 'Add sp=reject (or sp=quarantine) to your DMARC record to explicitly control subdomain policy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_RELAXED_DKIM_ALIGNMENT: {
		title: 'Relaxed DKIM Alignment',
		severity: 'low',
		explanation:
			'Your seal-checking rules are loose — a wax seal from any sub-address (subdomain) also counts as valid for the main address. It is like accepting a staff badge from a branch office at headquarters.',
		impact: 'If a subdomain is compromised, its seal can be used to fake emails for the main domain.',
		adverseConsequences: 'Attackers who gain control of a subdomain can use it to send convincing fakes from your main domain.',
		recommendation: 'Consider setting adkim=s (strict) to require exact domain matching in DKIM signatures.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-3.1.1'],
	},
	DMARC_RELAXED_SPF_ALIGNMENT: {
		title: 'Relaxed SPF Alignment',
		severity: 'low',
		explanation:
			'Your guest list matching is loose — a subdomain\'s guest list also counts as valid for the main domain. It is like accepting a guest pass from a different building.',
		impact: 'A subdomain with its own guest list could be used to bypass the main domain\'s checks.',
		adverseConsequences: 'Attackers can exploit a subdomain\'s guest list to send fake emails that pass the main domain\'s checks.',
		recommendation: 'Consider setting aspf=s (strict) to require exact domain matching for SPF alignment.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-3.1.2'],
	},
	DMARC_NO_FORENSIC_REPORTING: {
		title: 'No DMARC Forensic Reporting',
		severity: 'low',
		explanation:
			'You are not getting detailed reports when individual emails fail the check — like a security guard who does not write down who they turned away.',
		impact: 'When something goes wrong with an email, you have no details to figure out what happened.',
		adverseConsequences: 'Tracking down email problems or spotting targeted scam attempts takes much longer without these reports.',
		recommendation:
			'Add a ruf= tag pointing to a mailbox for forensic reports. Note: not all receivers send forensic reports.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_POLICY_NONE: {
		title: 'DMARC Policy Set to None',
		severity: 'high',
		explanation:
			'Your post office instructions say "just take notes" when mail fails the check — do not throw it away, do not flag it, just write it down. Fake emails get delivered like normal.',
		impact: 'Forged emails sail right through to people\'s inboxes because the instructions say not to stop them.',
		adverseConsequences: 'You have the rules on paper but they do nothing — scammers can impersonate you freely.',
		recommendation:
			'After reviewing aggregate reports to confirm legitimate senders pass authentication, upgrade to p=quarantine, then p=reject.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_NO_AGGREGATE_REPORTING: {
		title: 'No DMARC Aggregate Reporting',
		severity: 'medium',
		explanation:
			'You are not getting summary reports about who is sending email as you — like a building with no security camera footage. You have no idea what is happening.',
		impact: 'Scammers could be sending thousands of fake emails as you right now and you would never know.',
		adverseConsequences: 'Problems go unnoticed for longer, and email issues silently pile up without anyone being alerted.',
		recommendation: 'Add a rua= tag with a mailto: URI to receive aggregate reports.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_POLICY_QUARANTINE: {
		title: 'DMARC Policy Set to Quarantine',
		severity: 'low',
		explanation:
			'Your post office instructions say "put suspicious mail in the junk pile" rather than throwing it away. The fake mail is set aside but not destroyed.',
		impact: 'Forged emails land in spam folders instead of being blocked, and some people check their spam regularly.',
		adverseConsequences: 'People who dig through their junk mail may still find and fall for the fake messages.',
		recommendation: 'Consider upgrading to p=reject for maximum protection, once all legitimate senders pass DMARC.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_MULTIPLE_RECORDS: {
		title: 'Multiple DMARC Records',
		severity: 'critical',
		explanation:
			'You have more than one set of post office instructions posted, and the mail system does not know which to follow — so it ignores both. You can only have one.',
		impact: 'Having two sets of instructions breaks the whole system — the post office stops following any of them.',
		adverseConsequences: 'Your domain has no working protection against fake emails, even though you tried to set it up.',
		recommendation: 'Remove duplicate DMARC records so only one TXT record exists at _dmarc.<domain>.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.6.3'],
	},
	DMARC_SUBDOMAIN_WEAKER: {
		title: 'Subdomain Policy Weaker Than Organization Policy',
		severity: 'medium',
		explanation:
			'Your main address has strict rules, but your sub-addresses (subdomains) have weaker ones — like locking the front door but leaving the side door unlocked.',
		impact: 'Attackers skip your strong front-door rules and sneak in through the weaker subdomain side door.',
		adverseConsequences: 'Fake emails from your subdomains pass the checks because the subdomain rules are too relaxed.',
		recommendation:
			'Set the subdomain policy (sp=) to be at least as strict as the parent policy (p=). Ideally use sp=reject when p=reject.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_PARTIAL_COVERAGE: {
		title: 'DMARC Partial Coverage',
		severity: 'medium',
		explanation:
			'Your post office instructions only apply to some of the suspicious mail, not all of it — like a bouncer who only checks every other person in line.',
		impact: 'A chunk of fake emails skip the rules entirely because the instructions say to only check a percentage.',
		adverseConsequences: 'Scammers know some of their fake emails will get through because you are only spot-checking.',
		recommendation:
			'Increase pct= to 100 (or remove it, as 100 is the default) once you have verified that legitimate senders pass DMARC.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_INVALID_POLICY: {
		title: 'Invalid DMARC Policy Value',
		severity: 'critical',
		explanation:
			'Your post office instructions are written in gibberish — the mail system cannot understand them, so it ignores them completely.',
		impact: 'The instructions are treated as if they do not exist because they contain an unreadable value.',
		adverseConsequences: 'You went through the effort of writing instructions, but they do nothing because they are not valid.',
		recommendation:
			'Correct the p= tag to one of the valid values: none, quarantine, or reject.',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	DMARC_MISSING_POLICY: {
		title: 'DMARC Record Missing Policy Tag',
		severity: 'critical',
		explanation:
			'Your post office instructions exist but forgot the most important part — what to actually do with suspicious mail. Without that, the whole note is useless.',
		impact: 'Mail systems see your instructions but cannot follow them because the key action is missing.',
		adverseConsequences: 'You set up the rules but left out the punchline, so fake emails get through as if the rules were not there.',
		recommendation: 'Add a p= tag to the DMARC record. Start with p=quarantine or p=reject: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>',
		references: ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3'],
	},
	// --- Details-aware DNSSEC entries ---
	DNSSEC_NO_DNSKEY: {
		title: 'No DNSKEY Records',
		severity: 'high',
		explanation:
			'Your address records are missing the notary\'s stamp entirely. Without it, there is no way to prove your records are genuine.',
		impact: 'Even if the parent directory has your notary on file, the actual records have no stamp to verify.',
		adverseConsequences: 'Your address records can be forged because there is nothing to prove they are the real ones.',
		recommendation: 'Enable DNSSEC through your DNS provider, which will automatically publish the required DNSKEY records.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc4034#section-2',
			'https://www.cloudflare.com/dns/dnssec/how-dnssec-works/',
		],
	},
	DNSSEC_NO_DS: {
		title: 'No DS Records',
		severity: 'medium',
		explanation:
			'The parent directory has not registered your notary — like having a notarized document but nobody at the courthouse can confirm the notary is real.',
		impact: 'Even though your records have a stamp, nobody can verify the stamp is legitimate because the parent has no record of it.',
		adverseConsequences: 'The whole notary chain is broken at the link to the parent, so your stamps are treated as unverified.',
		recommendation: 'Add DS records at your domain registrar. Most registrars provide a DNSSEC management interface.',
		references: ['https://datatracker.ietf.org/doc/html/rfc4034#section-5'],
	},
	DNSSEC_DEPRECATED_ALGORITHM: {
		title: 'Deprecated DNSSEC Algorithm',
		severity: 'high',
		explanation:
			'Your notary stamp uses an old, outdated method that is being retired — like a signature style that banks no longer accept.',
		impact: 'Some systems have already stopped trusting this old stamp method, and more will follow.',
		adverseConsequences: 'Over time, more and more systems will ignore your stamp, leaving your records unverified.',
		recommendation: 'Rotate to a modern algorithm such as ECDSAP256SHA256 (algorithm 13) or Ed25519 (algorithm 15).',
		references: ['https://datatracker.ietf.org/doc/html/rfc8624'],
	},
	DNSSEC_UNKNOWN_ALGORITHM: {
		title: 'Unknown DNSSEC Algorithm',
		severity: 'medium',
		explanation:
			'Your notary stamp uses an unknown method that most systems cannot read — like signing a document in an alphabet nobody recognizes.',
		impact: 'Most systems cannot verify your stamp because they do not understand the method used.',
		adverseConsequences: 'Your records are treated as unsigned because the stamp is unreadable to nearly everyone.',
		recommendation:
			'Switch to a widely supported algorithm such as ECDSAP256SHA256 (algorithm 13) or Ed25519 (algorithm 15).',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc8624',
			'https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml',
		],
	},
	DNSSEC_DEPRECATED_DS_DIGEST: {
		title: 'Deprecated DS Digest Type',
		severity: 'medium',
		explanation:
			'The fingerprint used to verify your notary stamp relies on an outdated method that has known flaws — like a padlock with a design flaw that thieves know how to exploit.',
		impact: 'Some systems have stopped trusting this old fingerprint method, and the notary chain may break.',
		adverseConsequences: 'As more systems drop support for the old method, your notarized records gradually lose their verification.',
		recommendation:
			'Add or migrate to SHA-256 (digest type 2) DS records. Contact your registrar to update the DS record.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc8624',
			'https://datatracker.ietf.org/doc/html/rfc4509',
		],
	},
	// --- Details-aware SSL entries ---
	SSL_NO_HSTS: {
		title: 'No HSTS Header',
		severity: 'medium',
		explanation:
			'Your site does not tell browsers to always use the padlock. On the first visit, browsers may try the unprotected route first — like unlocking the armored door before checking if it should be locked.',
		impact: 'First-time visitors briefly connect without protection, giving eavesdroppers a window to intercept.',
		adverseConsequences: 'Passwords and login sessions can be stolen during that brief unprotected moment, especially on public Wi-Fi.',
		recommendation:
			'Add a Strict-Transport-Security header: max-age=31536000; includeSubDomains. Consider HSTS preloading.',
		references: [
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
			'https://hstspreload.org/',
		],
	},
	SSL_NO_REDIRECT: {
		title: 'No HTTP to HTTPS Redirect',
		severity: 'medium',
		explanation:
			'Your site does not send visitors from the unprotected entrance to the padlocked one. People who type your address without "https" get the wide-open version.',
		impact: 'Visitors on the unprotected route send everything in plain sight — anyone on the network can read or change it.',
		adverseConsequences:
			'Private data is exposed on the open route, and search engines may list the unprotected version of your site.',
		recommendation:
			'Configure your web server to redirect all HTTP requests (port 80) to HTTPS (port 443) with a 301 redirect.',
		references: ['https://https.cio.gov/hsts/'],
	},
	SSL_HSTS_SHORT_MAXAGE: {
		title: 'HSTS Max-Age Too Short',
		severity: 'low',
		explanation: 'Your "always use the padlock" instruction expires too quickly — like a parking pass that only lasts a day instead of a year.',
		impact: 'The instruction wears off fast, creating regular gaps where browsers forget to use the protected route.',
		adverseConsequences: 'Returning visitors lose their padlock reminder sooner, leaving them exposed again.',
		recommendation: 'Set max-age to at least 31536000 (1 year). For HSTS preloading, 2 years is recommended.',
		references: [
			'https://hstspreload.org/',
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
		],
	},
	SSL_HSTS_NO_SUBDOMAINS: {
		title: 'HSTS Missing includeSubDomains',
		severity: 'low',
		explanation:
			'Your "always use the padlock" rule covers the main site but not your subdomains — like locking the front door but leaving all the side doors without locks.',
		impact: 'Your subdomains are still exposed to eavesdropping even though the main site is protected.',
		adverseConsequences: 'Attackers can target your subdomains to intercept data, and your site cannot join the browser preload list.',
		recommendation:
			'Add includeSubDomains to the Strict-Transport-Security header. Ensure all subdomains support HTTPS before enabling.',
		references: [
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
			'https://hstspreload.org/',
		],
	},
	// --- Details-aware MTA-STS entries ---
	MTA_STS_NO_RECORDS: {
		title: 'No MTA-STS Records Found',
		severity: 'medium',
		explanation:
			'Your domain has no rules requiring the mail truck to take the armored route, and no reporting on delivery safety. Attackers can force the truck onto an unprotected road.',
		impact: 'Someone on the network can trick the mail truck into skipping the armored route and delivering your email in the open.',
		adverseConsequences: 'Private email content can be read by eavesdroppers while it is being delivered to you.',
		recommendation:
			'Publish an MTA-STS TXT record at _mta-sts.<domain> and host a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt. Also add a TLS-RPT record.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461', 'https://datatracker.ietf.org/doc/html/rfc8460'],
	},
	MTA_STS_TESTING: {
		title: 'MTA-STS in Testing Mode',
		severity: 'low',
		explanation:
			'Your armored mail truck rule is in practice mode — it reports when the truck takes the unprotected road, but does not stop it. Email still gets delivered either way.',
		impact: 'You can see when email takes the unsafe route, but nothing blocks it from happening.',
		adverseConsequences: 'The monitoring works, but the actual protection is not turned on yet.',
		recommendation: 'After verifying all mail servers support TLS via the reports, switch to mode=enforce.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461#section-5'],
	},
	MTA_STS_POLICY_INACCESSIBLE: {
		title: 'MTA-STS Policy File Inaccessible',
		severity: 'high',
		explanation:
			'Your armored truck rules exist in the directory, but the actual instruction sheet is missing or unreachable — like posting a "see rules inside" sign on a locked, empty office.',
		impact: 'The armored truck rule is broken because nobody can read the instructions, so it is completely ignored.',
		adverseConsequences: 'Mail trucks skip the armored route because the instructions are unreachable, and some deliveries may be delayed.',
		recommendation: 'Host the MTA-STS policy file at the correct URL with proper HTTPS. Verify it returns HTTP 200.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461#section-3.2'],
	},
	MTA_STS_TLSRPT_MISSING: {
		title: 'TLS-RPT Record Missing',
		severity: 'low',
		explanation:
			'You are not getting delivery safety reports from other mail systems. It is like having no dashcam on the mail truck — if something goes wrong on the route, you will never know.',
		impact: 'When email delivery hits a security problem on the road, nobody tells you about it.',
		adverseConsequences: 'Problems with the armored route go undetected, and attacks on your email delivery are invisible.',
		recommendation: 'Add a TXT record at _smtp._tls.<domain> with v=TLSRPTv1; rua=mailto:tlsrpt@<domain>',
		references: ['https://datatracker.ietf.org/doc/html/rfc8460'],
	},
	MTA_STS_DISABLED: {
		title: 'MTA-STS Disabled',
		severity: 'medium',
		explanation:
			'Your armored truck rule is explicitly turned off — the sign says "no armor required." It is the same as having no rule at all.',
		impact: 'Email is delivered without any requirement for the protected route, even though you set up the system.',
		adverseConsequences: 'Attackers can force email onto the unprotected road and read it in transit.',
		recommendation:
			'Change the MTA-STS policy mode to "testing" to begin monitoring, then upgrade to "enforce" once all mail servers support TLS.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461#section-5'],
	},
	MTA_STS_SHORT_MAXAGE: {
		title: 'MTA-STS Max Age Too Short',
		severity: 'low',
		explanation:
			'Your armored truck rule expires too quickly — mail systems have to keep re-reading it, and between reads, they forget the rule and take whatever road is available.',
		impact: 'During the gaps when the rule has expired, mail trucks can take the unprotected road without breaking any rules.',
		adverseConsequences: 'These regular gaps create repeated windows where attackers can intercept your email in transit.',
		recommendation:
			'Set max_age to at least 604800 (1 week). For stable configurations, 2592000 (30 days) or longer is recommended.',
		references: ['https://datatracker.ietf.org/doc/html/rfc8461#section-3.2'],
	},
	// --- Details-aware NS entries ---
	NS_LOW_DIVERSITY: {
		title: 'Low Nameserver Diversity',
		severity: 'low',
		explanation:
			'All your phone book listings are stored with the same company. If that company has a bad day, nobody can look up your address anywhere.',
		impact: 'A single provider outage could make your domain invisible — nobody can find you.',
		adverseConsequences: 'Your website, email, and all online services go dark if that one provider goes down.',
		recommendation: 'For critical domains, consider adding a secondary DNS provider for cross-provider redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035#section-2.2'],
	},
	NS_SOA_EXPIRE_SHORT: {
		title: 'SOA Expire Too Short',
		severity: 'medium',
		explanation:
			'Your backup phone books give up too quickly when they cannot reach the main one — like a temp worker who quits after one day without hearing from the boss.',
		impact: 'If the main directory goes down, the backups throw away their copies sooner than they should.',
		adverseConsequences: 'A longer outage of the main directory causes everything to go dark instead of limping along with the backups.',
		recommendation: 'Set SOA expire to at least 604800 (1 week), or 1209600 (2 weeks) for critical zones.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1912#section-2.2'],
	},
	NS_SINGLE_NAMESERVER: {
		title: 'Single Nameserver',
		severity: 'high',
		explanation:
			'You only have one phone book listing for your domain — if that single directory goes down, nobody can find you. The rules say you need at least two.',
		impact: 'If that one directory fails, your entire domain disappears from the internet.',
		adverseConsequences: 'Total blackout for your website, email, and everything else — with no backup to fall back on.',
		recommendation: 'Add at least one additional nameserver, preferably on a different network.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1035#section-2.2'],
	},
	NS_NO_SOA: {
		title: 'No SOA Record Found',
		severity: 'high',
		explanation:
			'Your domain is missing its "headquarters record" — the master document that tells all the backup directories how to stay in sync. Without it, the system is fundamentally broken.',
		impact: 'The backup directories have no way to know who is in charge or how to keep their copies up to date.',
		adverseConsequences: 'Backup directories fall out of sync, and the whole system cannot figure out how long to remember your information.',
		recommendation: 'Ensure the zone has a valid SOA record. Contact your DNS provider if the zone is not properly configured.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.13',
			'https://datatracker.ietf.org/doc/html/rfc1912#section-2.2',
		],
	},
	NS_SOA_REFRESH_SHORT: {
		title: 'SOA Refresh Interval Too Short',
		severity: 'low',
		explanation:
			'Your backup directories check in with headquarters way too often — like an employee calling the boss every five minutes to ask "anything new?" It wastes resources for no real benefit.',
		impact: 'The constant check-ins use up bandwidth and server time without actually helping.',
		adverseConsequences: 'Your directory system is under unnecessary strain, and the overly frequent checks may signal a setup mistake.',
		recommendation:
			'Set the SOA refresh value to at least 3600 (1 hour). For stable zones, 14400 (4 hours) or longer is common.',
		references: ['https://datatracker.ietf.org/doc/html/rfc1912#section-2.2'],
	},
	NS_SOA_NEGATIVE_TTL_LONG: {
		title: 'SOA Negative TTL Too Long',
		severity: 'low',
		explanation:
			'When someone looks up a record that does not exist, the "not found" answer is remembered for too long — like a phone book that says "number not listed" and refuses to check again for days.',
		impact: 'New records you add take much longer to show up because everyone still remembers the old "not found" answer.',
		adverseConsequences: 'When you need to fix or add records quickly, the changes are slow to take effect across the internet.',
		recommendation:
			'Set the SOA minimum (negative caching) TTL to no more than 3600 (1 hour). RFC 2308 recommends values between 1 and 3 hours.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc2308',
			'https://datatracker.ietf.org/doc/html/rfc1912#section-2.2',
		],
	},
	// --- Details-aware CAA entries ---
	CAA_NO_ISSUE_TAG: {
		title: 'No CAA Issue Tag',
		severity: 'medium',
		explanation:
			'You have a locksmith rule posted, but it does not actually name which locksmiths are approved — like hanging a "restricted" sign without listing who is allowed.',
		impact: 'Without a specific approved list, the rule does not actually limit who can make keys for you.',
		adverseConsequences: 'Unapproved locksmiths (certificate providers) may still make keys for your domain.',
		recommendation: 'Add a CAA record with the "issue" tag: 0 issue "your-ca.com"',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659#section-4.2'],
	},
	CAA_NO_ISSUEWILD: {
		title: 'No CAA Issuewild Tag',
		severity: 'low',
		explanation:
			'Your locksmith rule does not specifically cover skeleton keys (wildcard certificates) that work on all your subdomains at once.',
		impact: 'Any approved locksmith can also make skeleton keys, even if you only wanted them making regular keys.',
		adverseConsequences: 'A skeleton key covering all your subdomains could be created without separate approval.',
		recommendation: 'Add a CAA "issuewild" tag: 0 issuewild "your-ca.com"',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659#section-4.3'],
	},
	CAA_NO_IODEF: {
		title: 'No CAA Iodef Tag',
		severity: 'low',
		explanation:
			'Your locksmith rule does not include a "call me if someone suspicious asks for keys" instruction. If an unapproved locksmith tries to make keys, nobody tells you.',
		impact: 'When someone tries to get an unapproved key made for your domain, the attempt goes unnoticed.',
		adverseConsequences: 'You have no way to find out if someone is trying to get fake keys made for your domain.',
		recommendation: 'Add a CAA "iodef" tag: 0 iodef "mailto:security@yourdomain.com"',
		references: ['https://datatracker.ietf.org/doc/html/rfc8659#section-4.4'],
	},
	CAA_NO_RECORDS: {
		title: 'No CAA Records',
		severity: 'medium',
		explanation:
			'You have no "approved locksmiths" rule at all — any locksmith in the world can make keys for your domain without asking you.',
		impact: 'There is nothing stopping any certificate provider from issuing a certificate for your domain.',
		adverseConsequences: 'Someone could get a fake key made and use it to impersonate your website or intercept your traffic.',
		recommendation: 'Add CAA records: 0 issue "letsencrypt.org" and 0 iodef "mailto:security@yourdomain.com"',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc8659',
			'https://www.cloudflare.com/learning/dns/dns-records/dns-caa-record/',
		],
	},
	// --- Details-aware MX entries ---
	MX_SINGLE_RECORD: {
		title: 'Single MX Record',
		severity: 'low',
		explanation:
			'You only have one mailbox for receiving email — if it breaks, there is no backup and all incoming mail bounces back to the sender.',
		impact: 'When your single mail server goes down, all incoming email fails — there is nowhere else for it to go.',
		adverseConsequences: 'Important messages bounce back and people cannot reach you by email until the server is fixed.',
		recommendation: 'Add at least one backup MX record with a higher priority number.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_POINTS_TO_IP: {
		title: 'MX Points to IP Address',
		severity: 'medium',
		explanation:
			'Your mailbox address uses a raw number instead of a proper name — like writing "123.45.67.89" on an envelope instead of a street address. Many mail systems will not accept it.',
		impact: 'Some email providers refuse to deliver to a raw number, so mail from those senders bounces.',
		adverseConsequences: 'Email delivery is hit-or-miss depending on which provider is sending to you.',
		recommendation: 'Change MX records to point to hostnames that resolve to A/AAAA records.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321#section-5.1'],
	},
	MX_DANGLING: {
		title: 'Dangling MX Record',
		severity: 'medium',
		explanation: 'Your mailbox points to an address that does not exist — like listing a delivery address for a building that was torn down.',
		impact: 'Email sent to this address fails because the destination simply is not there.',
		adverseConsequences: 'Senders keep trying to deliver and eventually give up, bouncing the message back. If all your mailboxes point to nowhere, no email gets through.',
		recommendation: 'Update or remove the MX record pointing to the unresolvable hostname.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321#section-5.1'],
	},
	MX_NO_RECORDS: {
		title: 'No MX Records Found',
		severity: 'medium',
		explanation:
			'Your domain has no mailbox address listed at all. Other mail systems do not know where to deliver email for you — like a house with no mailbox on the street.',
		impact: 'Email either bounces back or tries an unreliable back road to reach you, which often fails.',
		adverseConsequences: 'Incoming messages are lost or delayed, and your domain cannot work as an email address.',
		recommendation:
			'If this domain should receive email, add MX records pointing to your mail servers. If not, publish a null MX record (0 .) per RFC 7505 to explicitly indicate the domain does not accept email.',
		references: [
			'https://datatracker.ietf.org/doc/html/rfc5321',
			'https://datatracker.ietf.org/doc/html/rfc7505',
		],
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
		impact: 'Your email guest list has gaps, making it easier for others to send fake emails as you.',
		adverseConsequences: 'Scam emails using your name increase, and your support team spends more time dealing with them.',
	},
	DMARC: {
		impact: 'Your post office instructions are weak or missing, so fake emails get delivered anyway.',
		adverseConsequences: 'Forged emails reach people\'s inboxes more often, damaging your reputation.',
	},
	DKIM: {
		impact: 'Your email wax seal is weak or missing, so receivers cannot confirm your messages are genuine.',
		adverseConsequences: 'Your real emails may be flagged as suspicious while fakes become harder to spot.',
	},
	DNSSEC: {
		impact: 'Your address records lack a notarized signature, so they could be forged in transit.',
		adverseConsequences: 'Visitors could be redirected to fake versions of your site without knowing it.',
	},
	SSL: {
		impact: 'The padlock on your website connection is weak or missing, leaving visitors exposed.',
		adverseConsequences: 'Private data could be intercepted, and browsers may show warning messages to visitors.',
	},
	MTA_STS: {
		impact: 'Your armored mail truck rule is not fully working, so email may travel on unprotected roads.',
		adverseConsequences: 'Private email content could be read by eavesdroppers during delivery.',
	},
	NS: {
		impact: 'Your domain\'s phone book listings are not as reliable as they should be.',
		adverseConsequences: 'Visitors may experience outages or be unable to find your site and email.',
	},
	CAA: {
		impact: 'Your "approved locksmiths" rule is weak, so unapproved providers may issue certificates for you.',
		adverseConsequences: 'Someone could get a fake key for your domain and use it to impersonate your site.',
	},
	MX: {
		impact: 'Your mailbox address has issues that make email delivery unreliable.',
		adverseConsequences: 'Important emails may be delayed, bounced, or lost entirely.',
	},
	SUBDOMAIN_TAKEOVER: {
		impact: 'An abandoned subdomain may be sitting empty for someone to claim and impersonate you.',
		adverseConsequences: 'Visitors could be sent to a fake page hosted under your trusted name.',
	},
};

export const SEVERITY_FALLBACK_IMPACT: Record<string, ImpactNarrative> = {
	critical: {
		impact: 'This is a serious problem that someone could take advantage of right now.',
		adverseConsequences: 'Without a quick fix, your domain could be abused, disrupted, or impersonated.',
	},
	high: {
		impact: 'This is a significant gap that makes your domain much easier to attack.',
		adverseConsequences: 'Your business, users, and reputation can be hurt if this is not addressed.',
	},
	medium: {
		impact: 'This weakness on its own is manageable, but combined with other gaps it becomes a bigger problem.',
		adverseConsequences: 'Over time, reliability and trust erode as these issues stack up.',
	},
	warning: {
		impact: 'You have some protection in place, but it is not as strong as it could be.',
		adverseConsequences: 'Leaving this as-is makes problems harder to prevent or clean up when they happen.',
	},
	fail: {
		impact: 'Something important is missing or not working the way it should.',
		adverseConsequences: 'Until this is fixed, things are more likely to go wrong.',
	},
	low: {
		impact: 'This is a small weakness — not urgent, but still worth improving.',
		adverseConsequences: 'Minor issues can pile up and cause headaches down the road.',
	},
};

export const SPECIFIC_IMPACT_RULES: SpecificImpactRule[] = [
	{
		checkType: 'DKIM',
		titleIncludes: ['weak rsa key'],
		impact: 'A weak wax seal is easier to copy, making it simpler for someone to stamp fake emails.',
		adverseConsequences: 'Scammers can forge your seal more easily, making their fake emails look genuine.',
	},
	{
		checkType: 'SSL',
		titleIncludes: ['no hsts header', 'no http to https redirect', 'mixed content'],
		impact: 'Visitors can be pushed onto the unprotected route, where eavesdroppers can see everything.',
		adverseConsequences: 'Passwords and private data can leak on public Wi-Fi or hostile networks.',
	},
	{
		checkType: 'DMARC',
		titleIncludes: ['no aggregate reporting'],
		impact: 'You cannot see the big picture of who is sending email as you or how often fakes are being sent.',
		adverseConsequences: 'Problems go unnoticed longer, and scammers operate freely because you have no visibility.',
	},
	{
		checkType: 'MX',
		titleIncludes: ['no mx records found', 'mx configuration error'],
		impact: 'Incoming email delivery is broken or unreliable — messages may not arrive at all.',
		adverseConsequences: 'Important emails may bounce, get lost, or silently disappear.',
	},
	{
		checkType: 'NS',
		titleIncludes: ['no soa record', 'nameserver', 'low nameserver diversity'],
		impact: 'Your phone book listings are less reliable, increasing the chance people cannot find you online.',
		adverseConsequences: 'Outages can take down your website, email, and other services.',
	},
	{
		checkType: 'CAA',
		titleIncludes: ['no caa records', 'issuewild', 'iodef'],
		impact: 'Your approved locksmiths rule has gaps, especially for skeleton keys (wildcards) and reporting.',
		adverseConsequences: 'Unapproved keys could be made for your domain, and you might not find out about it.',
	},
	{
		checkType: 'SPF',
		titleIncludes: ['permissive spf policy', 'multiple spf records'],
		detailIncludes: ['+all', 'multiple records'],
		impact: 'Your email guest list is either wide open or broken, so anyone can send email as you.',
		adverseConsequences: 'Fake emails flood in, your real emails get blocked, and both problems happen at once.',
	},
	{
		checkType: 'MTA_STS',
		titleIncludes: ['no mta-sts', 'testing mode', 'tls-rpt'],
		impact: 'Your armored mail truck rule is not fully working, so email may travel on unprotected roads.',
		adverseConsequences: 'Private emails may be read by eavesdroppers during delivery because the armored route is not required.',
	},
];