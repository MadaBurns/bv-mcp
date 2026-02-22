/**
 * Explain Finding tool.
 * Provides static explanations for DNS security findings.
 * No AI binding required - uses a built-in knowledge base.
 */

import type { CheckCategory, Severity } from "../lib/scoring";

export interface ExplanationResult {
  title: string;
  category: CheckCategory;
  severity: Severity;
  explanation: string;
  recommendation: string;
  references: string[];
}

/** Static knowledge base of finding explanations */
const EXPLANATIONS: Record<string, Omit<ExplanationResult, "title" | "category" | "severity">> = {
  "No SPF record found": {
    explanation: "SPF (Sender Policy Framework) is a DNS TXT record that specifies which mail servers are authorized to send email on behalf of your domain. Without SPF, any server can send email pretending to be from your domain.",
    recommendation: "Add a TXT record to your domain's DNS with a valid SPF policy. Start with: v=spf1 include:<your-email-provider> -all",
    references: ["https://datatracker.ietf.org/doc/html/rfc7208", "https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/"],
  },
  "Multiple SPF records": {
    explanation: "RFC 7208 requires exactly one SPF record per domain. Multiple SPF records cause unpredictable behavior as receivers may pick any one of them.",
    recommendation: "Merge all SPF records into a single TXT record that includes all authorized senders.",
    references: ["https://datatracker.ietf.org/doc/html/rfc7208#section-3.2"],
  },
  "No DMARC record found": {
    explanation: "DMARC (Domain-based Message Authentication, Reporting & Conformance) builds on SPF and DKIM to provide email authentication policy. Without DMARC, receivers have no policy guidance for handling authentication failures.",
    recommendation: "Add a TXT record at _dmarc.<domain> with at minimum: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>",
    references: ["https://datatracker.ietf.org/doc/html/rfc7489", "https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/"],
  },
  "DMARC policy set to none": {
    explanation: "A DMARC policy of 'none' means receivers should not take action on emails that fail authentication. This is useful for monitoring but provides no protection against spoofing.",
    recommendation: "After reviewing DMARC reports, upgrade the policy to 'quarantine' or 'reject' to actively protect against spoofing.",
    references: ["https://datatracker.ietf.org/doc/html/rfc7489#section-6.3"],
  },
  "No DKIM records found": {
    explanation: "DKIM (DomainKeys Identified Mail) adds a digital signature to outgoing emails, allowing receivers to verify the email was sent by an authorized server and wasn't modified in transit.",
    recommendation: "Configure DKIM signing with your email provider. They will provide the DKIM DNS records to publish.",
    references: ["https://datatracker.ietf.org/doc/html/rfc6376", "https://www.cloudflare.com/learning/dns/dns-records/dns-dkim-record/"],
  },
  "DNSSEC not validated": {
    explanation: "DNSSEC adds cryptographic signatures to DNS records, preventing DNS spoofing and cache poisoning attacks. Without DNSSEC, attackers can redirect your domain's traffic.",
    recommendation: "Enable DNSSEC through your domain registrar and DNS provider. Most providers offer one-click DNSSEC activation.",
    references: ["https://datatracker.ietf.org/doc/html/rfc4033", "https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
  },
  "HTTPS connection failed": {
    explanation: "The domain does not have a valid SSL/TLS certificate or the HTTPS server is not responding. This means traffic to the domain is not encrypted.",
    recommendation: "Install a valid SSL/TLS certificate. Free certificates are available from Let's Encrypt or Cloudflare.",
    references: ["https://letsencrypt.org/", "https://www.cloudflare.com/ssl/"],
  },
  "No CAA records": {
    explanation: "CAA (Certificate Authority Authorization) records specify which Certificate Authorities are allowed to issue certificates for your domain. Without CAA, any CA can issue a certificate.",
    recommendation: "Add CAA DNS records to restrict certificate issuance. Example: 0 issue \"letsencrypt.org\"",
    references: ["https://datatracker.ietf.org/doc/html/rfc8659"],
  },
  "No MTA-STS record found": {
    explanation: "MTA-STS (Mail Transfer Agent Strict Transport Security) enforces TLS encryption for incoming email, preventing downgrade attacks where an attacker forces email to be sent unencrypted.",
    recommendation: "Publish an MTA-STS TXT record at _mta-sts.<domain> and host a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt",
    references: ["https://datatracker.ietf.org/doc/html/rfc8461"],
  },
};



/** Default explanation for unknown findings */
const DEFAULT_EXPLANATION: Omit<ExplanationResult, "title" | "category" | "severity"> = {
  explanation: "This finding indicates a potential security issue with your DNS configuration.",
  recommendation: "Review the finding details and consult your DNS provider's documentation for remediation steps.",
  references: ["https://www.cloudflare.com/learning/dns/what-is-dns/"],
};

/**
 * Get a static explanation for a DNS security finding.
 * Returns a detailed explanation, recommendation, and references.
 * Works without any AI binding - uses built-in knowledge base.
 */
export function explainFinding(
  title: string,
  category: CheckCategory,
  severity: Severity,
): ExplanationResult {
  const known = EXPLANATIONS[title] ?? DEFAULT_EXPLANATION;

  return {
    title,
    category,
    severity,
    ...known,
  };
}

/**
 * Format an explanation as a human-readable text block.
 */
export function formatExplanation(result: ExplanationResult): string {
  const lines = [
    `## ${result.title}`,
    `**Category:** ${result.category} | **Severity:** ${result.severity}`,
    "",
    `### What this means`,
    result.explanation,
    "",
    `### Recommendation`,
    result.recommendation,
    "",
    `### References`,
    ...result.references.map((r) => `- ${r}`),
  ];
  return lines.join("\n");
}