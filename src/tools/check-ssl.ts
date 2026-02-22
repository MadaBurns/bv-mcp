/**
 * SSL/TLS certificate check tool.
 * Validates SSL certificate by attempting HTTPS connection and checking CAA records.
 * Workers-compatible: uses fetch API only.
 */

import { queryTxtRecords, queryDnsRecords } from "../lib/dns";
import {
  type CheckResult,
  type Finding,
  buildCheckResult,
  createFinding,
} from "../lib/scoring";

/**
 * Check SSL/TLS configuration for a domain.
 * Attempts HTTPS connection and checks CAA DNS records.
 */
export async function checkSsl(domain: string): Promise<CheckResult> {
  const findings: Finding[] = [];

  // Check HTTPS connectivity
  const httpsResult = await checkHttps(domain);
  findings.push(...httpsResult);

  // Check CAA records
  const caaResult = await checkCaa(domain);
  findings.push(...caaResult);

  // If no issues found, add info
  if (findings.length === 0) {
    findings.push(
      createFinding(
        "ssl",
        "SSL/TLS properly configured",
        "info",
        `HTTPS is accessible and CAA records are configured for ${domain}.`,
      ),
    );
  }

  return buildCheckResult("ssl", findings);
}

/** Check HTTPS connectivity by attempting a fetch */
async function checkHttps(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const response = await fetch(`https://${domain}`, {
      method: "HEAD",
      redirect: "follow",
      signal: AbortSignal.timeout(10_000),
    });

    // Check if we got redirected to HTTP (downgrade)
    if (response.url && response.url.startsWith("http://")) {
      findings.push(
        createFinding(
          "ssl",
          "HTTPS redirects to HTTP",
          "critical",
          `${domain} redirects HTTPS requests to HTTP, exposing traffic to interception.`,
        ),
      );
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);

    if (message.includes("timeout") || message.includes("abort")) {
      findings.push(
        createFinding(
          "ssl",
          "HTTPS connection timeout",
          "high",
          `Could not establish HTTPS connection to ${domain} within 10 seconds. The server may not support HTTPS.`,
        ),
      );
    } else {
      findings.push(
        createFinding(
          "ssl",
          "HTTPS connection failed",
          "critical",
          `Failed to connect to ${domain} over HTTPS: ${message}. The domain may not have a valid SSL certificate.`,
        ),
      );
    }
  }

  return findings;
}

/** Check CAA (Certificate Authority Authorization) DNS records */
async function checkCaa(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const caaRecords = await queryDnsRecords(domain, "CAA");

    if (caaRecords.length === 0) {
      findings.push(
        createFinding(
          "ssl",
          "No CAA records",
          "medium",
          `No CAA records found for ${domain}. CAA records restrict which Certificate Authorities can issue certificates for your domain, preventing unauthorized issuance.`,
        ),
      );
    } else {
      // Check if any "issue" or "issuewild" tags exist
      const hasIssue = caaRecords.some((r) => r.includes("issue"));
      const hasIssuewild = caaRecords.some((r) => r.includes("issuewild"));

      if (!hasIssue && !hasIssuewild) {
        findings.push(
          createFinding(
            "ssl",
            "CAA records missing issue tags",
            "medium",
            `CAA records exist but no "issue" or "issuewild" tags found. These tags are needed to restrict certificate issuance.`,
          ),
        );
      }
    }
  } catch {
    // CAA query failure is not critical
    findings.push(
      createFinding(
        "ssl",
        "CAA check failed",
        "low",
        `Could not query CAA records for ${domain}. This is non-critical but CAA records are recommended.`,
      ),
    );
  }

  return findings;
}

