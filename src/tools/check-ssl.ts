/**
 * SSL/TLS certificate check tool.
 * Validates SSL certificate by attempting HTTPS connection.
 * Workers-compatible: uses fetch API only.
 */

import {
  type CheckResult,
  type Finding,
  buildCheckResult,
  createFinding,
} from "../lib/scoring";

/**
 * Check SSL/TLS configuration for a domain.
 * Attempts HTTPS connection to verify certificate validity.
 */
export async function checkSsl(domain: string): Promise<CheckResult> {
  const findings: Finding[] = [];

  // Check HTTPS connectivity
  const httpsResult = await checkHttps(domain);
  findings.push(...httpsResult);

  // If no issues found, add info
  if (findings.length === 0) {
    findings.push(
      createFinding(
        "ssl",
        "SSL/TLS properly configured",
        "info",
        `HTTPS is accessible for ${domain}.`,
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


