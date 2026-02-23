/**
 * DKIM (DomainKeys Identified Mail) check tool.
 * Queries common DKIM selector TXT records and validates configuration.
 */

import { queryTxtRecords } from "../lib/dns";
import {
  type CheckResult,
  type Finding,
  buildCheckResult,
  createFinding,
} from "../lib/scoring";

/** Common DKIM selectors used by major email providers */
const COMMON_SELECTORS = [
  "default",
  "google",
  "selector1", // Microsoft 365
  "selector2", // Microsoft 365
  "k1",        // Mailchimp
  "s1",
  "s2",
  "mail",
  "dkim",
  "smtp",
];

/**
 * Check DKIM records for a domain.
 * Probes common selectors at <selector>._domainkey.<domain>.
 * Optionally accepts a specific selector to check.
 */
export async function checkDkim(
  domain: string,
  selector?: string,
): Promise<CheckResult> {
  const findings: Finding[] = [];
  const selectorsToCheck = selector ? [selector] : COMMON_SELECTORS;
  const foundSelectors: string[] = [];

  // Check each selector in parallel
  const results = await Promise.all(
    selectorsToCheck.map(async (sel) => {
      try {
        const records = await queryTxtRecords(`${sel}._domainkey.${domain}`);
        const dkimRecords = records.filter(
          (r) => r.toLowerCase().includes("v=dkim1") || r.includes("p="),
        );
        return { selector: sel, records: dkimRecords };
      } catch {
        return { selector: sel, records: [] };
      }
    }),
  );

  for (const result of results) {
    if (result.records.length > 0) {
      foundSelectors.push(result.selector);

      // Validate each DKIM record
      for (const record of result.records) {
        // Check for empty public key (revoked)
        if (/p=\s*;/i.test(record) || /p=\s*$/i.test(record)) {
          findings.push(
            createFinding(
              "dkim",
              `Revoked DKIM key: ${result.selector}`,
              "medium",
              `DKIM selector "${result.selector}" has an empty public key (p=), indicating the key has been revoked.`,
            ),
          );
        }

        // Check key type (should be rsa or ed25519)
        const keyType = record.match(/k=([^;\s]+)/i);
        if (keyType && !["rsa", "ed25519"].includes(keyType[1].toLowerCase())) {
          findings.push(
            createFinding(
              "dkim",
              `Unknown DKIM key type: ${keyType[1]}`,
              "medium",
              `DKIM selector "${result.selector}" uses unknown key type "${keyType[1]}". Expected "rsa" or "ed25519".`,
            ),
          );
        }

        // Check for testing mode
        if (/t=y/i.test(record)) {
          findings.push(
            createFinding(
              "dkim",
              `DKIM in testing mode: ${result.selector}`,
              "low",
              `DKIM selector "${result.selector}" is in testing mode (t=y). Verifiers may treat failures as non-fatal.`,
            ),
          );
        }
      }
    }
  }

  if (foundSelectors.length === 0) {
    findings.push(
      createFinding(
        "dkim",
        "No DKIM records found",
        "high",
        `No DKIM records found for ${domain} across common selectors (${COMMON_SELECTORS.join(", ")}). DKIM helps verify email authenticity and integrity.`,
      ),
    );
  } else if (findings.length === 0) {
    findings.push(
      createFinding(
        "dkim",
        "DKIM configured",
        "info",
        `DKIM records found for selectors: ${foundSelectors.join(", ")}`,
      ),
    );
  }

  return buildCheckResult("dkim", findings);
}

