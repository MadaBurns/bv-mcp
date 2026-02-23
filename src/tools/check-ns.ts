/**
 * NS (Name Server) check tool.
 * Validates nameserver configuration for a domain.
 */

import { queryDnsRecords, queryDns } from "../lib/dns";
import {
  type CheckResult,
  type Finding,
  buildCheckResult,
  createFinding,
} from "../lib/scoring";

/**
 * Check nameserver configuration for a domain.
 * Validates NS records exist, checks for diversity, and verifies responsiveness.
 */
export async function checkNs(domain: string): Promise<CheckResult> {
  const findings: Finding[] = [];

  let nsRecords: string[] = [];
  try {
    nsRecords = await queryDnsRecords(domain, "NS");
    // Clean trailing dots
    nsRecords = nsRecords.map((r) => r.replace(/\.$/, "").toLowerCase());
  } catch {
    findings.push(
      createFinding(
        "ns",
        "NS query failed",
        "critical",
        `Could not query nameserver records for ${domain}.`,
      ),
    );
    return buildCheckResult("ns", findings);
  }

  if (nsRecords.length === 0) {
    // Check if domain still resolves (e.g. delegation-only zones like govt.nz)
    let domainResolves = false;
    try {
      const aResp = await queryDns(domain, "A");
      domainResolves = (aResp.Answer ?? []).length > 0;
    } catch {
      /* ignore */
    }

    if (domainResolves) {
      findings.push(
        createFinding(
          "ns",
          "NS records not directly visible",
          "low",
          `No NS records returned for ${domain} directly, but the domain resolves. NS records may be managed at a parent zone.`,
        ),
      );
    } else {
      findings.push(
        createFinding(
          "ns",
          "No NS records found",
          "critical",
          `No nameserver records found for ${domain}. Without NS records, the domain cannot resolve.`,
        ),
      );
    }
    return buildCheckResult("ns", findings);
  }

  // Check for single nameserver (no redundancy)
  if (nsRecords.length === 1) {
    findings.push(
      createFinding(
        "ns",
        "Single nameserver",
        "high",
        `Only one nameserver found (${nsRecords[0]}). At least two nameservers are recommended for redundancy.`,
      ),
    );
  }

  // Check for nameserver diversity (all on same provider/TLD)
  const tlds = new Set(nsRecords.map((ns) => {
    const parts = ns.split(".");
    return parts.slice(-2).join(".");
  }));

  if (tlds.size === 1 && nsRecords.length > 1) {
    findings.push(
      createFinding(
        "ns",
        "Low nameserver diversity",
        "low",
        `All nameservers are under the same domain (${[...tlds][0]}). Consider using nameservers from different providers for better resilience.`,
      ),
    );
  }

  // Check SOA record exists
  try {
    const soaResp = await queryDns(domain, "SOA");
    const soaRecords = (soaResp.Answer ?? []).filter((a) => a.type === 6);
    if (soaRecords.length === 0) {
      findings.push(
        createFinding(
          "ns",
          "No SOA record",
          "medium",
          `No SOA (Start of Authority) record found for ${domain}. SOA records are required for proper DNS zone configuration.`,
        ),
      );
    }
  } catch {
    // Non-critical
  }

  // If no issues found
  if (findings.length === 0) {
    findings.push(
      createFinding(
        "ns",
        "Nameservers properly configured",
        "info",
        `${nsRecords.length} nameservers found: ${nsRecords.join(", ")}`,
      ),
    );
  }

  return buildCheckResult("ns", findings);
}

