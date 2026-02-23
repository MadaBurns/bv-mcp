/**
 * scan-domain orchestrator tool.
 * Runs all DNS security checks in parallel via Promise.all
 * and computes an overall security score.
 *
 * Uses in-memory cache with 5-minute TTL for scan results.
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

import {
  type CheckCategory,
  type CheckResult,
  type ScanScore,
  buildCheckResult,
  computeScanScore,
  createFinding,
} from "../lib/scoring";
import { cacheGet, cacheSet } from "../lib/cache";
import { validateDomain, sanitizeDomain } from "../lib/sanitize";
import { checkSpf } from "./check-spf";
import { checkDmarc } from "./check-dmarc";
import { checkDkim } from "./check-dkim";
import { checkDnssec } from "./check-dnssec";
import { checkSsl } from "./check-ssl";
import { checkMtaSts } from "./check-mta-sts";
import { checkNs } from "./check-ns";
import { checkCaa } from "./check-caa";

/** Cache key prefix for scan results */
const CACHE_PREFIX = "scan:";

export interface ScanDomainResult {
  domain: string;
  score: ScanScore;
  checks: CheckResult[];
  cached: boolean;
  timestamp: string;
  riskIndex?: Record<string, unknown>;
}

/**
 * Run a full DNS security scan on a domain.
 * Executes all checks in parallel and computes an overall score.
 *
 * @param domain - The domain to scan (will be validated and sanitized)
 * @returns Full scan result with score, individual check results, and metadata
 * @throws Error if domain validation fails
 */
export async function scanDomain(domain: string): Promise<ScanDomainResult> {
  // Validate domain
  const validation = validateDomain(domain);
  if (!validation.valid) {
    throw new Error(validation.error ?? "Invalid domain");
  }

  const cleanDomain = sanitizeDomain(domain);
  const cacheKey = `${CACHE_PREFIX}${cleanDomain}`;

  // Check cache first
  const cached = await cacheGet<ScanDomainResult>(cacheKey);
  if (cached) {
    return { ...cached, cached: true };
  }

  // Run all checks in parallel with individual error handling
  const checkResults = await Promise.all([
    safeCheck("spf", () => checkSpf(cleanDomain)),
    safeCheck("dmarc", () => checkDmarc(cleanDomain)),
    safeCheck("dkim", () => checkDkim(cleanDomain)),
    safeCheck("dnssec", () => checkDnssec(cleanDomain)),
    safeCheck("ssl", () => checkSsl(cleanDomain)),
    safeCheck("mta_sts", () => checkMtaSts(cleanDomain)),
    safeCheck("ns", () => checkNs(cleanDomain)),
    safeCheck("caa", () => checkCaa(cleanDomain)),
  ]);

  // Compute overall score from all check results
  const score = computeScanScore(checkResults);

  const result: ScanDomainResult = {
    domain: cleanDomain,
    score,
    checks: checkResults,
    cached: false,
    timestamp: new Date().toISOString(),
  };

  // Cache the result
  await cacheSet(cacheKey, result);

  return result;
}

/**
 * Run a single check with error handling.
 * If a check fails, returns a failed CheckResult with an error finding
 * instead of throwing, so other checks can still complete.
 */
async function safeCheck(
  category: CheckCategory,
  fn: () => Promise<CheckResult>,
): Promise<CheckResult> {
  try {
    return await fn();
  } catch (err) {
    const message = err instanceof Error ? err.message : "Check failed";
    const findings = [
      createFinding(category, `${category.toUpperCase()} check error`, "high", `Check failed: ${message}`),
    ];
    return buildCheckResult(category, findings);
  }
}

/**
 * Format a scan result as a human-readable text report.
 * Used by the MCP tool handler to return results.
 */
export function formatScanReport(result: ScanDomainResult): string {
  const lines: string[] = [];

  lines.push(`DNS Security Scan: ${result.domain}`);
  lines.push(`${"=".repeat(40)}`);
  lines.push(`Overall Score: ${result.score.overall}/100 (${result.score.grade})`);
  lines.push(`${result.score.summary}`);
  lines.push("");

  // Category breakdown
  lines.push("Category Scores:");
  lines.push("-".repeat(30));
  for (const [category, score] of Object.entries(result.score.categoryScores)) {
    const status = score >= 80 ? "✓" : score >= 50 ? "⚠" : "✗";
    lines.push(`  ${status} ${category.toUpperCase().padEnd(10)} ${score}/100`);
  }
  lines.push("");

  // Findings
  const nonInfoFindings = result.score.findings.filter((f) => f.severity !== "info");
  if (nonInfoFindings.length > 0) {
    lines.push("Findings:");
    lines.push("-".repeat(30));
    for (const finding of nonInfoFindings) {
      lines.push(`  [${finding.severity.toUpperCase()}] ${finding.title}`);
      lines.push(`    ${finding.detail}`);
    }
  } else {
    lines.push("No security issues found.");
  }

  if (result.cached) {
    lines.push("");
    lines.push("(Results served from cache)");
  }

  lines.push("");  lines.push('─'.repeat(40));
  if (result.riskIndex) {
    lines.push('Powered by BLACKVEIL Risk Index → https://blackveil.co.nz');
  } else {
    lines.push('Want continuous monitoring instead of one-off scans?');
    lines.push('→ https://blackveil.co.nz');
  }

  lines.push('');  lines.push(`Scan completed: ${result.timestamp}`);

  return lines.join("\n");
}

