// SPDX-License-Identifier: BUSL-1.1
/**
 * test/generate-discovery-report.spec.ts
 * 
 * Automatically discovers brand domains, performs RDAP correlation, classifies
 * the findings, and generates a fully Blackveil-branded PDF report.
 */

import { describe, expect, it } from 'vitest';
import { writeFileSync, mkdirSync, readFileSync } from 'fs';
import { dirname, join } from 'path';
import { marked } from 'marked';
import { discoverBrandDomains } from '../src/tools/discover-brand-domains';
import { checkRdapLookup } from '../src/tools/check-rdap-lookup';
import { buildBrandAuditDepthSummary, type CandidateUniverseDepth } from '../src/lib/brand-audit-depth';
import { generatePdf } from '../src/lib/pdf-engine';
import { SERVER_VERSION } from '../src/lib/server-version';
import {
    McpHttpClient,
    type BrandDiscoveryResult,
    type RdapResult,
    type BrandAuditReportEnvelope,
    type BrandAuditStatusResult,
} from './helpers/mcp-http-client';
import {
    buildDiscoveryReportModel,
    buildDiscoveryReportSidecar,
    type BrandAuditFindingLike,
    type BrandAuditResultLike,
    type DiscoveryReportCandidate,
} from './helpers/discovery-report-model';
import {
    buildBrandAuditBatchStartArgs,
    buildLocalDiscoveryOptions,
    parseReportGenerationEnv,
} from './helpers/report-generation-options';
import { fetchBrandAuditReportWithRetry } from './helpers/brand-audit-report-fetch';

const CONSUMER_REGISTRARS = [
    'godaddy', 'namecheap', 'hostinger', 'tucows', 'enom', 'squarespace', 
    'wix', 'publicdomainregistry', 'dynadot', 'gandi', 'media elite', 
    'name.com', 'network solutions', 'hostgator', 'bluehost', 'ionos'
];

const target = process.env.TARGET_DOMAIN || 'TARGET_DOMAIN_PLACEHOLDER';
const isPlaceholder = !target || target === 'TARGET_DOMAIN_PLACEHOLDER';

const assetsDir = join(__dirname, '../assets');
const logoFullBase64 = readFileSync(join(assetsDir, 'bv-logo-full.png')).toString('base64');
const logoMarkBase64 = readFileSync(join(assetsDir, 'bv-logo-mark.png')).toString('base64');

function extractSummaryTiers(summaryMeta: Record<string, unknown> | undefined): Parameters<typeof buildDiscoveryReportSidecar>[1]['tiers'] | undefined {
    const topLevelTiers = summaryMeta?.tiers;
    if (topLevelTiers && typeof topLevelTiers === 'object' && !Array.isArray(topLevelTiers)) {
        return topLevelTiers as Parameters<typeof buildDiscoveryReportSidecar>[1]['tiers'];
    }
    const discoveryPerformance = summaryMeta?.discoveryPerformance;
    if (discoveryPerformance && typeof discoveryPerformance === 'object' && !Array.isArray(discoveryPerformance)) {
        const tiers = (discoveryPerformance as { tiers?: unknown }).tiers;
        if (tiers && typeof tiers === 'object' && !Array.isArray(tiers)) {
            return tiers as Parameters<typeof buildDiscoveryReportSidecar>[1]['tiers'];
        }
    }
    return undefined;
}

describe('report generation option plumbing', () => {
    it('defaults MCP brand_audit_batch_start requests to deep discovery', () => {
        const options = parseReportGenerationEnv({ TARGET_DOMAIN: 'example.com' });

        expect(buildBrandAuditBatchStartArgs('example.com', options)).toMatchObject({
            domains: ['example.com'],
            min_confidence: 0.1,
            format: 'json',
            depth: 'deep',
        });
    });

    it('allows standard depth only when explicitly requested', () => {
        const options = parseReportGenerationEnv({
            TARGET_DOMAIN: 'example.com',
            BV_REPORT_DEPTH: 'standard',
        });

        expect(buildBrandAuditBatchStartArgs('example.com', options).depth).toBe('standard');
        expect(buildLocalDiscoveryOptions(options).depth).toBe('standard');
    });

    it('parses comma-separated public brand aliases for MCP and local discovery paths', () => {
        const options = parseReportGenerationEnv({
            TARGET_DOMAIN: 'example.com',
            BV_BRAND_ALIASES: 'Example Corp, example-pay,  ,Example Corp',
        });

        expect(options.brandAliases).toEqual(['example corp', 'example-pay']);
        expect(buildBrandAuditBatchStartArgs('example.com', options)).toMatchObject({
            brand_aliases: ['example corp', 'example-pay'],
        });
        expect(buildLocalDiscoveryOptions(options)).toMatchObject({
            brand_aliases: ['example corp', 'example-pay'],
        });
    });

    it('extracts tier counters from brand-audit summary metadata', () => {
        expect(extractSummaryTiers({
            tiers: {
                tier0Count: 1,
                tier1Count: 3,
                tier2Count: 1,
                tier3Count: 0,
                tier4Count: 0,
            },
        })).toMatchObject({
            tier0Count: 1,
            tier1Count: 3,
            tier2Count: 1,
        });
    });

});

describe.skipIf(isPlaceholder)('Automated Report Generation', () => {
    it('generates the report for a target domain', async () => {
        const reportOptions = parseReportGenerationEnv(process.env);

        // Route through the deployed MCP worker when BV_MCP_ENDPOINT is set.
        // Server-side brand_audit_batch_start runs discovery + RDAP +
        // classification through the queue consumer (300s/target budget),
        // which is the only synchronous-tool-budget escape hatch big enough
        // for tier-1 brands. Local fallback keeps the runner usable in CI.
        const mcpEndpoint = process.env.BV_MCP_ENDPOINT;
        const mcpToken = process.env.BV_MCP_TOKEN || process.env.BV_API_KEY;
        const existingAuditId = process.env.BV_MCP_AUDIT_ID;
        const mcp = mcpEndpoint ? new McpHttpClient(mcpEndpoint, mcpToken) : null;
        if (mcp) {
            console.log(`[0/4] Initializing MCP session at ${mcpEndpoint}...`);
            await mcp.initialize();
        }

        let primaryRegistrar = 'Unknown';
        let primaryRegistrarSource = 'unknown';
        let auditId: string | null = null;
        let sourceResult: BrandAuditResultLike | null = null;
        const sourceMode = mcp ? 'mcp' : 'local';

        const lookupRegistrar = (rdap: RdapResult): { registrar: string; registrarSource: string } => {
            const rFind = rdap.findings.find(f => typeof f.metadata?.registrar === 'string' && (f.metadata.registrar as string).length > 0);
            return {
                registrar: rFind ? String(rFind.metadata!.registrar).trim() : 'Unknown',
                registrarSource: typeof rFind?.metadata?.registrarSource === 'string' ? String(rFind.metadata.registrarSource) : 'unknown',
            };
        };

        const severityForBucket = (bucket: DiscoveryReportCandidate['bucket']): string => {
            if (bucket === 'consolidated') return 'info';
            if (bucket === 'shadowIt') return 'medium';
            if (bucket === 'indeterminate') return 'low';
            return 'high';
        };

        const candidateFinding = (input: {
            domain: string;
            bucket: DiscoveryReportCandidate['bucket'];
            signals: string[];
            confidence: number;
            registrar: string;
            registrarSource: string;
            reasons: string[];
        }): BrandAuditFindingLike => ({
            category: 'brand_discovery',
            title: `Brand candidate: ${input.domain}`,
            severity: severityForBucket(input.bucket),
            detail: input.reasons.join(' — '),
            metadata: {
                candidate: input.domain,
                bucket: input.bucket,
                signals: input.signals,
                combinedConfidence: input.confidence,
                registrar: input.registrar,
                registrarSource: input.registrarSource,
                reasons: input.reasons,
            },
        });

        if (mcp) {
            if (existingAuditId) {
                auditId = existingAuditId;
                console.log(`[1/4] Verifying reusable brand audit ${auditId} for ${target}...`);
                const status = await mcp.callToolStructured<BrandAuditStatusResult>('brand_audit_status', { auditId });
                const summary = status.findings.find(f => f.metadata?.summary === true);
                const md = summary?.metadata;
                const targetStatus = md?.targets?.find((candidateTarget: { target?: string }) => candidateTarget.target === target);
                if (md?.status !== 'completed' || targetStatus?.status !== 'completed') {
                    throw new Error(`BV_MCP_AUDIT_ID=${auditId} is not completed for ${target}: parent=${md?.status ?? 'unknown'} target=${targetStatus?.status ?? 'missing'}`);
                }
                console.log(`[1/4] Reusing completed brand audit ${auditId} for ${target}.`);
            } else {
                console.log(`[1/4] Enqueueing brand audit for ${target} (depth=${reportOptions.depthMode}, queue: 300s/target budget)...`);
                const startText = await mcp.callToolText('brand_audit_batch_start', buildBrandAuditBatchStartArgs(target, reportOptions));
                const idMatch = /auditId=([a-f0-9-]{8,})/i.exec(startText);
                if (!idMatch) throw new Error(`Could not extract auditId from batch_start response: ${startText.slice(0, 200)}`);
                auditId = idMatch[1];
                console.log(`auditId=${auditId}`);

                console.log(`[2/4] Polling brand_audit_status (5s interval, ~3min ETA)...`);
                const pollStartedAt = Date.now();
                const pollDeadline = Date.now() + 270_000;
                let lastProgress = '';
                let lastParentStatus = 'unknown';
                let lastTargetStatus = 'unknown';
                while (true) {
                    const status = await mcp.callToolStructured<BrandAuditStatusResult>('brand_audit_status', { auditId });
                    const summary = status.findings.find(f => f.metadata?.summary === true);
                    const md = summary?.metadata;
                    const progress = md?.progress ?? '?/?';
                    const target0 = md?.targets?.[0];
                    lastParentStatus = String(md?.status ?? 'unknown');
                    lastTargetStatus = String(target0?.status ?? 'unknown');
                    if (progress !== lastProgress) {
                        console.log(`  status=${lastParentStatus} target=${lastTargetStatus} progress=${progress}`);
                        lastProgress = progress;
                    }
                    if (md?.status === 'completed' && target0?.status === 'completed') break;
                    if (md?.status === 'failed' || target0?.status === 'failed') {
                        throw new Error(`brand_audit failed: ${target0?.error ?? 'unknown error'}`);
                    }
                    if (Date.now() > pollDeadline) {
                        const elapsedMs = Date.now() - pollStartedAt;
                        throw new Error(`brand_audit_status polling timed out after ${elapsedMs}ms auditId=${auditId} parentStatus=${lastParentStatus} targetStatus=${lastTargetStatus} progress=${progress}. Reuse command: BV_MCP_AUDIT_ID=${auditId} npm run generate-report -- ${target}`);
                    }
                    await new Promise(r => setTimeout(r, 5_000));
                }
            }

            console.log(`[3/4] Fetching report and classifying candidates...`);
            const { result: inner } = await fetchBrandAuditReportWithRetry({
                auditId,
                target,
                callTool: (args) => mcp.callToolStructured<BrandAuditReportEnvelope>('brand_audit_get_report', args),
                onRetry: (attempt) => {
                    console.log(`  retry ${attempt}/5 for brand_audit_get_report (completed row not readable yet)`);
                },
            });

            const innerSummary = inner.findings.find(f => f.metadata?.summary === true);
            if (typeof innerSummary?.metadata?.targetRegistrar === 'string') {
                primaryRegistrar = innerSummary.metadata.targetRegistrar;
            }
            console.log(`Primary Registrar: ${primaryRegistrar}`);

            sourceResult = inner;
            const preview = buildDiscoveryReportModel({ target, primaryRegistrar, result: inner });
            console.log(`Classified ${preview.counts.consolidated + preview.counts.shadowIt + preview.counts.indeterminate + preview.counts.impersonation} candidates: ${preview.counts.consolidated} consolidated, ${preview.counts.shadowIt} shadowIt, ${preview.counts.indeterminate} indeterminate, ${preview.counts.impersonation} impersonation`);
        } else {
            console.log(`[1/4] Looking up primary registrar for ${target} (local)...`);
            try {
                const rdap = (await checkRdapLookup(target)) as RdapResult;
                const lookup = lookupRegistrar(rdap);
                primaryRegistrar = lookup.registrar;
                primaryRegistrarSource = lookup.registrarSource;
            } catch (e) {
                console.warn(`Failed to lookup primary registrar: ${(e as Error).message}`);
            }
            console.log(`Primary Registrar: ${primaryRegistrar}`);

            console.log(`[2/4] Running brand discovery (local)...`);
            const result = (await discoverBrandDomains(target, buildLocalDiscoveryOptions(reportOptions))) as BrandDiscoveryResult;
            const discoverySummary = result.findings.find(f => f.metadata?.summary === true);
            const discoveryCandidateUniverse = (discoverySummary?.metadata?.candidateUniverse as CandidateUniverseDepth | undefined) ?? {
                seeded: 0,
                probed: 0,
                surfaced: 0,
                dropped: {},
                sources: {},
            };
            const discoverySignalStatus = (discoverySummary?.metadata?.signalStatus as Record<string, { status: string; error?: string }> | undefined) ?? {};
            const candidates = new Map<string, { domain: string; confidence: number; signals: string[] }>();
            for (const finding of result.findings) {
                if (finding.metadata?.candidate) {
                    const cand = finding.metadata.candidate as string;
                    const conf = finding.metadata.combinedConfidence as number;
                    const sigs = finding.metadata.signals as string[];
                    if (!candidates.has(cand) || conf > (candidates.get(cand)!.confidence)) {
                        candidates.set(cand, { domain: cand, confidence: conf, signals: sigs });
                    }
                }
            }
            const uniqueCandidates = Array.from(candidates.values()).sort((a, b) => b.confidence - a.confidence);
            console.log(`Discovered ${uniqueCandidates.length} unique candidates.`);

            console.log(`[3/4] Analyzing candidates (local)...`);
            const primaryRegLower = primaryRegistrar.toLowerCase();
            const isPrimaryCore = primaryRegLower !== 'unknown' && primaryRegLower.length > 3;
            const RDAP_CONCURRENCY = 16;
            const rdapTargets = uniqueCandidates.filter(c => !(c.signals.length === 1 && c.signals[0] === 'markov_gen'));
            const candidateRegistrars = new Map<string, { registrar: string; registrarSource: string }>();
            for (let i = 0; i < rdapTargets.length; i += RDAP_CONCURRENCY) {
                const chunk = rdapTargets.slice(i, i + RDAP_CONCURRENCY);
                const results = await Promise.allSettled(chunk.map(c => checkRdapLookup(c.domain) as Promise<RdapResult>));
                results.forEach((r, idx) => {
                    let lookup = { registrar: 'Unknown', registrarSource: 'unknown' };
                    if (r.status === 'fulfilled') {
                        lookup = lookupRegistrar(r.value);
                    }
                    candidateRegistrars.set(chunk[idx].domain, lookup);
                });
            }
            const localFindings: BrandAuditFindingLike[] = [];
            for (const cand of uniqueCandidates) {
                const lookup = candidateRegistrars.get(cand.domain) ?? { registrar: 'Unknown', registrarSource: 'unknown' };
                const candRegistrar = lookup.registrar;
                const candRegLower = candRegistrar.toLowerCase();
                let isMatch = false;
                if (isPrimaryCore && candRegLower !== 'unknown') {
                    const words1 = primaryRegLower.split(/[\s,.]+/).filter(w => w.length > 3);
                    const words2 = candRegLower.split(/[\s,.]+/).filter(w => w.length > 3);
                    isMatch = words1.some(w => words2.includes(w));
                }
                const deterministicSignals = cand.signals.filter(s => s === 'ns' || s === 'dkim_key_reuse' || s === 'dmarc_rua');
                const hasDeterministic = deterministicSignals.length > 0;
                const onlyMarkov = cand.signals.length === 1 && cand.signals[0] === 'markov_gen';
                const registrarsKnown = primaryRegLower !== 'unknown' && candRegLower !== 'unknown';
                let bucket: DiscoveryReportCandidate['bucket'];
                const reasons: string[] = [];
                if (isMatch || (registrarsKnown && candRegLower === primaryRegLower)) {
                    bucket = 'consolidated';
                    reasons.push('shared registrar family');
                } else if (onlyMarkov) {
                    bucket = 'impersonation';
                    reasons.push('markov-only lookalike');
                } else if (!registrarsKnown && hasDeterministic) {
                    bucket = 'consolidated';
                    reasons.push(`deterministic signal(s) with unavailable registrar: ${deterministicSignals.join(', ')}`);
                } else if (!registrarsKnown) {
                    bucket = 'indeterminate';
                    reasons.push('registrar unavailable and no deterministic ownership signal');
                } else {
                    const isConsumer = CONSUMER_REGISTRARS.some(r => candRegLower.includes(r));
                    if (isConsumer && cand.confidence < 0.8) {
                        bucket = 'impersonation';
                        reasons.push('consumer registrar with sub-threshold confidence');
                    } else if (!hasDeterministic && cand.confidence < 0.7) {
                        bucket = 'indeterminate';
                        reasons.push('non-deterministic evidence below Shadow IT threshold');
                    } else {
                        bucket = 'shadowIt';
                        reasons.push('non-aligned registrar with correlated infrastructure');
                    }
                }
                localFindings.push(candidateFinding({
                    domain: cand.domain,
                    bucket,
                    signals: cand.signals,
                    confidence: cand.confidence,
                    registrar: candRegistrar,
                    registrarSource: lookup.registrarSource,
                    reasons,
                }));
            }
            sourceResult = {
                category: 'brand_discovery',
                passed: true,
                score: 100,
                findings: [
                    {
                        category: 'brand_discovery',
                        title: `Brand audit: ${localFindings.length} candidate(s) classified for ${target}`,
                        severity: 'info',
                        detail: `local report fallback classified ${localFindings.length} candidate(s)`,
                        metadata: {
                            summary: true,
                            target,
                            targetRegistrar: primaryRegistrar,
                            depth: buildBrandAuditDepthSummary({
                                candidateUniverse: discoveryCandidateUniverse,
                                signalStatus: discoverySignalStatus,
                                registrarSources: [
                                    primaryRegistrarSource as 'rdap' | 'whois' | 'redacted' | 'notfound' | 'unknown',
                                    ...uniqueCandidates.map((candidate) =>
                                        (candidateRegistrars.get(candidate.domain)?.registrarSource ?? 'unknown') as 'rdap' | 'whois' | 'redacted' | 'notfound' | 'unknown',
                                    ),
                                ],
                            }),
                        },
                    },
                    ...localFindings,
                ],
            };
        }

        if (!sourceResult) throw new Error('No discovery result available for report generation.');

        const reportModel = buildDiscoveryReportModel({ target, primaryRegistrar, result: sourceResult });
        const { consolidated, shadowIt, indeterminate, impersonation } = reportModel.buckets;
        const generatedAt = new Date();
        const dateStr = generatedAt.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
        const targetUpper = target.toUpperCase();
        const registrarCell = (cand: DiscoveryReportCandidate): string => cand.registrarSource === 'unknown'
            ? cand.registrar
            : `${cand.registrar} (${cand.registrarSource})`;
        const depth = reportModel.depth;
        const depthWarnings = depth?.warnings ?? [];
        const executiveScope = depthWarnings.length > 0
            ? `This intelligence report maps observed domain architecture and cryptographic footprint associated with **${target}**. Discovery depth warnings are present, so the results should be treated as a coverage-qualified portfolio view rather than a definitive mapping.`
            : `This intelligence report provides a definitive mapping of the domain architecture and cryptographic footprint associated with **${target}**.`;
        const discoveryDepthSection = depth
            ? `
## Discovery Depth
This run seeded **${depth.candidateUniverse.seeded}** candidate domain(s), probed **${depth.candidateUniverse.probed}**, and surfaced **${depth.candidateUniverse.surfaced}** for classification. Registrar coverage known ratio: **${Math.round(depth.registrarCoverage.knownRatio * 100)}%**.

${depthWarnings.length > 0
    ? `Depth warnings:\n${depthWarnings.map(warning => `- ${warning}`).join('\n')}`
    : 'No discovery-depth warnings were emitted for this run.'}
`
            : '';

        let md = `<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;500;700&family=JetBrains+Mono:wght@400;700&family=Manrope:wght@200;400;600&display=swap');

  body {
    font-family: 'Manrope', sans-serif;
    background-color: #000000;
    color: #E0E0E0;
    line-height: 1.6;
    font-weight: 300;
    margin: 0;
    padding: 0;
  }
  .header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 1px solid #2A2A2A;
    padding-bottom: 32px;
    margin-bottom: 48px;
  }
  .header-info {
    text-align: right;
    color: #888888;
    font-size: 0.75rem;
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    line-height: 1.8;
  }
  .header-info strong {
    color: #00FF9D;
    font-weight: 700;
  }
  h1, h2, h3, h4 {
    font-family: 'Space Grotesk', sans-serif;
    color: #FFFFFF;
    letter-spacing: -0.02em;
    margin-top: 2em;
    margin-bottom: 1em;
  }
  h1 {
    font-size: 3rem;
    font-weight: 700;
    line-height: 1;
    margin-top: 0;
    background: linear-gradient(to bottom, #FFFFFF 0%, #888888 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  h2 {
    font-size: 1.5rem;
    font-weight: 500;
    border-left: 3px solid #00FF9D;
    padding-left: 16px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  p { margin-bottom: 1.5em; }
  
  table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    margin: 32px 0;
    background-color: #0A0A0A;
    border: 1px solid #1A1A1A;
    border-radius: 8px;
    overflow: hidden;
  }
  th {
    background-color: #111111;
    color: #888888;
    text-align: left;
    padding: 14px 20px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    border-bottom: 1px solid #1A1A1A;
  }
  td {
    padding: 16px 20px;
    border-bottom: 1px solid #111111;
    font-size: 0.85rem;
  }
  tr:last-child td { border-bottom: none; }
  
  .status-pass { color: #00FF9D; font-weight: 600; font-family: 'JetBrains Mono', monospace; }
  .status-warn { color: #FFB300; font-weight: 600; font-family: 'JetBrains Mono', monospace; }
  .status-fail { color: #FF3B30; font-weight: 600; font-family: 'JetBrains Mono', monospace; }
  
  .evidence { 
    font-family: 'JetBrains Mono', monospace; 
    font-size: 0.7rem; 
    color: #AAAAAA; 
    background: #151515; 
    padding: 4px 10px; 
    border-radius: 4px; 
    border: 1px solid #222222; 
  }
  
  .revenue-box {
    background: linear-gradient(135deg, #0A0A0A 0%, #111111 100%);
    border: 1px solid #1A1A1A;
    border-left: 4px solid #00FF9D;
    padding: 32px;
    margin: 48px 0;
    border-radius: 0 12px 12px 0;
  }
  .revenue-box h3 { margin-top: 0; color: #00FF9D; font-size: 1.2rem; }
  .revenue-box table { background: transparent; border: none; margin: 16px 0 0 0; }
  .revenue-box th { background: transparent; border-bottom: 1px solid #222222; }
  .revenue-box td { border-bottom: 1px solid #151515; }
  
  .logo {
    filter: brightness(1.2);
  }
</style>

<div class="header">
  <div>
    <img src="data:image/png;base64,${logoFullBase64}" width="220" class="logo" alt="Blackveil Security" />
  </div>
  <div class="header-info">
    <strong>Discovery Intel Report</strong><br>
    Asset: ${targetUpper}<br>
    Ref: BV-${target.substring(0,3).toUpperCase()}-${generatedAt.getTime().toString().slice(-6)}<br>
    Auth: Enterprise Tier
  </div>
</div>

# Infrastructure Audit: ${target}

## Executive Summary
${executiveScope} Leveraging the Blackveil Multi-Signal Correlation Engine, we have identified primary infrastructure, discovered "Shadow IT" Managed by third-party vendors, and assessed potential impersonation risks.

Our analysis separates verified infrastructure, Shadow IT opportunities, indeterminate candidates that require manual review, and likely impersonation risk. Registrar gaps are preserved in the JSON sidecar instead of being silently folded into revenue counts.

${discoveryDepthSection}

## 1. Primary Corporate Infrastructure
The following assets are verified as core components of the ${target} portfolio, currently consolidated under the master enterprise registrar (**${primaryRegistrar}**).

| Verified Asset | Correlation Signal | Registrar | State |
| :--- | :--- | :--- | :--- |
| **${target}** | [ROOT SEED] | ${primaryRegistrar} | <span class="status-pass">CONSOLIDATED</span> |
`;

        for (const cand of consolidated) {
            md += `| **${cand.domain}** | <span class="evidence">${cand.evidence}</span> | ${registrarCell(cand)} | <span class="status-pass">✅ Consolidated</span> |\n`;
        }

        if (consolidated.length === 0) {
            md += `| *No additional consolidated domains found* | - | - | - |\n`;
        }

        md += `
---

## 2. Discovered Shadow IT / Vendor Sprawl
The Blackveil engine successfully correlated the following domains to ${target}'s infrastructure (via shared cryptographic keys, DMARC reporting endpoints, and custom nameserver pools). However, WHOIS analysis reveals these domains are registered at a **competing registrar**, indicating portfolio fragmentation and vendor sprawl.

*These represent immediate consolidation opportunities for the primary registrar.*

| Discovered Domain | Correlation Evidence | Verified Registrar | Status |
| :--- | :--- | :--- | :--- |
`;

        for (const cand of shadowIt) {
            md += `| **${cand.domain}** | <span class="evidence">${cand.evidence}</span> | ${registrarCell(cand)} | <span class="status-warn">🟡 Consolidation Target</span> |\n`;
        }

        if (shadowIt.length === 0) {
            md += `| *No shadow IT domains found* | - | - | - |\n`;
        }

        md += `
---

## 3. Indeterminate / Manual Review
These candidates have incomplete registrar data, redacted ownership metadata, or non-deterministic correlation signals. They are preserved for review but excluded from the revenue projection until ownership is verified.

| Review Domain | Evidence Gap | Verified Registrar | Status |
| :--- | :--- | :--- | :--- |
`;

        for (const cand of indeterminate) {
            const reason = cand.reasons[0] ?? cand.evidence;
            md += `| **${cand.domain}** | <span class="evidence">${reason}</span> | ${registrarCell(cand)} | <span class="status-warn">Manual Review</span> |\n`;
        }

        if (indeterminate.length === 0) {
            md += `| *No indeterminate domains found* | - | - | - |\n`;
        }

        md += `
---

## 4. High-Risk Impersonation Threats
During the analysis, external domains exhibiting high visual similarity (lookalikes) or low confidence signal overlaps were evaluated against the infrastructure correlation engine. The following domains are registered at consumer-grade registrars or exhibit no strong shared infrastructure with ${target}, indicating they are unauthorized and potentially adversarial.

| Threat Domain | Discrepancy Evidence | Verified Registrar | Status |
| :--- | :--- | :--- | :--- |
`;

        for (const cand of impersonation) {
            md += `| **${cand.domain}** | <span class="evidence">${cand.evidence}</span> | ${registrarCell(cand)} | <span class="status-fail">🚨 High Risk (Phishing)</span> |\n`;
        }

        if (impersonation.length === 0) {
            md += `| *No high-risk impersonation domains found* | - | - | - |\n`;
        }

        const arrOpportunity = reportModel.arrOpportunity;

        md += `
---

## 5. Revenue & Consolidation Opportunity

Based on the discovery of ${arrOpportunity.domainCount} verified high-value Shadow IT domains, the following is a projection of the immediate revenue opportunity for the primary registrar to consolidate and secure this fragmented infrastructure. ${indeterminate.length} indeterminate candidate(s) are excluded until manual review confirms ownership.

<div class="revenue-box">
  <h3>Estimated Annual Recurring Revenue (ARR) Gain</h3>
  <table style="margin-top: 10px;">
    <tr>
      <th>Service Line</th>
      <th>Unit Economics</th>
      <th>Opportunity Value</th>
    </tr>
    <tr>
	      <td><strong>Domain Transfer & Renewals</strong></td>
	      <td>${arrOpportunity.domainCount} domains @ $150/yr (Enterprise Tier)</td>
	      <td><strong>$${arrOpportunity.domainRenewals.toLocaleString()} / yr</strong></td>
	    </tr>
	    <tr>
	      <td><strong>Managed Premium DNS</strong></td>
	      <td>${arrOpportunity.domainCount} domains @ $2,000/yr (UltraDNS SLA match)</td>
	      <td><strong>$${arrOpportunity.managedDns.toLocaleString()} / yr</strong></td>
	    </tr>
	    <tr>
	      <td><strong>Advanced Security Monitoring (Blackveil)</strong></td>
	      <td>${arrOpportunity.domainCount} domains @ $1,200/yr (Continuous Auditing)</td>
	      <td><strong>$${arrOpportunity.securityMonitoring.toLocaleString()} / yr</strong></td>
	    </tr>
	    <tr>
	      <td colspan="2" style="text-align: right; font-weight: bold; font-size: 16px;">Total Identified ARR Opportunity:</td>
	      <td style="font-weight: bold; font-size: 16px; color: #00FF9D;">$${arrOpportunity.total.toLocaleString()} / yr</td>
    </tr>
  </table>
  <p style="font-size: 12px; margin-top: 10px; color: #bfbfbf;"><em>* Note: This represents the opportunity from a single discovery run on a small subset of candidate domains. A full portfolio scan typically yields 10x-50x more candidates.</em></p>
</div>

## Strategic Recommendations
1. **Portfolio Consolidation:** Present the cryptographic evidence to the ${target} security team to initiate transfer procedures for the ${shadowIt.length} verified Shadow IT domains currently managed by competing registrars.
2. **Manual Review:** Resolve registrar gaps for the ${indeterminate.length} indeterminate candidates before including them in commercial opportunity totals.
3. **Defensive Action:** Forward the details of the unauthorized lookalike domains to the brand protection and legal teams for immediate takedown or UDRP proceedings.
4. **Continuous Monitoring:** Enroll the newly discovered Shadow IT domains into the Blackveil automated security scanning tier to ensure compliance with corporate baseline policies (DMARC, DNSSEC, etc.).

***
*Generated automatically by the Blackveil DNS Multi-Tenant Orchestrator. Powered by Blackveil Security.*
`;

        const html = await marked.parse(md);
        const pdfBuffer = await generatePdf(html, {
            displayHeaderFooter: true,
            headerTemplate: `
                <div style="width: 100%; font-size: 8px; padding: 10px 40px; display: flex; justify-content: space-between; align-items: center; font-family: 'Space Grotesk', sans-serif; color: #bfbfbf;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <img src="data:image/png;base64,${logoMarkBase64}" width="16" style="filter: invert(1) brightness(2);" />
                        <span style="letter-spacing: 0.05em;">BLACKVEIL SECURITY - PROPRIETARY & CONFIDENTIAL</span>
                    </div>
                    <span>${targetUpper} INFRASTRUCTURE AUDIT</span>
                </div>`,
            footerTemplate: `
                <div style="width: 100%; font-size: 8px; padding: 10px 40px; display: flex; justify-content: space-between; font-family: 'Space Grotesk', sans-serif; color: #bfbfbf; border-top: 1px solid #1f1f1f;">
                    <span>Generated on ${dateStr}</span>
                    <span style="color: #00FF9D; font-weight: 600;">BLACKVEIL DNS ORCHESTRATOR v${SERVER_VERSION}</span>
                    <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
                </div>`,
            margin: {
                top: '60px',
                bottom: '60px',
                left: '40px',
                right: '40px'
            }
        });

        const reportsDir = join(__dirname, '../reports');
        try { mkdirSync(reportsDir, { recursive: true }); } catch {}
        
        const filePath = process.env.BV_REPORT_PDF_PATH || join(reportsDir, `${target}-discovery-report.pdf`);
        mkdirSync(dirname(filePath), { recursive: true });
        writeFileSync(filePath, pdfBuffer);
        const sidecarPath = process.env.BV_REPORT_JSON_PATH || join(reportsDir, `${target}-discovery-report.json`);
        mkdirSync(dirname(sidecarPath), { recursive: true });
        // Forward pipeline-stamped tiered-mode metadata from the brand_audit
        // report envelope so the sidecar emits the v3 shape when tiered mode
        // ran. Pipeline stamps discoveryMode + top-level tiers on the summary
        // finding only when effectiveDiscoveryMode === 'tiered'.
        const sourceSummary = sourceResult?.findings?.find?.((f: { metadata?: Record<string, unknown> }) => f.metadata?.summary === true);
        const summaryMeta = sourceSummary?.metadata as Record<string, unknown> | undefined;
        const summaryDiscoveryMode = summaryMeta?.discoveryMode === 'tiered' ? 'tiered' as const : undefined;
        const summaryTiers = extractSummaryTiers(summaryMeta);
        const sidecar = buildDiscoveryReportSidecar(reportModel, {
            auditId,
            sourceMode,
            generatedAt: generatedAt.toISOString(),
            serverVersion: SERVER_VERSION,
            runId: reportOptions.runId,
            requestedAt: reportOptions.requestedAt,
            depthMode: reportOptions.depthMode,
            ...(summaryDiscoveryMode ? { discoveryMode: summaryDiscoveryMode } : {}),
            ...(summaryTiers ? { tiers: summaryTiers as Parameters<typeof buildDiscoveryReportSidecar>[1]['tiers'] } : {}),
        });
        writeFileSync(sidecarPath, JSON.stringify(sidecar, null, 2));
        
        console.log(`[4/4] PDF report generated: ${filePath}`);
        console.log(`[4/4] JSON sidecar generated: ${sidecarPath}`);
    }, 300000); // 5min timeout for large discoveries (brands like disney can have many candidates)
});
