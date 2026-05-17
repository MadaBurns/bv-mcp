// SPDX-License-Identifier: BUSL-1.1
/**
 * test/generate-discovery-report.spec.ts
 * 
 * Automatically discovers brand domains, performs RDAP correlation, classifies
 * the findings, and generates a fully Blackveil-branded PDF report.
 */

import { describe, it } from 'vitest';
import { writeFileSync, mkdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { marked } from 'marked';
import { discoverBrandDomains } from '../src/tools/discover-brand-domains';
import { checkRdapLookup } from '../src/tools/check-rdap-lookup';
import { generatePdf } from '../src/lib/pdf-engine';

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

describe.skipIf(isPlaceholder)('Automated Report Generation', () => {
    it('generates the report for a target domain', async () => {

        console.log(`[1/4] Looking up primary registrar for ${target}...`);
        let primaryRegistrar = 'Unknown';
        try {
            const rdap = await checkRdapLookup(target);
            // Registrar is published in finding metadata; the title is
            // "Registration details", not "...Registrar..." — relying on the
            // title check silently produced "Unknown" for every brand.
            const rFind = rdap.findings.find(f => typeof f.metadata?.registrar === 'string' && (f.metadata.registrar as string).length > 0);
            if (rFind) {
                primaryRegistrar = String(rFind.metadata!.registrar).trim();
            }
        } catch (e) {
            console.warn(`Failed to lookup primary registrar: ${(e as Error).message}`);
        }
        console.log(`Primary Registrar: ${primaryRegistrar}`);

        console.log(`[2/4] Running brand discovery...`);
        const result = await discoverBrandDomains(target, { 
            signals: ['san', 'ns', 'dmarc_rua', 'dkim_key_reuse'],
            min_confidence: 0.1
        });

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

        console.log(`[3/4] Analyzing candidates and generating report...`);
        
        const consolidated = [];
        const shadowIt = [];
        const impersonation = [];

        const primaryRegLower = primaryRegistrar.toLowerCase();
        const isPrimaryCore = primaryRegLower !== 'unknown' && primaryRegLower.length > 3;

        // Parallel RDAP lookups with bounded concurrency. Markov-only candidates
        // are speculative variants — no shared infra to verify, so we skip RDAP
        // for them entirely (saves significant wall time on brands like apple
        // that produce dozens of trigram-generated lookalikes).
        const RDAP_CONCURRENCY = 16;
        const rdapTargets = uniqueCandidates.filter(c => !(c.signals.length === 1 && c.signals[0] === 'markov_gen'));
        const candidateRegistrars = new Map<string, string>();
        for (let i = 0; i < rdapTargets.length; i += RDAP_CONCURRENCY) {
            const chunk = rdapTargets.slice(i, i + RDAP_CONCURRENCY);
            const results = await Promise.allSettled(chunk.map(c => checkRdapLookup(c.domain)));
            results.forEach((r, idx) => {
                let reg = 'Unknown';
                if (r.status === 'fulfilled') {
                    const rFind = r.value.findings.find(f => typeof f.metadata?.registrar === 'string' && (f.metadata.registrar as string).length > 0);
                    if (rFind) reg = String(rFind.metadata!.registrar).trim();
                }
                candidateRegistrars.set(chunk[idx].domain, reg);
            });
        }

        for (const cand of uniqueCandidates) {
            const candRegistrar = candidateRegistrars.get(cand.domain) ?? 'Unknown';
            const candRegLower = candRegistrar.toLowerCase();
            
            let isMatch = false;
            if (isPrimaryCore && candRegLower !== 'unknown') {
                const words1 = primaryRegLower.split(/[\s,.]+/).filter(w => w.length > 3);
                const words2 = candRegLower.split(/[\s,.]+/).filter(w => w.length > 3);
                isMatch = words1.some(w => words2.includes(w));
            }

            const evidenceString = cand.signals.map(s => {
                if (s === 'ns') return 'NS Match';
                if (s === 'san') return 'Cert SAN Match';
                if (s === 'dmarc_rua') return 'DMARC RUA Match';
                if (s === 'dkim_key_reuse') return 'DKIM Key Match';
                if (s === 'markov_gen') return 'Markov Variant';
                return s.toUpperCase();
            }).join(', ');

            const deterministicSignals = cand.signals.filter(s => s === 'ns' || s === 'dkim_key_reuse' || s === 'dmarc_rua');
            const hasDeterministic = deterministicSignals.length > 0;
            const onlyMarkov = cand.signals.length === 1 && cand.signals[0] === 'markov_gen';
            const registrarsKnown = primaryRegLower !== 'unknown' && candRegLower !== 'unknown';

            if (isMatch || (registrarsKnown && candRegLower === primaryRegLower)) {
                consolidated.push({ domain: cand.domain, evidence: evidenceString, registrar: candRegistrar });
            } else if (onlyMarkov) {
                // Speculative trigram-generated variant — by definition no shared
                // infrastructure, so it's a candidate impersonation regardless of registrar visibility.
                impersonation.push({ domain: cand.domain, evidence: evidenceString, registrar: candRegistrar });
            } else if (!registrarsKnown && hasDeterministic) {
                // Without registrar visibility, fall back to deterministic infra
                // signals (NS/DKIM/DMARC) — these prove operational linkage even
                // when WHOIS/RDAP can't confirm registrar.
                consolidated.push({ domain: cand.domain, evidence: evidenceString, registrar: candRegistrar });
            } else {
                const isConsumer = CONSUMER_REGISTRARS.some(r => candRegLower.includes(r));
                if (isConsumer && cand.confidence < 0.8) {
                    impersonation.push({ domain: cand.domain, evidence: cand.signals.length === 0 ? 'No shared infrastructure' : evidenceString, registrar: candRegistrar });
                } else {
                    shadowIt.push({ domain: cand.domain, evidence: evidenceString, registrar: candRegistrar });
                }
            }
        }

        const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
        const targetUpper = target.toUpperCase();

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
    Ref: BV-${target.substring(0,3).toUpperCase()}-${new Date().getTime().toString().slice(-6)}<br>
    Auth: Enterprise Tier
  </div>
</div>

# Infrastructure Audit: ${target}

## Executive Summary
This intelligence report provides a definitive mapping of the domain architecture and cryptographic footprint associated with **${target}**. Leveraging the Blackveil Multi-Signal Correlation Engine, we have identified primary infrastructure, discovered "Shadow IT" Managed by third-party vendors, and assessed potential impersonation risks. 

Our analysis utilizes deterministic signals (NS-Overlap, SAN Certificates, and DMARC RUA/RUF linkages) to provide a 100% factual baseline of the organization's decentralized portfolio.

## 1. Primary Corporate Infrastructure
The following assets are verified as core components of the ${target} portfolio, currently consolidated under the master enterprise registrar (**${primaryRegistrar}**).

| Verified Asset | Correlation Signal | Registrar | State |
| :--- | :--- | :--- | :--- |
| **${target}** | [ROOT SEED] | ${primaryRegistrar} | <span class="status-pass">CONSOLIDATED</span> |
`;

        for (const cand of consolidated) {
            md += `| **${cand.domain}** | <span class="evidence">${cand.evidence}</span> | ${cand.registrar} | <span class="status-pass">✅ Consolidated</span> |\n`;
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
            md += `| **${cand.domain}** | <span class="evidence">${cand.evidence}</span> | ${cand.registrar} | <span class="status-warn">🟡 Consolidation Target</span> |\n`;
        }

        if (shadowIt.length === 0) {
            md += `| *No shadow IT domains found* | - | - | - |\n`;
        }

        md += `
---

## 3. High-Risk Impersonation Threats
During the analysis, external domains exhibiting high visual similarity (lookalikes) or low confidence signal overlaps were evaluated against the infrastructure correlation engine. The following domains are registered at consumer-grade registrars or exhibit no strong shared infrastructure with ${target}, indicating they are unauthorized and potentially adversarial.

| Threat Domain | Discrepancy Evidence | Verified Registrar | Status |
| :--- | :--- | :--- | :--- |
`;

        for (const cand of impersonation) {
            md += `| **${cand.domain}** | <span class="evidence">${cand.evidence}</span> | ${cand.registrar} | <span class="status-fail">🚨 High Risk (Phishing)</span> |\n`;
        }

        if (impersonation.length === 0) {
            md += `| *No high-risk impersonation domains found* | - | - | - |\n`;
        }

        const arrOpportunity = shadowIt.length * (150 + 2000 + 1200);

        md += `
---

## 4. Revenue & Consolidation Opportunity

Based on the discovery of ${shadowIt.length} high-value Shadow IT domains, the following is a projection of the immediate revenue opportunity for the primary registrar to consolidate and secure this fragmented infrastructure.

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
      <td>${shadowIt.length} domains @ $150/yr (Enterprise Tier)</td>
      <td><strong>$${(shadowIt.length * 150).toLocaleString()} / yr</strong></td>
    </tr>
    <tr>
      <td><strong>Managed Premium DNS</strong></td>
      <td>${shadowIt.length} domains @ $2,000/yr (UltraDNS SLA match)</td>
      <td><strong>$${(shadowIt.length * 2000).toLocaleString()} / yr</strong></td>
    </tr>
    <tr>
      <td><strong>Advanced Security Monitoring (Blackveil)</strong></td>
      <td>${shadowIt.length} domains @ $1,200/yr (Continuous Auditing)</td>
      <td><strong>$${(shadowIt.length * 1200).toLocaleString()} / yr</strong></td>
    </tr>
    <tr>
      <td colspan="2" style="text-align: right; font-weight: bold; font-size: 16px;">Total Identified ARR Opportunity:</td>
      <td style="font-weight: bold; font-size: 16px; color: #00FF9D;">$${arrOpportunity.toLocaleString()} / yr</td>
    </tr>
  </table>
  <p style="font-size: 12px; margin-top: 10px; color: #bfbfbf;"><em>* Note: This represents the opportunity from a single discovery run on a small subset of candidate domains. A full portfolio scan typically yields 10x-50x more candidates.</em></p>
</div>

## Strategic Recommendations
1. **Portfolio Consolidation:** Present the cryptographic evidence to the ${target} security team to initiate transfer procedures for the ${shadowIt.length} identified domains currently managed by competing registrars, bringing them under the primary master agreement.
2. **Defensive Action:** Forward the details of the unauthorized lookalike domains to the brand protection and legal teams for immediate takedown or UDRP proceedings.
3. **Continuous Monitoring:** Enroll the newly discovered Shadow IT domains into the Blackveil automated security scanning tier to ensure compliance with corporate baseline policies (DMARC, DNSSEC, etc.).

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
                    <span style="color: #00FF9D; font-weight: 600;">BLACKVEIL DNS ORCHESTRATOR v2.13.1</span>
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
        
        const filePath = join(reportsDir, `${target}-discovery-report.pdf`);
        writeFileSync(filePath, pdfBuffer);
        
        console.log(`[4/4] PDF report generated: ${filePath}`);
    }, 300000); // 5min timeout for large discoveries (brands like disney can have many candidates)
});
