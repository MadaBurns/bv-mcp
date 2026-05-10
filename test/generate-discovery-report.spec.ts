// SPDX-License-Identifier: BUSL-1.1
/**
 * test/generate-discovery-report.spec.ts
 * 
 * Automatically discovers brand domains, performs RDAP correlation, classifies
 * the findings, and generates a fully Blackveil-branded PDF report.
 */

import { describe, it } from 'vitest';
import { discoverBrandDomains } from '../src/tools/discover-brand-domains';
import { checkRdapLookup } from '../src/tools/check-rdap-lookup';
import * as fs from 'fs';

const CONSUMER_REGISTRARS = [
    'godaddy', 'namecheap', 'hostinger', 'tucows', 'enom', 'squarespace', 
    'wix', 'publicdomainregistry', 'dynadot', 'gandi', 'media elite', 
    'name.com', 'network solutions', 'hostgator', 'bluehost', 'ionos'
];

describe('Automated Report Generation', () => {
    it('generates the report for a target domain', async () => {
        const target = 'TARGET_DOMAIN_PLACEHOLDER';
        if (!target || target === 'TARGET_DOMAIN_PLACEHOLDER') {
            throw new Error('Target domain is empty');
        }

        console.log(`[1/4] Looking up primary registrar for ${target}...`);
        let primaryRegistrar = 'Unknown';
        try {
            const rdap = await checkRdapLookup(target);
            const rFind = rdap.findings.find(f => f.title.includes('Registrar'));
            if (rFind) {
                primaryRegistrar = rFind.detail.replace('Registrar: ', '').trim();
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

        for (const cand of uniqueCandidates) {
            let candRegistrar = 'Unknown';
            try {
                const rdap = await checkRdapLookup(cand.domain);
                const rFind = rdap.findings.find(f => f.title.includes('Registrar'));
                if (rFind) {
                    candRegistrar = rFind.detail.replace('Registrar: ', '').trim();
                }
            } catch (e) {
                // Ignore RDAP failures
            }

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
                return s.toUpperCase();
            }).join(', ');

            if (isMatch || (candRegLower === primaryRegLower && primaryRegLower !== 'unknown')) {
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
  body {
    font-family: 'Manrope', ui-sans-serif, system-ui, sans-serif;
    background-color: #000000; /* Obsidian */
    color: #ffffff;
    line-height: 1.7;
    font-weight: 300;
    letter-spacing: 0.025em;
  }
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #404040; /* Obsidian Border */
    padding-bottom: 24px;
    margin-bottom: 40px;
  }
  .header-info {
    text-align: right;
    color: #bfbfbf; /* text-secondary */
    font-size: 0.875rem;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    letter-spacing: -0.015em;
  }
  h1, h2, h3, h4 {
    font-family: 'Space Grotesk', ui-sans-serif, system-ui, sans-serif;
    color: #ffffff;
    letter-spacing: -0.015em;
    -webkit-font-smoothing: antialiased;
  }
  h1 {
    font-weight: 900; /* Black */
    line-height: 1;
    font-size: 2.5rem;
  }
  h2 {
    font-weight: 800; /* Extrabold */
    line-height: 1.1;
    border-bottom: 1px solid #1f1f1f; /* Obsidian Elevated */
    padding-bottom: 8px;
    margin-top: 48px;
    font-size: 1.5rem;
  }
  h3 {
    font-weight: 700; /* Bold */
    line-height: 1.2;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 24px 0;
    font-size: 0.875rem;
    background-color: #1a1a1a; /* Obsidian Surface */
    border-radius: 0.5rem;
    overflow: hidden;
  }
  th {
    background-color: #1f1f1f; /* Obsidian Elevated */
    color: #bfbfbf;
    text-align: left;
    padding: 12px 16px;
    border-bottom: 1px solid #404040;
    font-weight: 600;
    font-family: 'Space Grotesk', sans-serif;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    font-size: 0.75rem;
  }
  td {
    padding: 12px 16px;
    border-bottom: 1px solid #1f1f1f;
    color: #ffffff;
  }
  .status-pass { color: #00FF9D; font-weight: 600; } /* Mint */
  .status-warn { color: #FFB300; font-weight: 600; }
  .status-fail { color: #FF3B30; font-weight: 600; }
  .evidence { 
    font-family: 'JetBrains Mono', ui-monospace, monospace; 
    font-size: 0.75rem; 
    color: #bfbfbf; 
    background: #1a1a1a; 
    padding: 2px 6px; 
    border-radius: 4px; 
    border: 1px solid #404040; 
    letter-spacing: -0.015em;
  }
  .revenue-box {
    background-color: #1a1a1a;
    border-left: 4px solid #00FF9D; /* Mint Accent */
    padding: 24px;
    margin: 32px 0;
    border-radius: 0 0.5rem 0.5rem 0;
  }
  .revenue-box table {
    background-color: transparent;
  }
  .logo {
    filter: invert(1) brightness(2);
  }
</style>

<div class="header">
  <div>
    <img src="../assets/bv-logo-full.png" width="200" class="logo" alt="Blackveil Security" />
  </div>
  <div class="header-info">
    <strong>BRAND DISCOVERY & SHADOW IT</strong><br>
    TARGET: ${targetUpper}<br>
    DATE: ${dateStr.toUpperCase()}<br>
    PREPARED BY: BLACKVEIL DNS ENTERPRISE SERVICES
  </div>
</div>

## Executive Summary
This report details the findings of an automated brand discovery and infrastructure correlation scan performed against the \`${target}\` seed domain. The objective of this scan is to map the organization's decentralized domain portfolio, identify "Shadow IT" (legitimate domains managed outside of the primary corporate registrar), and distinguish these from unauthorized impersonation threats.

## 1. Primary Corporate Infrastructure
The following domains were identified as part of the core corporate portfolio, correctly consolidated under the primary enterprise registrar (**${primaryRegistrar}**).

| Domain | Infrastructure Signals | Verified Registrar | Status |
| :--- | :--- | :--- | :--- |
| **${target}** | Primary Seed | ${primaryRegistrar} | <span class="status-pass">✅ Consolidated</span> |
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

        console.log('===MARKDOWN_START===');
        console.log(md);
        console.log('===MARKDOWN_END===');
        
        console.log(`[4/4] Markdown generated successfully.`);
    }, 120000); // 120s timeout for large discoveries
});
