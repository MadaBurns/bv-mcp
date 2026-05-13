<style>
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
    TARGET: GITHUB.COM<br>
    DATE: MAY 13, 2026<br>
    PREPARED BY: BLACKVEIL DNS ENTERPRISE SERVICES
  </div>
</div>

## Executive Summary
This report details the findings of an automated brand discovery and infrastructure correlation scan performed against the `github.com` seed domain. The objective of this scan is to map the organization's decentralized domain portfolio, identify "Shadow IT" (legitimate domains managed outside of the primary corporate registrar), and distinguish these from unauthorized impersonation threats.

## 1. Primary Corporate Infrastructure
The following domains were identified as part of the core corporate portfolio, correctly consolidated under the primary enterprise registrar (**Unknown**).

| Domain | Infrastructure Signals | Verified Registrar | Status |
| :--- | :--- | :--- | :--- |
| **github.com** | Primary Seed | Unknown | <span class="status-pass">✅ Consolidated</span> |
| *No additional consolidated domains found* | - | - | - |

---

## 2. Discovered Shadow IT / Vendor Sprawl
The Blackveil engine successfully correlated the following domains to github.com's infrastructure (via shared cryptographic keys, DMARC reporting endpoints, and custom nameserver pools). However, WHOIS analysis reveals these domains are registered at a **competing registrar**, indicating portfolio fragmentation and vendor sprawl.

*These represent immediate consolidation opportunities for the primary registrar.*

| Discovered Domain | Correlation Evidence | Verified Registrar | Status |
| :--- | :--- | :--- | :--- |
| *No shadow IT domains found* | - | - | - |

---

## 3. High-Risk Impersonation Threats
During the analysis, external domains exhibiting high visual similarity (lookalikes) or low confidence signal overlaps were evaluated against the infrastructure correlation engine. The following domains are registered at consumer-grade registrars or exhibit no strong shared infrastructure with github.com, indicating they are unauthorized and potentially adversarial.

| Threat Domain | Discrepancy Evidence | Verified Registrar | Status |
| :--- | :--- | :--- | :--- |
| *No high-risk impersonation domains found* | - | - | - |

---

## 4. Revenue & Consolidation Opportunity

Based on the discovery of 0 high-value Shadow IT domains, the following is a projection of the immediate revenue opportunity for the primary registrar to consolidate and secure this fragmented infrastructure.

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
      <td>0 domains @ $150/yr (Enterprise Tier)</td>
      <td><strong>$0 / yr</strong></td>
    </tr>
    <tr>
      <td><strong>Managed Premium DNS</strong></td>
      <td>0 domains @ $2,000/yr (UltraDNS SLA match)</td>
      <td><strong>$0 / yr</strong></td>
    </tr>
    <tr>
      <td><strong>Advanced Security Monitoring (Blackveil)</strong></td>
      <td>0 domains @ $1,200/yr (Continuous Auditing)</td>
      <td><strong>$0 / yr</strong></td>
    </tr>
    <tr>
      <td colspan="2" style="text-align: right; font-weight: bold; font-size: 16px;">Total Identified ARR Opportunity:</td>
      <td style="font-weight: bold; font-size: 16px; color: #00FF9D;">$0 / yr</td>
    </tr>
  </table>
  <p style="font-size: 12px; margin-top: 10px; color: #bfbfbf;"><em>* Note: This represents the opportunity from a single discovery run on a small subset of candidate domains. A full portfolio scan typically yields 10x-50x more candidates.</em></p>
</div>

## Strategic Recommendations
1. **Portfolio Consolidation:** Present the cryptographic evidence to the github.com security team to initiate transfer procedures for the 0 identified domains currently managed by competing registrars, bringing them under the primary master agreement.
2. **Defensive Action:** Forward the details of the unauthorized lookalike domains to the brand protection and legal teams for immediate takedown or UDRP proceedings.
3. **Continuous Monitoring:** Enroll the newly discovered Shadow IT domains into the Blackveil automated security scanning tier to ensure compliance with corporate baseline policies (DMARC, DNSSEC, etc.).

***
*Generated automatically by the Blackveil DNS Multi-Tenant Orchestrator. Powered by Blackveil Security.*

