// SPDX-License-Identifier: BUSL-1.1
/**
 * scripts/csc-brand-audit.ts
 * 
 * Performs a deep-intelligence brand audit on CSC-managed domains.
 * Classifies results into Consolidated, Shadow IT, and Impersonation.
 * Generates Polished Blackveil-branded PDF reports to the Desktop.
 */

import { describe, it } from 'vitest';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { discoverBrandDomains } from '../src/tools/discover-brand-domains';
import { checkRdapLookup } from '../src/tools/check-rdap-lookup';
import { generatePdf } from '../src/lib/pdf-engine';

const TARGET_DOMAINS = [
    'google.com', 'amazon.com', 'microsoft.com', 'apple.com', 'disney.com', 
    'nike.com', 'paypal.com', 'stripe.com', 'walmart.com', 'github.com', 
    'blackveilsecurity.com'
];

// Normalize registrar strings to a stable family name so MarkMonitor / Com Laude / SafeNames
// variants (case, punctuation, regional subsidiaries) collapse to one family per provider.
function normalizeRegistrar(raw: string): string {
    if (!raw || raw === 'Unknown') return 'Unknown';
    const lower = raw.toLowerCase();
    if (/markmonitor/.test(lower)) return 'MarkMonitor';
    if (/com\s*laude|nom[ -]?iq/.test(lower)) return 'Com Laude';
    if (/safenames/.test(lower)) return 'SafeNames';
    if (/csc\s*corporate|csc\s*global|corporate domains/.test(lower)) return 'CSC';
    if (/cloudflare/.test(lower)) return 'Cloudflare';
    if (/tucows/.test(lower)) return 'Tucows';
    if (/godaddy/.test(lower)) return 'GoDaddy';
    if (/namecheap/.test(lower)) return 'Namecheap';
    if (/network solutions|networksolutions/.test(lower)) return 'Network Solutions';
    if (/gandi/.test(lower)) return 'Gandi';
    return raw.trim();
}

async function lookupRegistrar(domain: string): Promise<string> {
    try {
        const rdap = await checkRdapLookup(domain);
        const rFind = rdap.findings.find(
            f => typeof f.metadata?.registrar === 'string' && (f.metadata.registrar as string).length > 0,
        );
        return rFind ? (rFind.metadata!.registrar as string) : 'Unknown';
    } catch {
        return 'Unknown';
    }
}

const INFRASTRUCTURE_DOMAINS = new Set([
    'agari.com', 'proofpoint.com', 'valimail.com', 'ondmarc.com', 'mimecast.com',
    'salesforce.com', 'google.com', 'outlook.com', 'protection.outlook.com',
    'sendgrid.net', 'mandrillapp.com', 'zendesk.com', 'postmarkapp.com',
    'stspg-customer.com', 'brevo.com', 'amazonses.com', 'mcsv.net',
    'hubspotemail.net', 'mktomail.com', 'pphosted.com', 'firebasemail.com',
    'freshdesk.com', 'messagelabs.com', 'atlassian.net', 'xero.com',
    'marketo.com', 'constantcontact.com', 'mailchimp.com', 'intercom.io'
]);

const TLDS = ['.net', '.org', '.co', '.io', '.sh', '.ai', '.biz', '.info', '.me', '.us', '.ca', '.uk', '.de', '.fr', '.app'];

function isSubdomainOf(cand: string, target: string) {
    if (cand === target) return true;
    return cand.endsWith('.' + target);
}

function isInfrastructure(cand: string) {
    const lower = cand.toLowerCase();
    for (const infra of INFRASTRUCTURE_DOMAINS) {
        if (lower === infra || lower.endsWith('.' + infra)) return true;
    }
    return false;
}

const assetsDir = join(import.meta.dirname, '../assets');
const logoFullBase64 = readFileSync(join(assetsDir, 'bv-logo-full.png')).toString('base64');

async function runAudit(target: string) {
    console.log(`\n>>> Starting Deep Intelligence Audit for: ${target}`);

    // Establish the target's own registrar as the consolidation baseline (per-target).
    const targetRegistrarRaw = await lookupRegistrar(target);
    const targetFamily = normalizeRegistrar(targetRegistrarRaw);
    console.log(`    Target registrar: ${targetFamily} (${targetRegistrarRaw})`);

    const base = target.split('.')[0];
    const candidateDomains = TLDS.map(tld => base + tld);

    const discovery = await discoverBrandDomains(target, {
        min_confidence: 0.1,
        signals: ['san', 'ns', 'dmarc_rua', 'dkim_key_reuse'],
        candidate_domains: candidateDomains
    });

    const candidateMap = new Map<string, { domain: string; confidence: number; signals: string[] }>();
    for (const f of discovery.findings) {
        if (f.metadata?.candidate) {
            const cand = f.metadata.candidate as string;
            const conf = f.metadata.combinedConfidence as number;
            const sigs = f.metadata.signals as string[];

            if (isInfrastructure(cand)) continue;
            
            if (!candidateMap.has(cand) || conf > candidateMap.get(cand)!.confidence) {
                candidateMap.set(cand, { domain: cand, confidence: conf, signals: sigs });
            }
        }
    }
    const candidates = Array.from(candidateMap.values()).sort((a, b) => b.confidence - a.confidence);

    const consolidated = [];
    const shadowIt = [];
    const impersonation = [];

    for (const cand of candidates) {
        const registrar = await lookupRegistrar(cand.domain);
        const candFamily = normalizeRegistrar(registrar);
        const evidence = cand.signals.map(s => s.toUpperCase().replace(/_/g, ' ')).join(', ');
        const entry = { domain: cand.domain, registrar, evidence, confidence: cand.confidence };

        // Same registrar family as target (and not Unknown==Unknown coincidence) → consolidated
        if (candFamily !== 'Unknown' && targetFamily !== 'Unknown' && candFamily === targetFamily) {
            consolidated.push(entry);
        } else if (isSubdomainOf(cand.domain, target)) {
            consolidated.push({ ...entry, note: 'Organizational Subdomain' });
        } else if (cand.confidence >= 0.7) {
            // High-confidence brand signal on a different/unknown registrar = provider sprawl / shadow IT
            shadowIt.push(entry);
        } else {
            impersonation.push(entry);
        }
    }

    const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    
    const html = `
    <html>
    <head>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;500;700&family=JetBrains+Mono:wght@400;700&family=Manrope:wght@200;400;600&display=swap');

            body {
                font-family: 'Manrope', sans-serif;
                background-color: #000000;
                color: #E0E0E0;
                line-height: 1.6;
                font-weight: 300;
                margin: 0;
                padding: 48px;
                -webkit-font-smoothing: antialiased;
            }

            .header {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                border-bottom: 1px solid #1A1A1A;
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
            }

            .logo { height: 44px; margin-bottom: 24px; }

            h1 {
                font-family: 'Space Grotesk', sans-serif;
                font-weight: 700;
                font-size: 3.5rem;
                margin: 0 0 8px 0;
                letter-spacing: -0.04em;
                color: #FFFFFF;
                line-height: 1;
            }

            .subtitle {
                font-family: 'JetBrains Mono', monospace;
                color: #00FF9D;
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 0.2em;
            }

            .section { margin-bottom: 64px; }

            h2 {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 1.25rem;
                font-weight: 500;
                color: #FFFFFF;
                border-bottom: 1px solid #1A1A1A;
                padding-bottom: 16px;
                margin-bottom: 32px;
                display: flex;
                align-items: center;
            }

            h2::before {
                content: '';
                display: inline-block;
                width: 8px;
                height: 8px;
                background-color: #00FF9D;
                margin-right: 16px;
                border-radius: 1px;
            }

            table {
                width: 100%;
                border-collapse: separate;
                border-spacing: 0 8px;
                margin-top: -8px;
            }

            th {
                text-align: left;
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.7rem;
                color: #666666;
                text-transform: uppercase;
                letter-spacing: 0.1em;
                padding: 12px 24px;
            }

            td {
                background: #0A0A0A;
                padding: 20px 24px;
                font-size: 0.85rem;
                border-top: 1px solid #111111;
                border-bottom: 1px solid #111111;
            }

            td:first-child {
                border-left: 1px solid #111111;
                border-radius: 4px 0 0 4px;
                font-weight: 600;
                color: #FFFFFF;
            }

            td:last-child {
                border-right: 1px solid #111111;
                border-radius: 0 4px 4px 0;
                color: #888888;
            }

            .badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 2px;
                font-size: 0.65rem;
                font-family: 'JetBrains Mono', monospace;
                font-weight: 700;
                text-transform: uppercase;
            }

            .badge-high { background: rgba(0, 255, 157, 0.1); color: #00FF9D; border: 1px solid rgba(0, 255, 157, 0.2); }
            .badge-med { background: rgba(255, 204, 0, 0.1); color: #FFCC00; border: 1px solid rgba(255, 204, 0, 0.2); }
            .badge-low { background: rgba(255, 77, 77, 0.1); color: #FF4D4D; border: 1px solid rgba(255, 77, 77, 0.2); }

            .footer {
                margin-top: 120px;
                padding-top: 32px;
                border-top: 1px solid #1A1A1A;
                display: flex;
                justify-content: space-between;
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.65rem;
                color: #444444;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <img src="data:image/png;base64,${logoFullBase64}" class="logo" />
                <h1>${target.toUpperCase()}</h1>
                <div class="subtitle">Discovery Intel Report</div>
            </div>
            <div class="header-info">
                <strong>Project:</strong> CSC Global Audit<br/>
                <strong>Status:</strong> External Review<br/>
                <strong>Date:</strong> ${dateStr}
            </div>
        </div>

        <div class="section">
            <h2>Consolidated Infrastructure</h2>
            <table>
                <thead><tr><th>Domain</th><th>Registrar</th><th>Signal Strength</th></tr></thead>
                <tbody>
                    ${consolidated.map(r => `<tr>
                        <td>${r.domain}</td>
                        <td>${r.registrar}</td>
                        <td><span class="badge badge-high">${r.evidence}</span></td>
                    </tr>`).join('')}
                    ${consolidated.length === 0 ? '<tr><td colspan="3" style="text-align:center; color:#444">Zero internal assets detected.</td></tr>' : ''}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Shadow IT Portfolio</h2>
            <table>
                <thead><tr><th>Domain</th><th>Registrar</th><th>Risk Level</th></tr></thead>
                <tbody>
                    ${shadowIt.map(r => `<tr>
                        <td>${r.domain}</td>
                        <td>${r.registrar}</td>
                        <td><span class="badge badge-med">High Confidence Match</span></td>
                    </tr>`).join('')}
                    ${shadowIt.length === 0 ? '<tr><td colspan="3" style="text-align:center; color:#444">Zero Shadow IT assets detected.</td></tr>' : ''}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Impersonation Vectors</h2>
            <table>
                <thead><tr><th>Domain</th><th>Registrar</th><th>Signal Origin</th></tr></thead>
                <tbody>
                    ${impersonation.map(r => `<tr>
                        <td>${r.domain}</td>
                        <td>${r.registrar}</td>
                        <td><span class="badge badge-low">${r.evidence}</span></td>
                    </tr>`).join('')}
                    ${impersonation.length === 0 ? '<tr><td colspan="3" style="text-align:center; color:#444">Zero impersonation risks detected.</td></tr>' : ''}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <div>&copy; 2026 Blackveil Security</div>
            <div>Deep Intelligence Engine v2.14.0</div>
            <div>Ref: ${Buffer.from(target).toString('hex').slice(0, 8).toUpperCase()}</div>
        </div>
    </body>
    </html>
    `;

    const pdfBuffer = await generatePdf(html);
    const desktopPath = join(homedir(), 'Desktop', `${target}-discovery-report.pdf`);
    writeFileSync(desktopPath, pdfBuffer);
    return { target, consolidated, shadowIt, impersonation };
}

describe('CSC Brand Audit Batch', () => {
    it('executes discovery and reporting', async () => {
        const allResults = [];
        for (const target of TARGET_DOMAINS) {
            const result = await runAudit(target);
            allResults.push(result);
        }
        mkdirSync('reports', { recursive: true });
        writeFileSync('reports/csc-audit-results.json', JSON.stringify(allResults, null, 2));
    }, 3_600_000);
});
