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
import { isInfrastructureProvider } from '../src/tenants/discovery/infrastructure-providers';
import {
    classifyCandidate,
    normalizeRegistrar,
    type CandidateInput,
    type RegistrarSource,
    type Classification,
} from './lib/brand-classification';

/**
 * Production-shaped Fetcher that targets the live bv-whois shim Worker.
 * Mirrors what the `BV_WHOIS` service binding does at runtime; in node env
 * we hit the public URL so the audit exercises the same end-to-end fallback
 * path. Without this, ccTLDs without public RDAP (`.de`, `.me`, `.co`, `.io`,
 * `.sh`, `.us`) come back as "Unknown" registrar.
 */
const LIVE_WHOIS_BINDING: { fetch: typeof fetch } = {
    async fetch(input: RequestInfo, init?: RequestInit) {
        const req = typeof input === 'string' ? new Request(input, init) : input;
        const path = new URL(req.url).pathname;
        const target = `https://bv-whois.bv-edge.workers.dev${path}`;
        return fetch(target, {
            method: req.method,
            headers: req.headers,
            body: req.method === 'GET' || req.method === 'HEAD' ? undefined : await req.clone().text(),
        });
    },
};

const TARGET_DOMAINS = [
    'google.com', 'amazon.com', 'microsoft.com', 'apple.com', 'disney.com', 
    'nike.com', 'paypal.com', 'stripe.com', 'walmart.com', 'github.com', 
    'blackveilsecurity.com'
];

interface RegistrarLookup {
    registrar: string;
    source: RegistrarSource;
    registrant: string | null;
}

/** Look up a domain's registrar + registrant via RDAP + bv-whois fallback,
 * returning the raw registrar string, the lookup `source`, and (when RDAP
 * exposes it) the registrant organization. `registrant` drives the
 * classifier's Rule 1.5 — direct cross-domain ownership match independent
 * of registrar family. */
async function lookupRegistrar(domain: string): Promise<RegistrarLookup> {
    try {
        const rdap = await checkRdapLookup(domain, { whoisBinding: LIVE_WHOIS_BINDING });
        const populatedFind = rdap.findings.find(
            f => typeof f.metadata?.registrar === 'string' && (f.metadata.registrar as string).length > 0,
        );
        const registrantFind = rdap.findings.find(
            f => typeof f.metadata?.registrant === 'string' && (f.metadata.registrant as string).length > 0,
        );
        const registrant = (registrantFind?.metadata?.registrant as string | undefined) ?? null;

        if (populatedFind) {
            const source = (populatedFind.metadata?.registrarSource as RegistrarSource | undefined) ?? 'unknown';
            return { registrar: populatedFind.metadata!.registrar as string, source, registrant };
        }
        const lastWithSource = [...rdap.findings].reverse().find(
            f => typeof f.metadata?.registrarSource === 'string',
        );
        const source = (lastWithSource?.metadata?.registrarSource as RegistrarSource | undefined) ?? 'unknown';
        return { registrar: 'Unknown', source, registrant };
    } catch {
        return { registrar: 'Unknown', source: 'unknown', registrant: null };
    }
}

// Expanded ccTLD coverage — tier-1 brands typically register defensively across
// 30+ country TLDs. The earlier 15-TLD list missed many real branded ccTLDs
// (`.jp`, `.kr`, `.cn`, `.br`, `.au`, `.nz`, `.in`, etc.) and silently dropped
// them from the caller-asserted candidate pool.
const TLDS = [
    '.net', '.org', '.co', '.io', '.sh', '.ai', '.biz', '.info', '.me', '.us',
    '.ca', '.uk', '.de', '.fr', '.app',
    '.jp', '.kr', '.cn', '.tw', '.in', '.au', '.nz', '.za',
    '.br', '.mx', '.cl', '.ar',
    '.es', '.it', '.nl', '.be', '.ch', '.at', '.pl', '.cz', '.se', '.no', '.dk', '.fi', '.ie',
    '.ru', '.tr',
];

const assetsDir = join(import.meta.dirname, '../assets');
const logoFullBase64 = readFileSync(join(assetsDir, 'bv-logo-full.png')).toString('base64');

interface BucketEntry {
    domain: string;
    registrar: string;
    registrarSource: RegistrarSource;
    evidence: string;
    confidence: number;
    confidenceTier: Classification['confidenceTier'];
    reasons: string[];
    note?: string;
}

async function runAudit(target: string) {
    console.log(`\n>>> Starting Deep Intelligence Audit for: ${target}`);

    // Establish the target's own registrar as the consolidation baseline (per-target).
    const targetLookup = await lookupRegistrar(target);
    const targetFamily = normalizeRegistrar(targetLookup.registrar);
    console.log(`    Target registrar: ${targetFamily} (${targetLookup.registrar}, src=${targetLookup.source})`);

    const base = target.split('.')[0];
    const candidateDomains = TLDS.map(tld => base + tld);

    const discovery = await discoverBrandDomains(target, {
        min_confidence: 0.1,
        // v2.17.0: 8 signals total. The 4 new ones (http_redirect / mx_overlap /
        // spf_include / cname_alignment) target the defensive-portfolio gap that
        // SAN/NS/DKIM/DMARC don't see for tier-1 brands.
        signals: ['san', 'ns', 'dmarc_rua', 'dkim_key_reuse', 'http_redirect', 'mx_overlap', 'spf_include', 'cname_alignment'],
        candidate_domains: candidateDomains
    });

    const candidateMap = new Map<string, { domain: string; confidence: number; signals: string[] }>();
    for (const f of discovery.findings) {
        if (f.metadata?.candidate) {
            const cand = f.metadata.candidate as string;
            const conf = f.metadata.combinedConfidence as number;
            const sigs = f.metadata.signals as string[];

            // Use the source-of-truth infrastructure-provider allowlist from src/
            // (`isInfrastructureProvider` covers ~50 vendors including modern ones
            // like Klaviyo, Brevo, ZeptoMail; was duplicated/stale in this spec).
            if (isInfrastructureProvider(cand)) continue;

            if (!candidateMap.has(cand) || conf > candidateMap.get(cand)!.confidence) {
                candidateMap.set(cand, { domain: cand, confidence: conf, signals: sigs });
            }
        }
    }
    const candidates = Array.from(candidateMap.values()).sort((a, b) => b.confidence - a.confidence);

    // Parallel registrar lookups, concurrency-capped to avoid hammering bv-whois.
    // Sequential per-candidate lookups make every target into a ~13min run because
    // each ccTLD round-trips TCP/43 to the shim Worker. Concurrency=10 brings each
    // target back under a minute without overloading the WHOIS shim.
    const CONCURRENCY = 10;
    const lookupsByDomain = new Map<string, RegistrarLookup>();
    for (let i = 0; i < candidates.length; i += CONCURRENCY) {
        const batch = candidates.slice(i, i + CONCURRENCY);
        const results = await Promise.all(batch.map(c => lookupRegistrar(c.domain)));
        batch.forEach((c, idx) => lookupsByDomain.set(c.domain, results[idx]));
    }

    const consolidated: BucketEntry[] = [];
    const shadowIt: BucketEntry[] = [];
    const indeterminate: BucketEntry[] = [];
    const impersonation: BucketEntry[] = [];

    for (const cand of candidates) {
        const lookup = lookupsByDomain.get(cand.domain) ?? { registrar: 'Unknown', source: 'unknown' as const, registrant: null };
        const input: CandidateInput = {
            domain: cand.domain,
            confidence: cand.confidence,
            signals: cand.signals,
            registrar: lookup.registrar,
            registrarSource: lookup.source,
            registrant: lookup.registrant,
        };
        const result = classifyCandidate(input, {
            domain: target,
            registrar: targetLookup.registrar,
            registrarFamily: targetFamily,
            registrant: targetLookup.registrant,
        });

        const evidence = cand.signals.map(s => s.toUpperCase().replace(/_/g, ' ')).join(', ');
        const entry: BucketEntry = {
            domain: cand.domain,
            registrar: lookup.registrar,
            registrarSource: lookup.source,
            evidence,
            confidence: cand.confidence,
            confidenceTier: result.confidenceTier,
            reasons: result.reasons,
            ...(result.note ? { note: result.note } : {}),
        };

        switch (result.bucket) {
            case 'consolidated': consolidated.push(entry); break;
            case 'shadowIt': shadowIt.push(entry); break;
            case 'indeterminate': indeterminate.push(entry); break;
            case 'impersonation': impersonation.push(entry); break;
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
            .badge-gray { background: rgba(180, 180, 180, 0.06); color: #999999; border: 1px solid rgba(180, 180, 180, 0.18); }

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
            <h2>Indeterminate</h2>
            <table>
                <thead><tr><th>Domain</th><th>Registrar</th><th>Reason</th></tr></thead>
                <tbody>
                    ${indeterminate.map(r => `<tr>
                        <td>${r.domain}</td>
                        <td>${r.registrar}${r.registrarSource === 'redacted' || r.registrarSource === 'notfound' ? ` <span class="badge badge-gray">${r.registrarSource}</span>` : ''}</td>
                        <td><span class="badge badge-gray">${r.reasons[0] ?? 'insufficient evidence'}</span></td>
                    </tr>`).join('')}
                    ${indeterminate.length === 0 ? '<tr><td colspan="3" style="text-align:center; color:#444">Zero indeterminate candidates.</td></tr>' : ''}
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
    return { target, consolidated, shadowIt, indeterminate, impersonation };
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
