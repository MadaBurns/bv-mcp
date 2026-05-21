import { discoverBrandDomains } from './src/tools/discover-brand-domains.js';
import { checkRdapLookup } from './src/tools/check-rdap-lookup.js';
import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

const domains = ['amazon.com', 'apple.com', 'google.com', 'microsoft.com', 'brand-beta.example.com', 'brand-zeta.example.com', 'brand-eta.example.com', 'brand-theta.example.com', 'brand-alpha.example.com', 'github.com'];

const BrandAudit_GLOBAL = 'brand-audit corporate domains';

async function auditDomain(target) {
    console.log(`Audit starting for ${target}...`);
    try {
        const result = await discoverBrandDomains(target, { min_confidence: 0.1 });
        const candidates = result.findings
            .filter(f => f.metadata?.candidate)
            .map(f => ({
                domain: f.metadata.candidate,
                confidence: f.metadata.combinedConfidence,
                signals: f.metadata.signals
            }));

        console.log(`Found ${candidates.length} candidates for ${target}.`);
        
        const rdapResults = [];
        for (const cand of candidates) {
            try {
                const rdap = await checkRdapLookup(cand.domain);
                const rFind = rdap.findings.find(f => f.title.includes('Registrar'));
                const registrar = rFind ? rFind.detail.replace('Registrar: ', '').trim() : 'Unknown';
                rdapResults.push({ ...cand, registrar });
            } catch (e) {
                rdapResults.push({ ...cand, registrar: 'Error' });
            }
        }

        const consolidated = rdapResults.filter(r => r.registrar.toLowerCase().includes('brand-audit corporate domains'));
        const shadowIt = rdapResults.filter(r => !r.registrar.toLowerCase().includes('brand-audit corporate domains') && r.confidence >= 0.7);
        const impersonation = rdapResults.filter(r => !r.registrar.toLowerCase().includes('brand-audit corporate domains') && r.confidence < 0.7);

        const report = {
            target,
            consolidated,
            shadowIt,
            impersonation
        };

        writeFileSync(`reports/${target}-fresh-discovery.json`, JSON.stringify(report, null, 2));
        console.log(`Report saved for ${target}.`);
    } catch (e) {
        console.error(`Failed audit for ${target}: ${e.message}`);
    }
}

async function main() {
    try { mkdirSync('reports', { recursive: true }); } catch (e) {}
    for (const d of domains) {
        await auditDomain(d);
    }
}

main();
