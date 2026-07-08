const fs = require('fs');
const path = require('path');

/**
 * Strip JSONC comments (// line + /* block) outside string literals, then JSON.parse.
 * Both wrangler.jsonc and .dev/wrangler.deploy.jsonc use the JSONC format.
 */
function parseJsonc(source) {
    let out = '';
    let i = 0;
    let inString = false;
    let stringQuote = '';
    while (i < source.length) {
        const ch = source[i];
        const next = source[i + 1];
        if (inString) {
            out += ch;
            if (ch === '\\' && i + 1 < source.length) { out += source[i + 1]; i += 2; continue; }
            if (ch === stringQuote) { inString = false; }
            i += 1;
            continue;
        }
        if (ch === '"' || ch === '\'') { inString = true; stringQuote = ch; out += ch; i += 1; continue; }
        if (ch === '/' && next === '/') { while (i < source.length && source[i] !== '\n') i += 1; continue; }
        if (ch === '/' && next === '*') { i += 2; while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) i += 1; i += 2; continue; }
        out += ch;
        i += 1;
    }
    return JSON.parse(out);
}

function mergeServices(publicServices, privateServices) {
    const merged = new Map();
    for (const service of Array.isArray(publicServices) ? publicServices : []) {
        if (service && typeof service.binding === 'string') {
            merged.set(service.binding, service);
        }
    }
    for (const service of Array.isArray(privateServices) ? privateServices : []) {
        if (service && typeof service.binding === 'string') {
            merged.set(service.binding, service);
        }
    }
    return [...merged.values()];
}

const REQUIRED_PRODUCTION_VARS = {
    OAUTH_ISSUER: 'https://dns-mcp.blackveilsecurity.com',
    REJECT_QUERY_API_KEY: 'true',
    REQUIRE_PRODUCTION_BINDINGS: 'true',
};
const REQUIRED_NONEMPTY_PRODUCTION_VARS = ['ALERT_WEBHOOK_URL'];

function validateProductionSecurityConfig(config) {
    const vars = config && typeof config.vars === 'object' && config.vars ? config.vars : {};
    const failures = [];
    for (const [name, expected] of Object.entries(REQUIRED_PRODUCTION_VARS)) {
        if (vars[name] !== expected) {
            failures.push(`${name} must be ${JSON.stringify(expected)}`);
        }
    }
    for (const name of REQUIRED_NONEMPTY_PRODUCTION_VARS) {
        if (typeof vars[name] !== 'string' || vars[name].trim() === '') {
            failures.push(`${name} must be non-empty`);
        }
    }
    if (failures.length > 0) {
        console.error(`FATAL: Unsafe production config: ${failures.join('; ')}.`);
        process.exit(1);
    }
}

/**
 * Automates the "Private Injection" process.
 * Merges the public engine build with local private overrides.
 */
function inject() {
    const publicConfig = parseJsonc(fs.readFileSync('wrangler.jsonc', 'utf8'));
    const privateConfigPath = '.dev/wrangler.deploy.jsonc';

    if (!fs.existsSync(privateConfigPath)) {
        console.error("FATAL: Missing .dev/wrangler.deploy.jsonc private overlay - cannot produce a safe production config. Aborting deploy.");
        process.exit(1);
    }

    const privateConfig = parseJsonc(fs.readFileSync(privateConfigPath, 'utf8'));
    
    // Merge Strategy: Private service bindings override public defaults by binding
    // name, while public service bindings absent from the overlay are retained.
    publicConfig.services = mergeServices(publicConfig.services, privateConfig.services);
    publicConfig.vars = { ...publicConfig.vars, ...privateConfig.vars };
    if (privateConfig.queues) {
        publicConfig.queues = privateConfig.queues;
    }
    
    // Core Infrastructure: KV, D1, Analytics
    if (privateConfig.kv_namespaces) {
        publicConfig.kv_namespaces = privateConfig.kv_namespaces;
    }
    if (privateConfig.d1_databases) {
        publicConfig.d1_databases = privateConfig.d1_databases;
    }
    if (privateConfig.analytics_engine_datasets) {
        publicConfig.analytics_engine_datasets = privateConfig.analytics_engine_datasets;
    }
    if (privateConfig.r2_buckets) {
        publicConfig.r2_buckets = privateConfig.r2_buckets;
    }
    validateProductionSecurityConfig(publicConfig);
    
    fs.writeFileSync('wrangler.production.jsonc', JSON.stringify(publicConfig, null, 2));
    console.log("Successfully generated wrangler.production.jsonc with injected private configuration.");
}

inject();
