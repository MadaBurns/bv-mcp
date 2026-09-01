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

/**
 * Keys the private overlay is allowed to contribute. Each one has explicit merge
 * handling in inject() below.
 */
const OVERLAY_MERGED_KEYS = [
    'services',
    'vars',
    'queues',
    'kv_namespaces',
    'd1_databases',
    'analytics_engine_datasets',
    'r2_buckets',
];

/**
 * `$schema` and `main` are paths relative to the file that declares them. The overlay
 * lives in .dev/, so its copies are SUPPOSED to differ from the public ones and are
 * discarded without comment — the generated config sits at the repo root.
 */
const OVERLAY_PATH_RELATIVE_KEYS = ['$schema', 'main'];

/**
 * Keys the public wrangler.jsonc owns outright. The overlay is a standalone wrangler
 * config, so it carries copies of these, but the copies are discarded — and that
 * discard is load-bearing: the overlay's `compatibility_date` has drifted months behind
 * the public one, so merging it would silently REGRESS the production runtime.
 */
const OVERLAY_PUBLIC_OWNED_KEYS = [
    'name',
    'compatibility_date',
    'compatibility_flags',
    'upload_source_maps',
    'durable_objects',
    'migrations',
    'observability',
    'limits',
    'triggers',
    'tail_consumers',
];

/**
 * Drift in these is never a harmless stale copy. Silently discarding a Durable Object
 * binding, a migration tag, or the worker name ships a config nobody reviewed.
 */
const OVERLAY_FATAL_ON_DRIFT = ['name', 'durable_objects', 'migrations'];

/**
 * Fail closed on any overlay key this script does not know how to handle.
 *
 * The merge in inject() is an ALLOWLIST: a key absent from it is silently dropped from
 * the generated production config, and that silence has shipped misconfigured deploys
 * before. A new binding kind added to the overlay (hyperdrive, workflows, vectorize,
 * secrets_store_secrets, ...) must fail here rather than vanish.
 */
function validateOverlayKeys(publicConfig, privateConfig) {
    const known = new Set([...OVERLAY_MERGED_KEYS, ...OVERLAY_PATH_RELATIVE_KEYS, ...OVERLAY_PUBLIC_OWNED_KEYS]);
    const unknown = Object.keys(privateConfig).filter((key) => !known.has(key));
    if (unknown.length > 0) {
        console.error(
            `FATAL: .dev/wrangler.deploy.jsonc declares ${unknown.map((key) => JSON.stringify(key)).join(', ')}, which this ` +
            'script does not merge. It would be silently dropped from wrangler.production.jsonc. Add explicit merge ' +
            'handling in inject(), or list the key in OVERLAY_PUBLIC_OWNED_KEYS if the public wrangler.jsonc owns it.',
        );
        process.exit(1);
    }

    const fatal = [];
    for (const key of OVERLAY_PUBLIC_OWNED_KEYS) {
        if (!(key in privateConfig)) continue;
        if (JSON.stringify(privateConfig[key]) === JSON.stringify(publicConfig[key])) continue;
        if (OVERLAY_FATAL_ON_DRIFT.includes(key)) {
            fatal.push(key);
            continue;
        }
        console.warn(
            `WARNING: overlay ${key} differs from wrangler.jsonc and is being ignored — the public value is what ships. ` +
            'Delete the stale copy from the overlay so it stops reading as live configuration.',
        );
    }
    if (fatal.length > 0) {
        console.error(
            `FATAL: .dev/wrangler.deploy.jsonc overrides ${fatal.map((key) => JSON.stringify(key)).join(', ')}, but the ` +
            'public wrangler.jsonc owns those keys, so the overlay value would be discarded. Reconcile the two files ' +
            'before deploying.',
        );
        process.exit(1);
    }
}

/**
 * Secrets whose absence breaks or silently degrades production, verified present on the
 * live Worker. Emitted as `secrets.required` into the generated production config, so
 * `wrangler deploy` refuses to ship without them instead of failing open at runtime.
 *
 * Deliberately NOT declared in the public wrangler.jsonc: `secrets.required` also makes
 * `wrangler dev` load only the listed keys from .dev.vars and stops `wrangler types`
 * inferring from it. Scoping the declaration to the generated production config keeps the
 * deploy gate without changing local development or the OSS self-host surface.
 *
 * Fail-soft capabilities are intentionally absent — check_ssl, the recon tools, Cert
 * Spotter and the PDF renderer are all designed to degrade when their key is unset, so
 * requiring them would block deploys over a supported configuration:
 *   BV_RECON_KEY, BV_TLS_PROBE_KEY, CERTSPOTTER_TOKEN, BV_BROWSER_RENDERER_KEY,
 *   BV_CERTSTREAM_ADMIN_KEY, BV_MOBILE_INTERNAL_KEY, BV_INTERNAL_DEV_KEY(_2).
 *
 * Entries are added only once the secret is provisioned on the Worker: declaring a name
 * before it exists turns the gate into a deploy outage. KV_ENVELOPE_KEY belongs here
 * whenever OAuth is enabled (FIND-17) — add it as part of provisioning it, not before.
 */
const PRODUCTION_REQUIRED_SECRETS = [
    'BV_API_KEY',
    'OAUTH_SIGNING_SECRET',
    'BV_WEB_INTERNAL_KEY',
    'MCP_ACCESS_LOG_IP_ENCRYPTION_KEY',
    'CF_ANALYTICS_TOKEN',
];

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

    validateOverlayKeys(publicConfig, privateConfig);
    
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
    publicConfig.secrets = { required: [...PRODUCTION_REQUIRED_SECRETS] };

    validateProductionSecurityConfig(publicConfig);
    
    fs.writeFileSync('wrangler.production.jsonc', JSON.stringify(publicConfig, null, 2));
    console.log("Successfully generated wrangler.production.jsonc with injected private configuration.");
}

inject();
