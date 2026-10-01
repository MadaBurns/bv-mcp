// Pure overlay-merge core, extracted verbatim from scripts/inject-private-config.cjs (SQ-254,
// Phase 5.1). No side effects, no fs access, no process.exit / console output: callers pass
// text and objects in and get values (or a thrown OverlayValidationError) out. The Wrangler-door
// injector keeps every side effect; Phase 5.2's cloudflare.config.ts imports this module too.

/**
 * Strip JSONC comments (// line + /* block) outside string literals, then JSON.parse.
 * Both wrangler.jsonc and .dev/wrangler.deploy.jsonc use the JSONC format.
 */
export function parseJsonc(source) {
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

export function mergeServices(publicServices, privateServices) {
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
 * handling in mergeOverlay() below.
 */
export const OVERLAY_MERGED_KEYS = [
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
export const OVERLAY_PATH_RELATIVE_KEYS = ['$schema', 'main'];

/**
 * Keys the public wrangler.jsonc owns outright. The overlay is a standalone wrangler
 * config, so it carries copies of these, but the copies are discarded — and that
 * discard is load-bearing: the overlay's `compatibility_date` has drifted months behind
 * the public one, so merging it would silently REGRESS the production runtime.
 */
export const OVERLAY_PUBLIC_OWNED_KEYS = [
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
export const OVERLAY_FATAL_ON_DRIFT = ['name', 'durable_objects', 'migrations'];

/**
 * Thrown by validateOverlayKeys on a fatal overlay problem. `message` is the exact
 * FATAL text the injector prints; `warnings` are the non-fatal drift warnings collected
 * before the failure (printed first by the injector, as they always were).
 */
export class OverlayValidationError extends Error {
    constructor(message, warnings = []) {
        super(message);
        this.name = 'OverlayValidationError';
        this.warnings = warnings;
    }
}

/**
 * Fail closed on any overlay key this module does not know how to handle.
 *
 * The merge in mergeOverlay() is an ALLOWLIST: a key absent from it is silently dropped from
 * the generated production config, and that silence has shipped misconfigured deploys
 * before. A new binding kind added to the overlay (hyperdrive, workflows, vectorize,
 * secrets_store_secrets, ...) must fail here rather than vanish.
 *
 * Throws OverlayValidationError for an unknown key or fatal drift. On success returns
 * `{ warnings }` — the messages for non-fatal drift the caller should surface.
 * When `publicConfig` is omitted the drift comparison is skipped (unknown-key check only).
 *
 * @param {Record<string, unknown>} privateConfig
 * @param {Record<string, unknown>} [publicConfig]
 * @returns {{ warnings: string[] }}
 */
export function validateOverlayKeys(privateConfig, publicConfig) {
    const known = new Set([...OVERLAY_MERGED_KEYS, ...OVERLAY_PATH_RELATIVE_KEYS, ...OVERLAY_PUBLIC_OWNED_KEYS]);
    const unknown = Object.keys(privateConfig).filter((key) => !known.has(key));
    if (unknown.length > 0) {
        throw new OverlayValidationError(
            `FATAL: .dev/wrangler.deploy.jsonc declares ${unknown.map((key) => JSON.stringify(key)).join(', ')}, which this ` +
            'script does not merge. It would be silently dropped from wrangler.production.jsonc. Add explicit merge ' +
            'handling in inject(), or list the key in OVERLAY_PUBLIC_OWNED_KEYS if the public wrangler.jsonc owns it.',
        );
    }

    const warnings = [];
    if (publicConfig === undefined) return { warnings };

    const fatal = [];
    for (const key of OVERLAY_PUBLIC_OWNED_KEYS) {
        if (!(key in privateConfig)) continue;
        if (JSON.stringify(privateConfig[key]) === JSON.stringify(publicConfig[key])) continue;
        if (OVERLAY_FATAL_ON_DRIFT.includes(key)) {
            fatal.push(key);
            continue;
        }
        warnings.push(
            `WARNING: overlay ${key} differs from wrangler.jsonc and is being ignored — the public value is what ships. ` +
            'Delete the stale copy from the overlay so it stops reading as live configuration.',
        );
    }
    if (fatal.length > 0) {
        throw new OverlayValidationError(
            `FATAL: .dev/wrangler.deploy.jsonc overrides ${fatal.map((key) => JSON.stringify(key)).join(', ')}, but the ` +
            'public wrangler.jsonc owns those keys, so the overlay value would be discarded. Reconcile the two files ' +
            'before deploying.',
            warnings,
        );
    }
    return { warnings };
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
export const PRODUCTION_REQUIRED_SECRETS = [
    'BV_API_KEY',
    'OAUTH_SIGNING_SECRET',
    'BV_WEB_INTERNAL_KEY',
    'MCP_ACCESS_LOG_IP_ENCRYPTION_KEY',
    'CF_ANALYTICS_TOKEN',
];

export const REQUIRED_PRODUCTION_VARS = {
    OAUTH_ISSUER: 'https://dns-mcp.blackveilsecurity.com',
    REJECT_QUERY_API_KEY: 'true',
    REQUIRE_PRODUCTION_BINDINGS: 'true',
};

/**
 * Merges the public engine build with the private overlay. Pure: returns a new object and
 * leaves both inputs untouched. Call validateOverlayKeys first — this merge is an allowlist.
 *
 * @param {Record<string, any>} publicBase
 * @param {Record<string, any>} overlay
 * @returns {Record<string, any>}
 */
export function mergeOverlay(publicBase, overlay) {
    const merged = { ...publicBase };
    // Merge Strategy: Private service bindings override public defaults by binding
    // name, while public service bindings absent from the overlay are retained.
    merged.services = mergeServices(publicBase.services, overlay.services);
    merged.vars = { ...publicBase.vars, ...overlay.vars };
    if (overlay.queues) {
        // Wholesale replace, not a per-consumer merge: every field on every producer/consumer
        // entry — including one this script has no special handling for, such as a consumer's
        // `dead_letter_queue` — passes through verbatim (SQ-185/SQ-169: bv-scanner-queue had
        // none, so a message that exhausted max_retries was dropped with no marker).
        merged.queues = overlay.queues;
    }

    // Core Infrastructure: KV, D1, Analytics
    if (overlay.kv_namespaces) {
        merged.kv_namespaces = overlay.kv_namespaces;
    }
    if (overlay.d1_databases) {
        merged.d1_databases = overlay.d1_databases;
    }
    if (overlay.analytics_engine_datasets) {
        merged.analytics_engine_datasets = overlay.analytics_engine_datasets;
    }
    if (overlay.r2_buckets) {
        merged.r2_buckets = overlay.r2_buckets;
    }
    merged.secrets = { required: [...PRODUCTION_REQUIRED_SECRETS] };
    return merged;
}
