const fs = require('fs');
const path = require('path');
const { spawnSync: nodeSpawnSync } = require('node:child_process');

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

/**
 * Secret-aware replacement for the old `REQUIRED_NONEMPTY_PRODUCTION_VARS`
 * check on `ALERT_WEBHOOK_URL` (#1073). `wrangler types --config
 * wrangler.production.jsonc` (run by `check:bindings:prod` right after this
 * script) renders every plaintext `vars` entry inline, so requiring the
 * webhook URL as a var re-disclosed it — including its path token, which is
 * sufficient on its own to post to the ops alert endpoint — on every prod
 * deploy. The guarantee "prod never ships with alerting silently off" stays;
 * it is now proven against `wrangler secret list` instead of `vars`.
 */
const ALERT_WEBHOOK_SECRET_NAME = 'ALERT_WEBHOOK_URL';

/**
 * One-shot operator escape hatch for the transition deploy: var just removed,
 * secret not yet provisioned (or the lister could not be reached). Deliberate
 * precedent: BV_ALLOW_STALE_SIDECARS (scripts/sidecar-deploy-drift.ts). It
 * does NOT bypass the var-still-present failure below — that state is
 * actively wrong (the re-disclosure this gate exists to stop), not merely
 * unverified, so no override should wave it through.
 */
const ALERT_WEBHOOK_OVERRIDE_ENV = 'BV_ALLOW_MISSING_ALERT_SECRET';

const WRANGLER_SECRET_LIST_TIMEOUT_MS = 30_000; // Network call — matches WRANGLER_TIMEOUT_MS in sidecar-deploy-drift-check.ts.

/** Read-only argv, as data, so a test can assert it verbatim (mirrors WRANGLER_DEPLOYMENTS_ARGV). */
const WRANGLER_SECRET_LIST_ARGV = ['wrangler', 'secret', 'list', '--format', 'json', '--name'];

/**
 * A timed-out spawnSync must FAIL CLOSED, never read as "no secret". Node
 * reports a timeout as `error.code === 'ETIMEDOUT'`; the killed child also
 * carries `signal: 'SIGTERM'` — check both (scripts/ci/sidecar-deploy-drift-check.ts).
 */
function isSpawnTimeout(result) {
    return (result.error && result.error.code === 'ETIMEDOUT') || result.signal === 'SIGTERM';
}

function firstStderrLine(stderr) {
    return (stderr || '').trim().split('\n')[0]?.trim() || 'no stderr';
}

/**
 * Lists the secret NAMES currently provisioned on the named Worker. `--name`
 * resolves the Worker without a `--config` — `wrangler.production.jsonc`
 * does not exist yet at the point this gate runs, since it is this script's
 * own output. `--format json` (the default; passed explicitly for clarity)
 * is `JSON.stringify` of the array the Cloudflare "list secrets" API
 * returns, each entry carrying a `.name` (verified against the installed
 * wrangler, 4.131.1, via `npx wrangler secret list --help` and its
 * `secretListCommand` handler — never assumed from memory).
 *
 * Throws on every failure (timeout, launch failure, non-zero exit, unparseable
 * output) so the caller can fold it into a fail-closed result — same shape as
 * `parseNewestDeployment` in scripts/ci/sidecar-deploy-drift-check.ts.
 */
function listProductionSecretNames(workerName, spawnSyncFn) {
    const result = spawnSyncFn('npx', [...WRANGLER_SECRET_LIST_ARGV, workerName], {
        encoding: 'utf8',
        timeout: WRANGLER_SECRET_LIST_TIMEOUT_MS,
    });
    if (isSpawnTimeout(result)) {
        throw new Error(`\`wrangler secret list\` timed out after ${WRANGLER_SECRET_LIST_TIMEOUT_MS}ms`);
    }
    if (result.error) {
        throw new Error(`could not launch wrangler: ${result.error.message}`);
    }
    if (result.status !== 0) {
        // Exit status is the reliable signal — a bad/expired token can still print
        // a non-JSON auth banner on stdout, which must never be parsed without this check.
        throw new Error(`\`wrangler secret list\` exited ${result.status ?? 'with no status'}: ${firstStderrLine(result.stderr)}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(result.stdout || '');
    } catch {
        const preview = (result.stdout || '').trim().slice(0, 120);
        throw new Error(`\`wrangler secret list\` did not return JSON (likely an auth banner or an error): ${preview || '<empty output>'}`);
    }
    if (!Array.isArray(parsed)) {
        throw new Error(`\`wrangler secret list\` returned ${typeof parsed}, expected an array of secrets`);
    }
    return parsed.map((entry) => (entry && typeof entry.name === 'string' ? entry.name : null)).filter((name) => name !== null);
}

/**
 * Pure decision core for the ALERT_WEBHOOK_URL gate — unit-tested directly
 * (no subprocess, no network) by requiring this module and injecting
 * `listSecretNames`. PASS iff the name is a listed Worker secret AND absent
 * from `vars` (a name cannot be both: `wrangler secret put` fails with
 * `[code: 10053]` while it is a var, which is also the re-disclosure state
 * this gate exists to stop). `allowMissing` is checked before ever calling
 * `listSecretNames`, so the transition override also covers an unreachable
 * lister (an operator deploying with no Cloudflare auth must not be
 * stranded) — matching `assessSidecarDrift`'s "checked FIRST" precedent.
 *
 * @param {Record<string, unknown>} vars
 * @param {() => string[]} listSecretNames
 * @param {boolean} allowMissing
 * @returns {{ ok: boolean, message: string | null }}
 */
function assessAlertWebhookSecretGate(vars, listSecretNames, allowMissing) {
    const varPresent = Object.prototype.hasOwnProperty.call(vars, ALERT_WEBHOOK_SECRET_NAME);
    if (varPresent) {
        return {
            ok: false,
            message:
                `${ALERT_WEBHOOK_SECRET_NAME} is still present in vars. A binding name cannot be both a var and a secret ` +
                `(wrangler rejects \`secret put\` with [code: 10053] while it is), and \`wrangler types\` renders every ` +
                `plaintext var inline on every deploy. Remove it from the private overlay's vars, run ` +
                `\`printf %s "<url>" | npx wrangler secret put ${ALERT_WEBHOOK_SECRET_NAME} --config .dev/wrangler.deploy.jsonc\`, ` +
                `then redeploy. For the transition deploy in between (var removed, secret not yet set): ` +
                `${ALERT_WEBHOOK_OVERRIDE_ENV}=1.`,
        };
    }

    if (allowMissing) {
        console.warn(
            `WARNING: ${ALERT_WEBHOOK_OVERRIDE_ENV}=1 — proceeding without verifying ${ALERT_WEBHOOK_SECRET_NAME} is provisioned ` +
                'as a Worker secret. Alerting fallback is UNVERIFIED for this deploy: the dynamic bv-web-prod lookup ' +
                '(resolveAlertWebhookUrl) is unaffected and still tried first, but if it is unreachable the static fallback ' +
                'may resolve to nothing. One-shot override — do not leave it set.',
        );
        return { ok: true, message: null };
    }

    let secretNames;
    try {
        secretNames = listSecretNames();
    } catch (error) {
        return {
            ok: false,
            message:
                `could not verify ${ALERT_WEBHOOK_SECRET_NAME} is provisioned as a Worker secret: ${error instanceof Error ? error.message : String(error)}. ` +
                `An unverified result is not evidence the secret exists. Fix wrangler auth/network and re-run, or deliberately ` +
                `bypass with ${ALERT_WEBHOOK_OVERRIDE_ENV}=1 for a transition deploy.`,
        };
    }

    if (secretNames.includes(ALERT_WEBHOOK_SECRET_NAME)) {
        return { ok: true, message: null };
    }

    return {
        ok: false,
        message:
            `${ALERT_WEBHOOK_SECRET_NAME} is not set as a Worker secret (and is correctly absent from vars). Run ` +
            `\`printf %s "<url>" | npx wrangler secret put ${ALERT_WEBHOOK_SECRET_NAME} --config .dev/wrangler.deploy.jsonc\` ` +
            `before deploying, or bypass for one transition deploy with ${ALERT_WEBHOOK_OVERRIDE_ENV}=1.`,
    };
}

function validateProductionSecurityConfig(config) {
    const vars = config && typeof config.vars === 'object' && config.vars ? config.vars : {};
    const failures = [];
    for (const [name, expected] of Object.entries(REQUIRED_PRODUCTION_VARS)) {
        if (vars[name] !== expected) {
            failures.push(`${name} must be ${JSON.stringify(expected)}`);
        }
    }

    const workerName = config && typeof config.name === 'string' ? config.name : undefined;
    const alertGate = assessAlertWebhookSecretGate(
        vars,
        () => listProductionSecretNames(workerName, nodeSpawnSync),
        process.env[ALERT_WEBHOOK_OVERRIDE_ENV] === '1',
    );
    if (!alertGate.ok) {
        failures.push(alertGate.message);
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

// Guarded so a test can `require()` this module for its pure/injectable
// exports below without running the real (side-effecting, wrangler-shelling)
// injection as an import side effect — same split as
// scripts/ci/sidecar-deploy-drift-check.ts's `isInvokedDirectly` guard.
if (require.main === module) {
    inject();
}

module.exports = {
    assessAlertWebhookSecretGate,
    listProductionSecretNames,
    ALERT_WEBHOOK_SECRET_NAME,
    ALERT_WEBHOOK_OVERRIDE_ENV,
    WRANGLER_SECRET_LIST_ARGV,
};
