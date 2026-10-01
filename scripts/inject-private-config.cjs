const fs = require('fs');
const path = require('path');
const { spawnSync: nodeSpawnSync } = require('node:child_process');
const { pathToFileURL } = require('node:url');

/**
 * The pure merge core (parseJsonc, validateOverlayKeys, mergeOverlay and their constant lists)
 * lives in the ESM module scripts/lib/overlay-merge.mjs so cloudflare.config.ts can share it.
 * This CommonJS door loads it lazily, so a test can still `require()` this file for its
 * pure exports without touching the filesystem.
 */
function loadOverlayMerge() {
    return import(pathToFileURL(path.join(__dirname, 'lib', 'overlay-merge.mjs')).href);
}


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

function validateProductionSecurityConfig(config, requiredVars) {
    const vars = config && typeof config.vars === 'object' && config.vars ? config.vars : {};
    const failures = [];
    for (const [name, expected] of Object.entries(requiredVars)) {
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
async function inject() {
    const { parseJsonc, validateOverlayKeys, mergeOverlay, OverlayValidationError, REQUIRED_PRODUCTION_VARS } =
        await loadOverlayMerge();
    const publicConfig = parseJsonc(fs.readFileSync('wrangler.jsonc', 'utf8'));
    const privateConfigPath = '.dev/wrangler.deploy.jsonc';

    if (!fs.existsSync(privateConfigPath)) {
        console.error("FATAL: Missing .dev/wrangler.deploy.jsonc private overlay - cannot produce a safe production config. Aborting deploy.");
        process.exit(1);
    }

    const privateConfig = parseJsonc(fs.readFileSync(privateConfigPath, 'utf8'));

    try {
        for (const warning of validateOverlayKeys(privateConfig, publicConfig).warnings) {
            console.warn(warning);
        }
    } catch (error) {
        if (!(error instanceof OverlayValidationError)) throw error;
        for (const warning of error.warnings) {
            console.warn(warning);
        }
        console.error(error.message);
        process.exit(1);
    }

    const mergedConfig = mergeOverlay(publicConfig, privateConfig);

    validateProductionSecurityConfig(mergedConfig, REQUIRED_PRODUCTION_VARS);

    fs.writeFileSync('wrangler.production.jsonc', JSON.stringify(mergedConfig, null, 2));
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
