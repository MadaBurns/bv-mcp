// SPDX-License-Identifier: BUSL-1.1

/**
 * `npm run provision:ct-index` — PRINTS the operator commands that provision the bv-ct-index sidecar, in order. It never executes
 * any of them, calls no Cloudflare API and reads nothing from the account: every step creates account resources or a secret, which
 * is the operator's decision. Run the commands yourself from the REPO ROOT, one at a time.
 *
 * Every flag below was checked against `npx wrangler <command> --help` on the pinned wrangler 4.149.0 (packages/bv-ct-index).
 *
 * Why the D1 steps look the way they do (measured): `wrangler d1 migrations apply <db> --remote` takes the database UUID from the
 * d1_databases entry of the wrangler config it loads (getDatabaseInfoFromConfig), and the tracked packages/bv-ct-index/wrangler.jsonc
 * deliberately holds the YOUR_* placeholder. So the migrations step runs against a gitignored copy with the real id substituted,
 * which also leaves the tree clean for `npm run deploy:ct-index`.
 */

import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const PACKAGE = 'packages/bv-ct-index';
const WORKER = 'bv-ct-index';
const D1_NAME = 'bv-ct-index-cursors';
const PLACEHOLDER = 'YOUR_BV_CT_INDEX_CURSORS_D1_DATABASE_ID';
const MIGRATE_CONFIG = `${PACKAGE}/.wrangler.migrate.jsonc`;

const migrations = readdirSync(fileURLToPath(new URL('../packages/bv-ct-index/migrations/', import.meta.url)))
	.filter((f) => f.endsWith('.sql'))
	.sort();

const lines = [
	`# bv-ct-index provisioning (US-12). PRINT-ONLY: nothing below has been run. Run each command yourself from the repo root.`,
	``,
	`## 1. The Worker name must be free`,
	`npx wrangler deployments list --name ${WORKER}`,
	`#   Expect "not found" / no deployments before the FIRST deploy. If it lists deployments, STOP: ${WORKER} is already taken.`,
	`#   WARNING: NEVER deploy under the name bv-certstream-worker. It is a third party's live app on this account, and a deploy`,
	`#   upserts by name, so it would overwrite it. The only name for this package is ${WORKER}.`,
	``,
	`## 2. R2 bucket`,
	`npx wrangler r2 bucket create ${WORKER}`,
	``,
	`## 3. Queues`,
	`npx wrangler queues create ${WORKER}-entries`,
	`npx wrangler queues create ${WORKER}-compact`,
	``,
	`## 4. D1 database`,
	`npx wrangler d1 create ${D1_NAME}`,
	`#   Do NOT pass --update-config: it would write the real id into a tracked file and dirty the tree.`,
	`#   Capture the printed database_id (a UUID) into the environment of the shell you will deploy from:`,
	`export BV_CT_INDEX_D1_ID=<the database_id printed above>`,
	`#   Lost it? It is recoverable any time:  npx wrangler d1 info ${D1_NAME} --json`,
	`#   cloudflare.config.ts reads BV_CT_INDEX_D1_ID at deploy time and THROWS if it is missing, empty, the placeholder or not a UUID.`,
	``,
	`## 5. D1 migrations (${migrations.length} in ${PACKAGE}/migrations/: ${migrations.join(', ')})`,
	`#   Remote migrations read the database id from the wrangler config, so apply them through a gitignored copy of the test config`,
	`#   with the id substituted (it stays untracked, so the tree stays clean for the deploy):`,
	`sed "s/${PLACEHOLDER}/$BV_CT_INDEX_D1_ID/" ${PACKAGE}/wrangler.jsonc > ${MIGRATE_CONFIG}`,
	`npx wrangler d1 migrations apply ${D1_NAME} --remote --config ${MIGRATE_CONFIG}`,
	`#   It applies every file in migrations/ that is not applied yet, so it is safe to re-run after a new migration lands.`,
	``,
	`## 6. Admin secret (the value must never be echoed; keep it in your password manager first)`,
	`printf %s "$CT_INDEX_ADMIN_KEY" | npx wrangler secret put CT_INDEX_ADMIN_KEY --name ${WORKER}`,
	`#   Set CT_INDEX_ADMIN_KEY in your shell from the password manager without echoing it. If wrangler asks whether to create a new`,
	`#   Worker named ${WORKER}, that is expected on the first run (step 1 proved the name is free).`,
	``,
	`## 7. Deploy (clean tree, BV_CT_INDEX_D1_ID exported)`,
	`npm run deploy:ct-index`,
	`#   Runs check:ct-index-deploy-ready first (D1 id resolves, Worker name is exactly ${WORKER}, no bv-certstream-worker, migrations present).`,
	``,
];

console.log(lines.join('\n'));
