# Deploying bv-ct-index

This is the short deploy reference. The README and the full operator runbook (SQ-346) link here.

## Deploy

The D1 database id is an account resource id, so it is never committed. The tracked `wrangler.jsonc` (the test-only config)
keeps the `YOUR_BV_CT_INDEX_CURSORS_D1_DATABASE_ID` placeholder, and `cloudflare.config.ts` (the deploy config) reads the real id
from the environment variable `BV_CT_INDEX_D1_ID` when `cf deploy` evaluates it. That keeps the tree clean, which
`npm run deploy:ct-index` requires (`check:release-integrity:sidecar`).

Run everything from the repo root.

1. `npm run provision:ct-index` prints the ordered, idempotent operator commands. It executes nothing. They are: check that the
   name `bv-ct-index` is free, create the R2 bucket, the two queues and the D1 database, apply every migration in `migrations/`,
   set the `CT_INDEX_ADMIN_KEY` secret, then deploy. Run them one at a time.
2. `export BV_CT_INDEX_D1_ID=<database_id printed by wrangler d1 create>`. Recover it any time with
   `npx wrangler d1 info bv-ct-index-cursors --json`.
3. `npm run deploy:ct-index` runs `check:ct-index-deploy-ready` first. It blocks unless the D1 id is a UUID, the Worker name is
   exactly `bv-ct-index`, the other Worker name that must never be used (`bv-certstream-worker`, a third party's live app) appears in no
   deploy file, and `migrations/` holds a `.sql` file. Deploy is upsert-by-name, so the name check is not optional.

Rehearse without uploading: `BV_CT_INDEX_D1_ID=<any UUID> npm -w packages/bv-ct-index run deploy -- --dry-run`. A missing, empty,
placeholder or non-UUID value makes the config throw, naming the variable and `npm run provision:ct-index`.

Remote migrations: `wrangler d1 migrations apply --remote` takes the database id from the wrangler config it loads, which is the
placeholder one. `provision:ct-index` therefore prints a step that substitutes the id into the gitignored
`packages/bv-ct-index/.wrangler.migrate.jsonc` and passes it with `--config`. Do not pass `--update-config` to `d1 create`: it writes the
real id into a tracked file.

Rollback: `npx wrangler rollback --name bv-ct-index`.
