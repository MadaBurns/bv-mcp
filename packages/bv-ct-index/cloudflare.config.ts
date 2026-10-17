// Deploy config: `npm -w packages/bv-ct-index run deploy` (`cf deploy`). Rollback: `npx wrangler rollback --name bv-ct-index`.
// Written in the shape `cf migrate` produces for packages/bv-whois. The sidecar drift gate reads this Worker via the explicit
// `--name` pinned in scripts/sidecar-deploy-drift.ts.
// wrangler.jsonc stays alongside as the TEST-ONLY config (cloudflareTest's `wrangler.configPath` cannot load a cf config). Parity
// between the two (name, compatibilityDate, flags, crons, R2/D1/queue bindings and both consumers, workersDev/previewUrls) is
// asserted by test/audits/infra-probe-wrangler.audit.test.ts.
// The Worker name is exactly `bv-ct-index` (US-12 hard constraint): deploy is upsert-by-name, so a different name would create or
// overwrite some other Worker on the account.
// The D1 database id is an account resource id, so it is NOT committed: the operator exports BV_CT_INDEX_D1_ID (printed by
// `npm run provision:ct-index`) and `cf deploy` evaluates this file in Node with that environment. resolveCtIndexD1Id THROWS on a
// missing, empty, placeholder or non-UUID value, so a deploy without it fails before upload. wrangler.jsonc, the test-only config,
// keeps the YOUR_* placeholder.
import { bindings, defineConfig, triggers } from 'cf/config';
// cf evaluates this file with Node's native ESM loader, which needs the explicit `.ts` extension (tsconfig: allowImportingTsExtensions).
import { CT_INDEX_D1_ID_ENV, resolveCtIndexD1Id } from '../../scripts/ct-index-deploy-ready.ts';

export default defineConfig({
	worker: {
		name: 'bv-ct-index',
		compatibilityDate: '2026-07-29',
		compatibilityFlags: ['global_fetch_strictly_public'],
		entrypoint: 'src/index.ts',
		workersDev: false,
		previewUrls: false,
		observability: {
			enabled: true,
		},
		triggers: [
			// Tailer every minute; compactor hourly at :17.
			triggers.scheduled({ schedule: '* * * * *' }),
			triggers.scheduled({ schedule: '17 * * * *' }),
			triggers.queue({ name: 'bv-ct-index-entries', maxBatchSize: 100, maxBatchTimeout: 30, maxRetries: 3 }),
			triggers.queue({ name: 'bv-ct-index-compact', maxBatchSize: 1, maxBatchTimeout: 1, maxRetries: 3 }),
		],
		env: {
			INDEX: bindings.r2({ name: 'bv-ct-index' }),
			// Resolved at deploy time from BV_CT_INDEX_D1_ID; see the note at the top of this file.
			CURSORS: bindings.d1({ name: 'bv-ct-index-cursors', id: resolveCtIndexD1Id(process.env[CT_INDEX_D1_ID_ENV]) }),
			ENTRIES: bindings.queue({ name: 'bv-ct-index-entries' }),
			COMPACT: bindings.queue({ name: 'bv-ct-index-compact' }),
			CT_INDEX_ADMIN_KEY: bindings.secret(),
		},
	},
});
