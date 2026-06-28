-- Phase 2 scheduler core — optional SCAN_SCHEDULE_DB (D1). Applied only at
-- enable time via: wrangler d1 migrations apply --remote <SCAN_SCHEDULE_DB>.
-- scan_rollup is RETENTION-BOUNDED (decisions #8/#9) — prune on a cron with:
--   DELETE FROM scan_rollup WHERE bucket_day < ?;   -- ? = floor((now-retentionMs)/86400000)
CREATE TABLE `scan_schedule` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`tenant_id` text NOT NULL,
	`domain` text NOT NULL,
	`tier` text,
	`lane` text NOT NULL,
	`cadence_ms` integer NOT NULL,
	`next_scan_at` integer NOT NULL,
	`jitter_seed` integer,
	`last_dispatched_at` integer,
	`last_scanned_at` integer,
	`consecutive_failures` integer DEFAULT 0 NOT NULL,
	`active` integer DEFAULT 1 NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_scan_schedule_tenant_domain` ON `scan_schedule` (`tenant_id`,`domain`);--> statement-breakpoint
CREATE INDEX `idx_scan_schedule_due` ON `scan_schedule` (`active`,`lane`,`next_scan_at`);--> statement-breakpoint
CREATE TABLE `scan_rollup` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`bucket_day` integer NOT NULL,
	`tenant_id` text NOT NULL,
	`domain` text NOT NULL,
	`run_id` text,
	`grade` text,
	`score` integer,
	`finding_count` integer,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_scan_rollup_bucket_day` ON `scan_rollup` (`bucket_day`);--> statement-breakpoint
CREATE INDEX `idx_scan_rollup_tenant_domain` ON `scan_rollup` (`tenant_id`,`domain`);
