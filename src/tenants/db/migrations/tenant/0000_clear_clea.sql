CREATE TABLE `alerts` (
	`id` text PRIMARY KEY NOT NULL,
	`domain` text NOT NULL,
	`alert_type` text NOT NULL,
	`triggered_at` integer NOT NULL,
	`resolved_at` integer,
	`detail` text,
	`delivered_to` text,
	`delivered_at` integer
);
--> statement-breakpoint
CREATE INDEX `idx_alerts_active` ON `alerts` (`triggered_at`) WHERE "alerts"."resolved_at" IS NULL;--> statement-breakpoint
CREATE TABLE `domains` (
	`domain` text PRIMARY KEY NOT NULL,
	`source` text NOT NULL,
	`added_at` integer NOT NULL,
	`last_scanned_at` integer,
	`last_score` integer,
	`last_grade` text,
	`watch` integer DEFAULT true,
	`watch_interval_hours` integer DEFAULT 168,
	`is_candidate` integer DEFAULT false,
	`discovery_signals` text,
	`discovery_confidence` real
);
--> statement-breakpoint
CREATE TABLE `findings` (
	`id` text PRIMARY KEY NOT NULL,
	`scan_id` text NOT NULL,
	`domain` text NOT NULL,
	`category` text NOT NULL,
	`severity` text NOT NULL,
	`title` text NOT NULL,
	`detail` text,
	`metadata` text,
	FOREIGN KEY (`scan_id`) REFERENCES `scans`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_findings_domain_severity` ON `findings` (`domain`,`severity`);--> statement-breakpoint
CREATE TABLE `scans` (
	`id` text PRIMARY KEY NOT NULL,
	`domain` text NOT NULL,
	`scan_at` integer NOT NULL,
	`score` integer,
	`grade` text,
	`maturity_stage` integer,
	`finding_count` integer,
	`result_json` text,
	`cycle_id` text,
	FOREIGN KEY (`domain`) REFERENCES `domains`(`domain`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_scans_domain_time` ON `scans` (`domain`,`scan_at`);--> statement-breakpoint
CREATE INDEX `idx_scans_cycle` ON `scans` (`cycle_id`);