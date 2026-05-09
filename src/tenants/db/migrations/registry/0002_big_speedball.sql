CREATE TABLE `tenant_cycles` (
	`id` text PRIMARY KEY NOT NULL,
	`super_tenant_id` text NOT NULL,
	`sub_tenant_id` text NOT NULL,
	`started_at` integer NOT NULL,
	`expected_total` integer NOT NULL,
	`completed_total` integer NOT NULL DEFAULT 0,
	`errored_total` integer NOT NULL DEFAULT 0,
	`alert_sent_at` integer,
	`alert_outcome` text,
	`baseline_cycle_id` text,
	FOREIGN KEY (`super_tenant_id`) REFERENCES `super_tenants`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`sub_tenant_id`) REFERENCES `sub_tenants`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_cycles_sub_tenant_ts` ON `tenant_cycles` (`sub_tenant_id`,`started_at`);--> statement-breakpoint
CREATE INDEX `idx_cycles_pending_alert` ON `tenant_cycles` (`alert_sent_at`) WHERE "tenant_cycles"."alert_sent_at" IS NULL;