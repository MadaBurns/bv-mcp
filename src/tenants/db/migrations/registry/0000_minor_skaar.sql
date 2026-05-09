CREATE TABLE `billing_events` (
	`id` text PRIMARY KEY NOT NULL,
	`super_tenant_id` text NOT NULL,
	`sub_tenant_id` text,
	`event_type` text NOT NULL,
	`count` integer NOT NULL,
	`cost_cents` integer,
	`occurred_at` integer NOT NULL,
	FOREIGN KEY (`super_tenant_id`) REFERENCES `super_tenants`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_billing_lookup` ON `billing_events` (`super_tenant_id`,`occurred_at`);--> statement-breakpoint
CREATE TABLE `sub_tenants` (
	`id` text PRIMARY KEY NOT NULL,
	`super_tenant_id` text NOT NULL,
	`name` text NOT NULL,
	`d1_db_id` text NOT NULL,
	`domain_count` integer DEFAULT 0,
	`scan_schedule` text,
	`scan_quota_per_month` integer,
	`active` integer DEFAULT true,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`super_tenant_id`) REFERENCES `super_tenants`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `super_tenants` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`api_key_hash` text NOT NULL,
	`d1_binding_prefix` text NOT NULL,
	`rate_limit_per_minute` integer DEFAULT 1000,
	`active` integer DEFAULT true,
	`created_at` integer NOT NULL,
	`metadata` text
);
--> statement-breakpoint
CREATE TABLE `tenant_keys` (
	`key_hash` text PRIMARY KEY NOT NULL,
	`super_tenant_id` text NOT NULL,
	`sub_tenant_id` text,
	`scope` text NOT NULL,
	`expires_at` integer,
	`revoked_at` integer,
	`last_used_at` integer,
	FOREIGN KEY (`super_tenant_id`) REFERENCES `super_tenants`(`id`) ON UPDATE no action ON DELETE no action
);
