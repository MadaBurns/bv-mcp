CREATE TABLE `audit_events` (
	`id` text PRIMARY KEY NOT NULL,
	`timestamp` integer NOT NULL,
	`actor_principal` text NOT NULL,
	`actor_tier` text NOT NULL,
	`super_tenant_id` text,
	`sub_tenant_id` text,
	`action` text NOT NULL,
	`resource_type` text NOT NULL,
	`resource_id` text,
	`outcome` text NOT NULL,
	`request_id` text,
	`cf_ray` text,
	`ip_hash` text,
	`blob` text,
	FOREIGN KEY (`super_tenant_id`) REFERENCES `super_tenants`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`sub_tenant_id`) REFERENCES `sub_tenants`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_audit_super_tenant_ts` ON `audit_events` (`super_tenant_id`,`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_audit_sub_tenant_ts` ON `audit_events` (`sub_tenant_id`,`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_audit_actor_ts` ON `audit_events` (`actor_principal`,`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_audit_action_ts` ON `audit_events` (`action`,`timestamp`);