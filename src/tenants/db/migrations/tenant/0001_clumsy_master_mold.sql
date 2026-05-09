ALTER TABLE `domains` ADD `fingerprint` text;--> statement-breakpoint
ALTER TABLE `domains` ADD `fingerprint_at` integer;--> statement-breakpoint
CREATE UNIQUE INDEX `idx_scans_cycle_domain_unique` ON `scans` (`cycle_id`,`domain`);