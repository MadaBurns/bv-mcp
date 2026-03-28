// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';

/** Domain name — shape validation only. SSRF/blocklist checks stay in sanitize.ts. */
export const DomainSchema = z.string().min(1).max(253);

/** Session ID — exactly 64 lowercase hex characters. */
export const SessionIdSchema = z.string().regex(/^[0-9a-f]{64}$/);

/** DKIM selector — valid DNS label, max 63 chars. */
export const DkimSelectorSchema = z.string().max(63).regex(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/);

/** Internal route tool name — lowercase + underscores, max 30 chars. */
export const ToolNameSchema = z.string().min(1).max(30).regex(/^[a-z_]+$/);

/** Safe label for array elements (provider names, MX hosts). */
export const SafeLabelSchema = z.string().min(1).max(253);

/** Scoring profile (with auto). Used by scan_domain. */
export const ProfileSchema = z.enum(['auto', 'mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal']);

/** Scoring profile (without auto). Used by get_benchmark, get_provider_insights. */
export const BenchmarkProfileSchema = z.enum(['mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal']);

/** Output format. */
export const FormatSchema = z.enum(['full', 'compact']);

/** DNS record type for resolver consistency. */
export const RecordTypeSchema = z.enum(['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA']);

/** Security grade. */
export const GradeSchema = z.enum(['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'F']);

/** API key tier. */
export const TierSchema = z.enum(['free', 'agent', 'developer', 'enterprise', 'partner']);

/** DMARC policy for generate_dmarc_record. */
export const DmarcPolicySchema = z.enum(['none', 'quarantine', 'reject']);

/** Explain finding status values. */
export const ExplainStatusSchema = z.enum(['pass', 'fail', 'warning', 'critical', 'high', 'medium', 'low', 'info']);

/** Inferred types for external use. */
export type Profile = z.infer<typeof ProfileSchema>;
export type BenchmarkProfile = z.infer<typeof BenchmarkProfileSchema>;
export type OutputFormat = z.infer<typeof FormatSchema>;
export type Grade = z.infer<typeof GradeSchema>;
export type Tier = z.infer<typeof TierSchema>;
