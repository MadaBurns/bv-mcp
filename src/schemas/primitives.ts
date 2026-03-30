// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';

/**
 * Domain name — shape validation only (length 1-253).
 *
 * Intentional two-layer design: this schema validates the string shape so Zod can
 * reject obviously invalid input early (empty strings, oversized payloads). The
 * second layer — `validateDomain()` + `sanitizeDomain()` from `lib/sanitize.ts` —
 * handles structural validation (label rules, TLD checks), SSRF protection
 * (blocked IPs/TLDs), and punycode normalization. That second layer runs after Zod
 * in `extractAndValidateDomain()` (handlers/tool-args.ts).
 */
export const DomainSchema = z.string().min(1).max(253);

/** Session ID — exactly 64 lowercase hex characters. */
export const SessionIdSchema = z.string().regex(/^[0-9a-f]{64}$/);

/** DKIM selector — valid DNS label, max 63 chars. Trims and lowercases input before validation. */
export const DkimSelectorSchema = z.string().transform(s => s.trim().toLowerCase()).pipe(z.string().max(63).regex(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/));

/** Internal route tool name — lowercase + underscores, max 30 chars. */
export const ToolNameSchema = z.string().min(1).max(30).regex(/^[a-z_]+$/);

/** Safe label for array elements (provider names, MX hosts). */
export const SafeLabelSchema = z.string().min(1).max(253);

/** Scoring profile (with auto). Used by scan_domain. Trims and lowercases input. */
export const ProfileSchema = z.string().transform(s => s.trim().toLowerCase()).pipe(z.enum(['auto', 'mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal']));

/** Scoring profile (without auto). Used by get_benchmark, get_provider_insights. Trims and lowercases input. */
export const BenchmarkProfileSchema = z.string().transform(s => s.trim().toLowerCase()).pipe(z.enum(['mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal']));

/** Output format. Trims and lowercases input before validation. */
export const FormatSchema = z.string().transform(s => s.trim().toLowerCase()).pipe(z.enum(['full', 'compact']));

/** DNS record type for resolver consistency. Trims and uppercases input before validation. */
export const RecordTypeSchema = z.string().transform(s => s.trim().toUpperCase()).pipe(z.enum(['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA']));

/** Security grade. */
export const GradeSchema = z.enum(['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'F']);

/** API key tier. */
export const TierSchema = z.enum(['free', 'agent', 'developer', 'enterprise', 'partner', 'owner']);

/** DMARC policy for generate_dmarc_record. Trims and lowercases input. */
export const DmarcPolicySchema = z.string().transform(s => s.trim().toLowerCase()).pipe(z.enum(['none', 'quarantine', 'reject']));

/** Explain finding status values. Trims and lowercases input. */
export const ExplainStatusSchema = z.string().transform(s => s.trim().toLowerCase()).pipe(z.enum(['pass', 'fail', 'warning', 'critical', 'high', 'medium', 'low', 'info']));

/** Inferred types for external use. */
export type Profile = z.infer<typeof ProfileSchema>;
export type BenchmarkProfile = z.infer<typeof BenchmarkProfileSchema>;
export type OutputFormat = z.infer<typeof FormatSchema>;
export type Grade = z.infer<typeof GradeSchema>;
export type Tier = z.infer<typeof TierSchema>;
