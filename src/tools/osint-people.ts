// SPDX-License-Identifier: BUSL-1.1
/**
 * People-centric OSINT investigations (username, email). Tier-gated to
 * owner/enterprise. Sensitive abuse surface (doxing/GDPR): deny-by-default.
 */
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';
import { osintInvestigateStart, type ReconToolOptions } from './osint-investigate';

const CATEGORY = 'osint_investigation' as CheckCategory;
const ALLOWED_TIERS = new Set(['owner', 'enterprise']);

export interface PeopleOsintOptions extends ReconToolOptions {
	authTier?: string;
}

function tierDenied(kind: string): CheckResult {
	return buildCheckResult(CATEGORY, [
		createFinding(
			CATEGORY,
			'Insufficient tier for people-OSINT',
			'info',
			`The ${kind} investigation tool requires owner or enterprise tier. People-centric OSINT is restricted to prevent misuse.`,
			{ tierDenied: true, requiredTiers: ['owner', 'enterprise'] },
		),
	]) as CheckResult;
}

export async function osintInvestigateUsernameStart(username: string, options: PeopleOsintOptions = {}): Promise<CheckResult> {
	if (!options.authTier || !ALLOWED_TIERS.has(options.authTier)) return tierDenied('username');
	return osintInvestigateStart('username', username, options);
}

export async function osintInvestigateEmailStart(email: string, options: PeopleOsintOptions = {}): Promise<CheckResult> {
	if (!options.authTier || !ALLOWED_TIERS.has(options.authTier)) return tierDenied('email');
	return osintInvestigateStart('email', email, options);
}
