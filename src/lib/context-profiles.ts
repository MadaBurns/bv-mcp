// SPDX-License-Identifier: BUSL-1.1

/**
 * Context-aware scoring profiles — re-exported from @blackveil/dns-checks/scoring (single source of truth).
 * @deprecated Import directly from @blackveil/dns-checks/scoring in new code.
 */

export {
	PROFILE_WEIGHTS,
	PROFILE_CRITICAL_CATEGORIES,
	PROFILE_EMAIL_BONUS_ELIGIBLE,
	detectDomainContext,
	getProfileWeights,
} from '@blackveil/dns-checks/scoring';

export type { DomainProfile, DomainContext } from '@blackveil/dns-checks/scoring';
