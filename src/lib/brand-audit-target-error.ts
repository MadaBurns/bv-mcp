// SPDX-License-Identifier: BUSL-1.1

/** Target rows can contain diagnostic text from a queue worker, including rows written by older versions. */
export function publicBrandAuditTargetError(error: string | null | undefined): string | null {
	if (!error) return null;
	if (
		error === 'discovery timed out' ||
		/^(?:read-path|reaper): target stuck >/.test(error) ||
		/^(?:brand_audit_single|discover_brand_domains) budget exceeded/.test(error)
	) {
		return 'Audit target exceeded its deadline.';
	}
	return 'Audit target processing failed.';
}
