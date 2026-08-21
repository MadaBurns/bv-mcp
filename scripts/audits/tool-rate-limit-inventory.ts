// SPDX-License-Identifier: BUSL-1.1
//
// Rate-limit inventory audit (#746).
//
// Emits, for every entry in TOOL_DEFS, the rate-limit decision surface:
//   name, group, tier, scanIncluded, auth-required, internal-only,
//   gated-paid-only, free-tier daily quota, partner-tier effective daily limit,
//   and whether that partner limit is EXPLICIT (an entry in
//   TIER_TOOL_DAILY_LIMITS.partner) or INHERITED (the flat TIER_DAILY_LIMITS.partner).
//
// Usage:
//   npx tsx scripts/audits/tool-rate-limit-inventory.ts            # table
//   npx tsx scripts/audits/tool-rate-limit-inventory.ts --json     # machine-readable
//   npx tsx scripts/audits/tool-rate-limit-inventory.ts --inherited-only
//
// The DURABLE guard is test/audits/tool-quota-coverage.audit.test.ts (it fails
// when a TOOL_DEFS entry carries no explicit partner-tier decision). This script
// is the human-readable companion used to make those decisions.

import { TOOLS } from '../../src/schemas/tool-definitions';
import {
	TIER_DAILY_LIMITS,
	TIER_TOOL_DAILY_LIMITS,
	FREE_TOOL_DAILY_LIMITS,
	INTENTIONALLY_UNLIMITED_TOOLS,
	INTENTIONALLY_PARTNER_FLAT_TOOLS,
	INTERNAL_ONLY_TOOLS,
	AUTH_REQUIRED_TOOLS,
	GATED_PAID_ONLY_TOOLS,
} from '../../src/lib/config';

interface Row {
	name: string;
	group: string;
	tier: string;
	scanIncluded: boolean;
	internalOnly: boolean;
	authRequired: boolean;
	gatedPaidOnly: boolean;
	freeDaily: number | 'unlimited' | 'none';
	partnerDaily: number;
	partnerSource: 'explicit' | 'inherited';
	partnerFlatDeclared: boolean;
}

const partnerOverrides = TIER_TOOL_DAILY_LIMITS.partner ?? {};

const rows: Row[] = TOOLS.map((tool) => {
	const explicit = Object.prototype.hasOwnProperty.call(partnerOverrides, tool.name);
	const free = Object.prototype.hasOwnProperty.call(FREE_TOOL_DAILY_LIMITS, tool.name)
		? FREE_TOOL_DAILY_LIMITS[tool.name]
		: INTENTIONALLY_UNLIMITED_TOOLS.has(tool.name)
			? ('unlimited' as const)
			: ('none' as const);
	return {
		name: tool.name,
		group: tool.group,
		tier: tool.tier ?? '—',
		scanIncluded: tool.scanIncluded,
		internalOnly: INTERNAL_ONLY_TOOLS.has(tool.name),
		authRequired: AUTH_REQUIRED_TOOLS.has(tool.name),
		gatedPaidOnly: GATED_PAID_ONLY_TOOLS.has(tool.name),
		freeDaily: free,
		partnerDaily: explicit ? partnerOverrides[tool.name] : TIER_DAILY_LIMITS.partner,
		partnerSource: explicit ? 'explicit' : 'inherited',
		partnerFlatDeclared: INTENTIONALLY_PARTNER_FLAT_TOOLS.has(tool.name),
	};
});

const args = new Set(process.argv.slice(2));
const shown = args.has('--inherited-only') ? rows.filter((r) => r.partnerSource === 'inherited') : rows;

if (args.has('--json')) {
	console.log(JSON.stringify(shown, null, 2));
} else {
	const header = ['tool', 'group', 'tier', 'scan', 'auth', 'gated', 'free/day', 'partner/day', 'source', 'flat-declared'];
	const table = shown.map((r) => [
		r.name + (r.internalOnly ? ' (internal)' : ''),
		r.group,
		r.tier,
		r.scanIncluded ? 'y' : '',
		r.authRequired ? 'y' : '',
		r.gatedPaidOnly ? 'y' : '',
		String(r.freeDaily),
		String(r.partnerDaily),
		r.partnerSource,
		r.partnerFlatDeclared ? 'y' : '',
	]);
	const widths = header.map((h, i) => Math.max(h.length, ...table.map((row) => row[i].length)));
	const fmt = (row: string[]) => row.map((cell, i) => cell.padEnd(widths[i])).join('  ');
	console.log(fmt(header));
	console.log(widths.map((w) => '-'.repeat(w)).join('  '));
	for (const row of table) console.log(fmt(row));

	const inherited = rows.filter((r) => r.partnerSource === 'inherited');
	const undecided = inherited.filter((r) => !r.partnerFlatDeclared && !r.internalOnly);
	console.log(
		`\ntotals: ${rows.length} tools · explicit ${rows.length - inherited.length} · inherited ${inherited.length}` +
			` (declared-flat ${inherited.length - undecided.length - inherited.filter((r) => r.internalOnly).length}, UNDECIDED ${undecided.length})`,
	);
	if (undecided.length) console.log(`UNDECIDED: ${undecided.map((r) => r.name).join(', ')}`);

	// Alias keys in the partner block that are not TOOL_DEFS names (e.g. `scan`).
	const toolNames = new Set(TOOLS.map((t) => t.name));
	const aliasKeys = Object.keys(partnerOverrides).filter((k) => !toolNames.has(k));
	if (aliasKeys.length) console.log(`alias keys in TIER_TOOL_DAILY_LIMITS.partner (not TOOL_DEFS): ${aliasKeys.join(', ')}`);
}
