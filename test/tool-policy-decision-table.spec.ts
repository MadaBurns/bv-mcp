// SPDX-License-Identifier: BUSL-1.1

/**
 * Decision table for the per-tool policy chokepoint `evaluateToolPolicy` (src/lib/config.ts).
 *
 * The precedence is: empty tool -> internal-only (public only) -> auth-required -> paid-only
 * -> contract-flag. This spec pins it twice:
 *
 *  1. an explicit row table (input -> decision), one row per branch; and
 *  2. an exhaustive differential sweep against `referencePolicy`, a straight transcription of
 *     the pre-split implementation, over every tool that sits in any gate set crossed with
 *     surface x authenticated x tier x fullInternalAuthority x contract-flag inputs.
 *
 * Both run against the shipped function, so a refactor that reorders a gate or flips an arm fails here.
 */
import { describe, expect, it } from 'vitest';
import {
	AUTH_REQUIRED_TOOLS,
	CONTRACT_FLAGGED_TOOLS,
	GATED_PAID_ONLY_TOOLS,
	INTERNAL_ONLY_TOOLS,
	contractFlagBlocks,
	evaluateToolPolicy,
	isAuthRequiredTool,
	isGatedPaidOnlyTool,
	isInternalOnlyTool,
	tierToolDailyLimit,
	type McpApiKeyTier,
	type ToolPolicyDecision,
	type ToolPolicyInput,
} from '../src/lib/config';

const ALLOWED: ToolPolicyDecision = { allowed: true };
const deny = (block: 'internal_only' | 'auth_required' | 'paid_only' | 'contract_flag'): ToolPolicyDecision => ({ allowed: false, block });

/** Transcription of the pre-split decision ladder (the pinned truth). */
function referencePolicy(input: ToolPolicyInput): ToolPolicyDecision {
	const { surface, tool, authenticated, tier } = input;
	if (!tool) return ALLOWED;
	const fullInternalAuthority = surface === 'internal' && input.fullInternalAuthority === true;
	if (isInternalOnlyTool(tool) && surface === 'public') return deny('internal_only');
	if (isAuthRequiredTool(tool)) {
		if (surface === 'public') {
			if (!authenticated) return deny('auth_required');
		} else if (!authenticated || !fullInternalAuthority) {
			return deny('auth_required');
		}
	}
	if (isGatedPaidOnlyTool(tool) && !fullInternalAuthority) {
		if (tier === null) return deny('paid_only');
		if (tierToolDailyLimit(tier, tool) === 0) return deny('paid_only');
	}
	if (
		tier !== null &&
		contractFlagBlocks({
			gateEnabled: input.contractFlagGateEnabled === true,
			tier,
			tool,
			hasContractFlag: input.hasContractFlag === true,
		})
	) {
		return deny('contract_flag');
	}
	return ALLOWED;
}

const PAID = 'discover_subdomains'; // paid-only AND contract-flagged
const INTERNAL_ONLY = 'map_registrar_products';
const AUTH_REQUIRED = 'query_signins'; // auth-required (and, since 3.63.0, internal-only)
const ORDINARY = 'check_spf';

type Row = { name: string; input: ToolPolicyInput; expected: ToolPolicyDecision };

const ROWS: Row[] = [
	{
		name: 'empty tool falls through on public',
		input: { surface: 'public', tool: '', authenticated: false, tier: null },
		expected: ALLOWED,
	},
	{
		name: 'empty tool falls through on internal',
		input: { surface: 'internal', tool: '', authenticated: false, tier: null },
		expected: ALLOWED,
	},
	{
		name: 'public + internal-only tool + unauthenticated -> internal_only',
		input: { surface: 'public', tool: INTERNAL_ONLY, authenticated: false, tier: null },
		expected: deny('internal_only'),
	},
	{
		name: 'public + internal-only tool + owner -> internal_only (no tier escapes it)',
		input: { surface: 'public', tool: INTERNAL_ONLY, authenticated: true, tier: 'owner' },
		expected: deny('internal_only'),
	},
	{
		name: 'public + auth-required tool + unauthenticated -> internal_only (shadows the 401 arm)',
		input: { surface: 'public', tool: AUTH_REQUIRED, authenticated: false, tier: null },
		expected: deny('internal_only'),
	},
	{
		name: 'public + auth-required tool + authenticated -> internal_only (still shadowed)',
		input: { surface: 'public', tool: AUTH_REQUIRED, authenticated: true, tier: 'enterprise' },
		expected: deny('internal_only'),
	},
	{
		name: 'internal + internal-only tool + any caller -> allowed',
		input: { surface: 'internal', tool: INTERNAL_ONLY, authenticated: false, tier: null },
		expected: ALLOWED,
	},
	{
		name: 'internal + auth-required + full authority + authenticated -> allowed',
		input: { surface: 'internal', tool: AUTH_REQUIRED, authenticated: true, tier: 'owner', fullInternalAuthority: true },
		expected: ALLOWED,
	},
	{
		name: 'internal + auth-required + full authority + NOT authenticated (network guard only) -> auth_required',
		input: { surface: 'internal', tool: AUTH_REQUIRED, authenticated: false, tier: 'free', fullInternalAuthority: true },
		expected: deny('auth_required'),
	},
	{
		name: 'internal + auth-required + authenticated + narrow capability -> auth_required',
		input: { surface: 'internal', tool: AUTH_REQUIRED, authenticated: true, tier: 'developer', fullInternalAuthority: false },
		expected: deny('auth_required'),
	},
	{
		name: 'internal + auth-required + fullInternalAuthority omitted -> auth_required (fail closed)',
		input: { surface: 'internal', tool: AUTH_REQUIRED, authenticated: true, tier: 'owner' },
		expected: deny('auth_required'),
	},
	{
		name: 'public + paid-only + unauthenticated -> paid_only',
		input: { surface: 'public', tool: PAID, authenticated: false, tier: null },
		expected: deny('paid_only'),
	},
	{
		name: 'public + paid-only + free tier -> paid_only',
		input: { surface: 'public', tool: PAID, authenticated: true, tier: 'free' },
		expected: deny('paid_only'),
	},
	{
		name: 'public + paid-only + agent tier -> paid_only',
		input: { surface: 'public', tool: PAID, authenticated: true, tier: 'agent' },
		expected: deny('paid_only'),
	},
	{
		name: 'public + paid-only + developer tier -> allowed',
		input: { surface: 'public', tool: PAID, authenticated: true, tier: 'developer' },
		expected: ALLOWED,
	},
	{
		name: 'public + paid-only + fullInternalAuthority flag is ignored on public -> still paid_only',
		input: { surface: 'public', tool: PAID, authenticated: true, tier: 'free', fullInternalAuthority: true },
		expected: deny('paid_only'),
	},
	{
		name: 'internal + paid-only + full authority + no tier -> allowed (first-party)',
		input: { surface: 'internal', tool: PAID, authenticated: false, tier: null, fullInternalAuthority: true },
		expected: ALLOWED,
	},
	{
		name: 'internal + paid-only + narrow principal on free tier -> paid_only',
		input: { surface: 'internal', tool: PAID, authenticated: true, tier: 'free', fullInternalAuthority: false },
		expected: deny('paid_only'),
	},
	{
		name: 'internal + paid-only + narrow principal with no tier -> paid_only',
		input: { surface: 'internal', tool: PAID, authenticated: true, tier: null, fullInternalAuthority: false },
		expected: deny('paid_only'),
	},
	{
		name: 'contract-flag gate off -> allowed for developer',
		input: { surface: 'public', tool: PAID, authenticated: true, tier: 'developer', contractFlagGateEnabled: false },
		expected: ALLOWED,
	},
	{
		name: 'contract-flag gate on, claim absent -> contract_flag',
		input: { surface: 'public', tool: PAID, authenticated: true, tier: 'developer', contractFlagGateEnabled: true },
		expected: deny('contract_flag'),
	},
	{
		name: 'contract-flag gate on, claim present -> allowed',
		input: {
			surface: 'public',
			tool: PAID,
			authenticated: true,
			tier: 'developer',
			contractFlagGateEnabled: true,
			hasContractFlag: true,
		},
		expected: ALLOWED,
	},
	{
		name: 'contract-flag gate on, owner bypasses',
		input: { surface: 'public', tool: PAID, authenticated: true, tier: 'owner', contractFlagGateEnabled: true },
		expected: ALLOWED,
	},
	{
		name: 'paid_only outranks contract_flag for a free tier',
		input: { surface: 'public', tool: PAID, authenticated: true, tier: 'free', contractFlagGateEnabled: true },
		expected: deny('paid_only'),
	},
	{
		name: 'contract-flag is skipped when there is no tier (full-authority internal, tier null)',
		input: { surface: 'internal', tool: PAID, authenticated: true, tier: null, fullInternalAuthority: true, contractFlagGateEnabled: true },
		expected: ALLOWED,
	},
	{
		name: 'ordinary tool -> allowed unauthenticated on public',
		input: { surface: 'public', tool: ORDINARY, authenticated: false, tier: null },
		expected: ALLOWED,
	},
	{
		name: 'ordinary tool -> allowed on internal for a narrow principal',
		input: { surface: 'internal', tool: ORDINARY, authenticated: true, tier: 'free', fullInternalAuthority: false },
		expected: ALLOWED,
	},
];

describe('evaluateToolPolicy decision table', () => {
	it.each(ROWS)('$name', ({ input, expected }) => {
		expect(evaluateToolPolicy(input)).toEqual(expected);
	});

	it('every table row agrees with the transcribed reference ladder', () => {
		for (const row of ROWS) expect(referencePolicy(row.input)).toEqual(row.expected);
	});

	it('uses a fixture set that really contains each gate class', () => {
		expect(isGatedPaidOnlyTool(PAID)).toBe(true);
		expect(CONTRACT_FLAGGED_TOOLS.has(PAID)).toBe(true);
		expect(INTERNAL_ONLY_TOOLS.has(INTERNAL_ONLY)).toBe(true);
		expect(AUTH_REQUIRED_TOOLS.has(AUTH_REQUIRED)).toBe(true);
		expect(isInternalOnlyTool(ORDINARY) || isGatedPaidOnlyTool(ORDINARY) || isAuthRequiredTool(ORDINARY)).toBe(false);
	});
});

describe('evaluateToolPolicy exhaustive differential sweep', () => {
	const tools = new Set<string>([ORDINARY, '']);
	for (const set of [INTERNAL_ONLY_TOOLS, AUTH_REQUIRED_TOOLS, GATED_PAID_ONLY_TOOLS, CONTRACT_FLAGGED_TOOLS]) {
		for (const tool of set) tools.add(tool);
	}
	const tiers: Array<McpApiKeyTier | null> = [null, 'free', 'agent', 'developer', 'enterprise', 'partner', 'owner'];
	const fullAuthorities: Array<boolean | undefined> = [undefined, false, true];
	const flags = [undefined, false, true];

	it('matches the reference ladder for every combination', () => {
		let checked = 0;
		for (const surface of ['public', 'internal'] as const) {
			for (const tool of tools) {
				for (const authenticated of [false, true]) {
					for (const tier of tiers) {
						for (const fullInternalAuthority of fullAuthorities) {
							for (const contractFlagGateEnabled of flags) {
								for (const hasContractFlag of flags) {
									const input: ToolPolicyInput = {
										surface,
										tool,
										authenticated,
										tier,
										fullInternalAuthority,
										contractFlagGateEnabled,
										hasContractFlag,
									};
									expect(evaluateToolPolicy(input), JSON.stringify(input)).toEqual(referencePolicy(input));
									checked++;
								}
							}
						}
					}
				}
			}
		}
		expect(checked).toBeGreaterThan(5000);
	});
});
