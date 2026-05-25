// SPDX-License-Identifier: BUSL-1.1
//
// Audit test: the public `wrangler.jsonc` must NOT declare the brand-discovery
// cross-Worker bindings that are proprietary to BlackVeil production.
//
// Background: `BV_INFRA_GRAPH`, `BV_INTEL_GATEWAY`, and `BV_ENTERPRISE` are
// service bindings to bv-web-owned Workers. `BV_RECON` is an operator-only
// recon service binding; `BV_RECON_KEY` is its companion secret. bv-mcp is
// BUSL-1.1 source-available; `discovery_mode: 'classic'` is the only supported
// mode for self-hosted BSL deployments. The private overlay
// (`scripts/inject-private-config.cjs` + `.dev/wrangler.deploy.jsonc`) injects
// these bindings at deploy time for BlackVeil production only.
//
// If anyone accidentally promotes one of these binding names into the public
// `wrangler.jsonc`, this audit fails loudly — protecting the BSL self-host
// story and the proprietary-data-binding boundary.
//
// Per testing-methodology.md principle 4 — audit tests replace review checklists.

import { describe, it, expect } from 'vitest';

// Read the public wrangler.jsonc as raw text (cheaper than parsing JSONC, and
// catches the binding name regardless of which key it lives under).
import wranglerPublic from '../../wrangler.jsonc?raw';

const FORBIDDEN_PUBLIC_BINDINGS = [
	'BV_INFRA_GRAPH',
	'BV_INTEL_GATEWAY',
	'BV_ENTERPRISE',
	'BV_RECON',
	'BV_RECON_KEY',
] as const;

describe('public wrangler.jsonc license-boundary audit', () => {
	it('does not reference any private brand-discovery service binding', () => {
		const offenders = FORBIDDEN_PUBLIC_BINDINGS.filter((name) => wranglerPublic.includes(name));
		expect(
			offenders,
			`Forbidden private binding(s) found in public wrangler.jsonc: ${offenders.join(', ')}. ` +
				`These bindings live only in the private overlay (.dev/wrangler.deploy.jsonc) and must ` +
				`never appear in the BSL-licensed public config.`,
		).toEqual([]);
	});
});
