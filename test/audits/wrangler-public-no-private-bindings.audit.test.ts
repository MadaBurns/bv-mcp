// SPDX-License-Identifier: BUSL-1.1
//
// Audit test: the public `wrangler.jsonc` must NOT declare the brand-discovery
// cross-Worker bindings that are proprietary to BlackVeil production.
//
// Background: `BV_INFRA_GRAPH`, `BV_INTEL_GATEWAY`, and `BV_ENTERPRISE` are
// service bindings to bv-web-owned Workers. `BV_RECON` is an operator-only
// recon service binding; `BV_RECON_KEY` is its companion secret. `BV_WEB` is the
// proprietary bv-web-prod service binding (OAuth consent proxy + the m365Proxy
// for the identity_secops tools) — CLAUDE.md documents it as "not in public
// wrangler.jsonc", and its `service: bv-web-prod` reference both leaks the
// proprietary service name and breaks a BSL self-host `wrangler deploy`. bv-mcp
// is BUSL-1.1 source-available; `discovery_mode: 'classic'` is the only supported
// mode for self-hosted BSL deployments. The private overlay
// (`scripts/inject-private-config.cjs` + `.dev/wrangler.deploy.jsonc`) injects
// these bindings at deploy time for BlackVeil production only.
//
// NOTE: matched as quoted-exact tokens (`"BV_WEB"`) so the legitimately-public
// `BV_WEB_OAUTH_CONSENT_URL` var (a public consent URL) is not a false positive.
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
	'BV_TLS_PROBE',
	'BV_TLS_PROBE_KEY',
	'BV_WEB',
] as const;

describe('public wrangler.jsonc license-boundary audit', () => {
	it('does not reference any private brand-discovery service binding', () => {
		// Quoted-exact match so `"BV_WEB"` (the binding) is caught while
		// `"BV_WEB_OAUTH_CONSENT_URL"` (a legitimately-public var) is not.
		const offenders = FORBIDDEN_PUBLIC_BINDINGS.filter((name) => wranglerPublic.includes(`"${name}"`));
		expect(
			offenders,
			`Forbidden private binding(s) found in public wrangler.jsonc: ${offenders.join(', ')}. ` +
				`These bindings live only in the private overlay (.dev/wrangler.deploy.jsonc) and must ` +
				`never appear in the BSL-licensed public config.`,
		).toEqual([]);
	});
});
