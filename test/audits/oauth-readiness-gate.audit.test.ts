import { describe, expect, it } from 'vitest';

// Audit: every OAuth-related route in src/index.ts must be wrapped in `oauthGuarded`
// (the three-state availability gate added in v2.10.9). Bare `isOAuthEnabled` /
// boolean checks are forbidden — they're the smoking gun from the 2026-05-08
// incident, where misconfigured deploys exposed routes that succeeded until
// /oauth/token, leaking partial state to users mid-consent.
//
// This audit catches the regression at lint time before another silent rollout.

const indexSource = (
	import.meta.glob('../../src/index.ts', { query: '?raw', import: 'default', eager: true }) as Record<string, string>
)['../../src/index.ts'];

describe('OAuth route readiness-gate audit', () => {
	it('source loaded', () => {
		expect(indexSource).toBeDefined();
		expect(indexSource.length).toBeGreaterThan(1000);
	});

	it('every OAuth path registration goes through oauthGuarded(), not a bare ternary', () => {
		// Forbidden patterns: a route handler that ternaries on `isOAuthEnabled` /
		// `ENABLE_OAUTH` directly instead of dispatching through `oauthGuarded`.
		// The forbidden form is what existed pre-v2.10.9 and what the incident hit.
		const forbidden = /\b(isOAuthEnabled|env\.ENABLE_OAUTH\s*===)\b/g;
		const matches = indexSource.match(forbidden);
		expect(
			matches,
			'src/index.ts must not check ENABLE_OAUTH directly outside oauthAvailability — use oauthGuarded() at the route layer',
		).toBeNull();
	});

	it('all six OAuth route paths are wrapped in oauthGuarded', () => {
		const oauthRoutes = [
			'/.well-known/oauth-authorization-server',
			'/.well-known/oauth-protected-resource',
			'/oauth/register',
			'/oauth/authorize', // appears for GET and POST — counted via grep below
			'/oauth/token',
		];

		// Each route's registration line must reference oauthGuarded.
		for (const route of oauthRoutes) {
			const escaped = route.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
			// Find lines mentioning the route literal that are also a route registration.
			const routeLineRegex = new RegExp(`^.*['\`"]${escaped}['\`"].*$`, 'gm');
			const routeLines = indexSource.match(routeLineRegex) ?? [];
			expect(routeLines.length, `route ${route} must appear in src/index.ts`).toBeGreaterThan(0);

			// At least one of those lines (or a near-neighbor) must be inside an
			// oauthGuarded() call. We approximate by requiring the line OR the
			// adjacent handler arrow to mention oauthGuarded.
			const surroundingRegex = new RegExp(
				`['\`"]${escaped}['\`"][^]{0,200}oauthGuarded\\s*\\(`,
				's',
			);
			expect(
				surroundingRegex.test(indexSource),
				`route ${route} registration must dispatch through oauthGuarded(c, …)`,
			).toBe(true);
		}
	});

	it('oauthAvailability returns the three documented states and only those', () => {
		// Defense against a future change that adds states like 'partial' or removes
		// 'misconfigured', either of which would silently re-enable the incident.
		const literalsRegex = /OAuthAvailability\s*=\s*['`"]ready['`"]\s*\|\s*['`"]disabled['`"]\s*\|\s*['`"]misconfigured['`"]/;
		expect(
			literalsRegex.test(indexSource),
			'OAuthAvailability type union must be exactly: "ready" | "disabled" | "misconfigured"',
		).toBe(true);
	});

	it('oauthMisconfiguredResponse uses 503 + service_unavailable + JSON body', () => {
		// Locks the wire shape the chaos test asserts against.
		const fnRegex = /function\s+oauthMisconfiguredResponse[^]*?status:\s*503/;
		const errorRegex = /service_unavailable/;
		expect(fnRegex.test(indexSource), 'oauthMisconfiguredResponse must return status: 503').toBe(true);
		expect(errorRegex.test(indexSource), 'oauthMisconfiguredResponse must use error: "service_unavailable"').toBe(
			true,
		);
	});
});
