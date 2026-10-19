// SPDX-License-Identifier: BUSL-1.1

/**
 * Table-driven coverage of every per-provider `add_txt` fix-step builder in provider-guides.
 * Each builder interpolates the record name/value with `?? '@'` / `?? '(see recommendation)'`
 * fallbacks; both branches are exercised for every provider.
 */

import { describe, it, expect } from 'vitest';
import { getProviderFixSteps } from '../src/tools/provider-guides';

// `signIn` = the provider-specific first step; `valueStep` = the step that carries the record value.
const ADD_TXT_PROVIDERS: ReadonlyArray<{ provider: string; signIn: string; valueStep: RegExp }> = [
	{ provider: 'Google Workspace', signIn: 'Sign in to your domain registrar or DNS provider.', valueStep: /^Add a new TXT record with name / },
	{
		provider: 'Microsoft 365',
		signIn: 'Sign in to your domain registrar or DNS provider (not Microsoft 365 admin).',
		valueStep: /^Add a new TXT record with name /,
	},
	{ provider: 'Cloudflare', signIn: 'Sign in to the Cloudflare dashboard (dash.cloudflare.com).', valueStep: /^Set the Name field to / },
	{ provider: 'AWS Route 53', signIn: 'Sign in to the AWS Management Console.', valueStep: /^Set the value to: / },
	{ provider: 'Namecheap', signIn: 'Sign in to your Namecheap account.', valueStep: /^Set Host to / },
	{ provider: 'GoDaddy', signIn: 'Sign in to your GoDaddy account.', valueStep: /^Set Name to / },
	{ provider: 'Fastmail', signIn: 'Sign in to the Fastmail control panel.', valueStep: /^Add a TXT record with name / },
	{ provider: 'Mimecast', signIn: 'Log in to the Mimecast Administration Console.', valueStep: /^Add a TXT record with name / },
];

describe('provider-guides add_txt builders', () => {
	describe.each(ADD_TXT_PROVIDERS)('$provider', ({ provider, signIn, valueStep }) => {
		it('interpolates the supplied record name and value', () => {
			const steps = getProviderFixSteps(provider, 'add_txt', { name: '_dmarc', value: 'v=DMARC1; p=reject' });
			expect(steps).not.toBeNull();
			expect(steps![0]).toBe(signIn);
			const carrier = steps!.find((s) => valueStep.test(s));
			expect(carrier, `${provider}: no step matching ${valueStep}`).toBeDefined();
			expect(carrier).toContain('v=DMARC1; p=reject');
		});

		it('falls back to "@" and the "(see recommendation)" placeholder when params are absent', () => {
			const steps = getProviderFixSteps(provider, 'add_txt', {});
			expect(steps).not.toBeNull();
			const carrier = steps!.find((s) => valueStep.test(s));
			expect(carrier, `${provider}: no step matching ${valueStep}`).toBeDefined();
			expect(carrier).toContain('(see recommendation)');
			expect(steps!.some((s) => s.includes('"@"') || s.includes('\'@\''))).toBe(true);
		});
	});
});
