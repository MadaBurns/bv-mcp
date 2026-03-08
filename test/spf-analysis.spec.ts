import { describe, expect, it } from 'vitest';
import { analyzeSpfLookupBudget, checkBroadIpRanges, extractLookupDomains, extractSpfSignalDomains } from '../src/tools/spf-analysis';

describe('spf-analysis', () => {
	it('counts DNS lookup mechanisms in a single SPF record', () => {
		const analysis = analyzeSpfLookupBudget('v=spf1 include:a.com a mx exists:test.com redirect=_spf.example.com -all');
		expect(analysis.count).toBe(5);
		expect(analysis.mechanisms).toEqual(['include', 'a', 'mx', 'exists', 'redirect']);
	});

	it('extracts include and redirect domains for downstream signal use', () => {
		expect(extractSpfSignalDomains('v=spf1 include:_spf.google.com include:mail.example.com redirect=_spf.example.net')).toEqual({
			includeDomains: ['_spf.google.com', 'mail.example.com'],
			redirectDomain: '_spf.example.net',
		});
		expect(extractLookupDomains('v=spf1 include:a.com include:b.com redirect=c.com -all')).toEqual({
			includes: ['a.com', 'b.com'],
			redirect: 'c.com',
		});
	});

	it('flags overly broad IPv4 and IPv6 ranges', () => {
		const findings = checkBroadIpRanges('v=spf1 ip4:10.0.0.0/8 ip6:2001::/16 -all', { signalType: 'spf' });
		expect(findings).toHaveLength(2);
		expect(findings[0].title).toContain('Overly broad IP range');
		expect(findings[1].title).toContain('Overly broad IPv6 range');
	});
});