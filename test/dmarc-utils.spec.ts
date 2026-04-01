import { describe, expect, it, vi, afterEach } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('dmarc-utils', () => {
	it('parses tag-value pairs case-insensitively', async () => {
		const { parseDmarcTags } = await import('../src/tools/dmarc-utils');
		const tags = parseDmarcTags('V=DMARC1; P=Reject; rua=mailto:d@example.com');
		expect(tags.get('v')).toBe('dmarc1');
		expect(tags.get('p')).toBe('reject');
	});

	it('validates DMARC report URIs and extracts domains from mailto targets', async () => {
		const { extractDomainFromMailto, isValidDmarcUri } = await import('../src/tools/dmarc-utils');
		expect(extractDomainFromMailto('mailto:reports@thirdparty.com!10m')).toBe('thirdparty.com');
		expect(isValidDmarcUri('mailto:reports@example.com')).toBe(true);
		expect(isValidDmarcUri('https://example.com/report')).toBe(false);
	});

	it('detects configured third-party aggregators', async () => {
		const { detectThirdPartyAggregators } = await import('../src/tools/dmarc-utils');
		expect(detectThirdPartyAggregators(['mailto:a@dmarcian.com', 'mailto:b@valimail.com'])).toEqual(['dmarcian.com', 'valimail.com']);
	});
});