import { describe, it, expect } from 'vitest';
import { handleResourcesList, handleResourcesRead } from '../src/handlers/resources';

describe('handleResourcesList', () => {
	it('returns an object with a resources array of exactly 5 items', () => {
		const result = handleResourcesList();
		expect(result).toHaveProperty('resources');
		expect(result.resources).toHaveLength(5);
	});

	it('each resource has uri, name, mimeType, and description', () => {
		const { resources } = handleResourcesList();
		for (const resource of resources) {
			expect(resource).toHaveProperty('uri');
			expect(resource).toHaveProperty('name');
			expect(resource).toHaveProperty('mimeType');
			expect(resource).toHaveProperty('description');
		}
	});

	it('includes all expected URIs', () => {
		const { resources } = handleResourcesList();
		const uris = resources.map((r) => r.uri);
		expect(uris).toContain('dns-security://guides/security-checks');
		expect(uris).toContain('dns-security://guides/scoring');
		expect(uris).toContain('dns-security://guides/record-types');
		expect(uris).toContain('dns-security://guides/agent-workflows');
	});

	it('all mimeTypes are text/markdown', () => {
		const { resources } = handleResourcesList();
		for (const resource of resources) {
			expect(resource.mimeType).toBe('text/markdown');
		}
	});
});

describe('handleResourcesRead', () => {
	it('returns contents array with uri, mimeType, and text for security-checks', () => {
		const result = handleResourcesRead({ uri: 'dns-security://guides/security-checks' });
		expect(result).toHaveProperty('contents');
		expect(result.contents).toHaveLength(1);
		const item = result.contents[0];
		expect(item).toHaveProperty('uri', 'dns-security://guides/security-checks');
		expect(item).toHaveProperty('mimeType', 'text/markdown');
		expect(item).toHaveProperty('text');
	});

	it('security-checks content mentions SPF, DMARC, and DKIM', () => {
		const { contents } = handleResourcesRead({ uri: 'dns-security://guides/security-checks' });
		expect(contents[0].text).toContain('SPF');
		expect(contents[0].text).toContain('DMARC');
		expect(contents[0].text).toContain('DKIM');
	});

	it('scoring content mentions importance weights', () => {
		const { contents } = handleResourcesRead({ uri: 'dns-security://guides/scoring' });
		expect(contents[0].text).toContain('Importance Weights');
	});

	it('record-types content mentions DNS record types', () => {
		const { contents } = handleResourcesRead({ uri: 'dns-security://guides/record-types' });
		const text = contents[0].text;
		expect(text).toContain('A');
		expect(text).toContain('AAAA');
		expect(text).toContain('MX');
		expect(text).toContain('TXT');
	});

	it('throws when uri parameter is missing', () => {
		expect(() => handleResourcesRead({})).toThrow('Missing required parameter: uri');
	});

	it('throws for an unknown URI', () => {
		expect(() => handleResourcesRead({ uri: 'dns-security://guides/nonexistent' })).toThrow('Resource not found');
	});

	it('throws when uri is a number', () => {
		expect(() => handleResourcesRead({ uri: 42 as unknown as string })).toThrow('Missing required parameter: uri');
	});

	it('throws when uri is null', () => {
		expect(() => handleResourcesRead({ uri: null as unknown as string })).toThrow('Missing required parameter: uri');
	});
});
