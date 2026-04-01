import { describe, expect, it } from 'vitest';

describe('dnssec-analysis', () => {
	async function getModule() {
		return import('../src/tools/dnssec-analysis');
	}

	it('parses the DNSKEY algorithm from record data', async () => {
		const { parseDnskeyAlgorithm } = await getModule();
		expect(parseDnskeyAlgorithm('257 3 13 mdsswUyr3DPW...')).toBe(13);
		expect(parseDnskeyAlgorithm('bad-record')).toBeNull();
	});

	it('parses DS algorithm and digest type from record data', async () => {
		const { parseDsRecord } = await getModule();
		expect(parseDsRecord('12345 13 2 abc123...')).toEqual({ algorithm: 13, digestType: 2 });
		expect(parseDsRecord('invalid')).toBeNull();
	});

	it('flags deprecated and unknown DNSKEY algorithms once each', async () => {
		const { auditDnskeyAlgorithms } = await getModule();
		const findings = auditDnskeyAlgorithms('example.com', ['257 3 5 oldkey', '257 3 5 duplicate-oldkey', '257 3 99 unknownkey']);

		expect(findings).toHaveLength(2);
		expect(findings.map((finding) => finding.title)).toEqual([
			'Deprecated DNSKEY algorithm (RSA/SHA-1)',
			'Unknown DNSKEY algorithm (99)',
		]);
	});

	it('emits an info finding for modern DNSKEY algorithms', async () => {
		const { auditDnskeyAlgorithms } = await getModule();
		const findings = auditDnskeyAlgorithms('example.com', ['257 3 13 modernkey']);

		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].title).toBe('Modern DNSSEC algorithm (ECDSA P-256)');
	});

	it('flags deprecated DS digest types once each', async () => {
		const { auditDsDigestTypes } = await getModule();
		const findings = auditDsDigestTypes('example.com', ['12345 13 1 olddigest', '67890 13 1 duplicate-olddigest']);

		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('medium');
		expect(findings[0].title).toBe('Deprecated DS digest type (SHA-1)');
	});
});