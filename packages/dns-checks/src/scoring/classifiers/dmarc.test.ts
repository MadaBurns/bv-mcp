// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it } from 'vitest';
import { classifyDmarc } from './dmarc';

const base = { recordCount: 1 } as const;

describe('classifyDmarc', () => {
	it('flags absent DMARC as high (NIST v3.5.0)', () => {
		const f = classifyDmarc({ recordCount: 0, policy: null });
		expect(f).toHaveLength(1);
		expect(f[0].title).toBe('No DMARC record found');
		expect(f[0].severity).toBe('high');
	});

	it('scores p=none as a medium finding (NIST v3.5.0)', () => {
		const f = classifyDmarc({ ...base, policy: 'none' });
		expect(f.find((x) => x.title === 'DMARC policy set to none')?.severity).toBe('medium');
	});

	it('flags p=quarantine as low', () => {
		const f = classifyDmarc({ ...base, policy: 'quarantine', rua: 'mailto:dmarc@example.com' });
		expect(f.find((x) => x.title === 'DMARC policy set to quarantine')?.severity).toBe('low');
	});

	it('emits no significant finding for a clean p=reject record', () => {
		const f = classifyDmarc({ ...base, policy: 'reject', sp: 'reject', rua: 'mailto:dmarc@example.com', adkim: 's', aspf: 's' });
		const significant = f.filter((x) => ['critical', 'high', 'medium'].includes(x.severity));
		expect(significant).toHaveLength(0);
	});

	it('flags multiple records as high', () => {
		const f = classifyDmarc({ ...base, recordCount: 2, policy: 'reject', rua: 'mailto:dmarc@example.com', adkim: 's', aspf: 's' });
		expect(f.some((x) => x.title === 'Multiple DMARC records' && x.severity === 'high')).toBe(true);
	});

	it('flags missing p= tag as critical', () => {
		const f = classifyDmarc({ ...base, policy: null });
		expect(f.some((x) => x.title === 'Missing DMARC policy' && x.severity === 'critical')).toBe(true);
	});

	it('downgrades weak subdomain policy when np protects (DMARCbis)', () => {
		const f = classifyDmarc({ ...base, policy: 'reject', sp: 'none', np: 'reject', rua: 'mailto:dmarc@example.com' });
		expect(f.find((x) => x.title === 'Subdomain policy weaker than parent policy')?.severity).toBe('low');
	});
});
