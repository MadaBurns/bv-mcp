// SPDX-License-Identifier: BUSL-1.1
/**
 * Shared cross-repo scoring parity corpus.
 *
 * Both bv-mcp and bv-web run each fixture through their FULL `checkDMARC` (with a
 * mocked resolver returning `records`) and must produce `expectedScore` +
 * `expectedMissingControl`. This makes scoring drift between the two scanners a
 * test failure rather than a silent product divergence.
 *
 * Records are keyed on the queried name (e.g. `_dmarc.example.com`) so the corpus
 * exercises each repo's fact-extraction (tag parsing, DMARCbis tree-walk) — the
 * UNSHARED layer where drift actually lives — not just the shared classifier.
 *
 * Design: bv-web docs/superpowers/specs/2026-05-31-cross-repo-scoring-parity-gate-design.md
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd. Licensed under BSL 1.1.
 */

export interface DmarcParityFixture {
	check: 'dmarc';
	/** Human label for the case. */
	name: string;
	/** Primary lookup name, e.g. "_dmarc.example.com". */
	query: string;
	/** Lookup name -> TXT records the mock resolver returns (includes parents for tree-walk). */
	records: Record<string, string[]>;
	expectedScore: number;
	expectedMissingControl: boolean;
	/**
	 * True when the fixture requires RFC 9989 §4.10 tree-walk inheritance. The
	 * tree-walking full checks (bv-mcp `checkDMARC` + bv-web dns-worker-v2) BOTH
	 * assert it; only the SYNC extension path (records-in, no DNS) cannot tree-walk
	 * and skips it.
	 */
	treeWalkOnly?: boolean;
	/** Wrapper-only async finding bv-web can't compute (e.g. third-party RUA-auth), documented. */
	asyncDelta?: { finding: string; points: number };
}

/** Must equal the package version (asserted by both repos' version-lock). */
export const PARITY_CORPUS_VERSION = '1.3.5';

/**
 * DNSSEC parity fixture. Keyed on the AD flag + DNSKEY/DS/NSEC3PARAM records.
 * NIST SP 800-81r3 / RFC 9364 (BCP 237): unsigned public zone is near-failing
 * (critical → ~60, NOT zeroed); broken-chain / validation-failing are BOGUS
 * (missingControl → 0); RSA is valid-but-soft-dinged; NSEC3 penalized only on
 * RFC-9276-violating params.
 */
export interface DnssecParityFixture {
	check: 'dnssec';
	name: string;
	domain: string;
	/** DNSSEC AD flag (authenticated data) from the raw query. */
	ad: boolean;
	dnskey: string[];
	ds: string[];
	nsec3param: string[];
	expectedScore: number;
	expectedMissingControl: boolean;
}

/**
 * SVCB-HTTPS parity fixture (RFC 9460). Coarse-advisory scoring: a present record
 * scores ~90-100 (info/low), absence is NOT a deficiency (~95, no missingControl)
 * — HTTPS/SVCB RRs are a performance/privacy optimization, not a required control.
 */
export interface SvcbParityFixture {
	check: 'svcb_https';
	name: string;
	domain: string;
	/** HTTPS (type 65) records returned for `domain`. */
	https: string[];
	expectedScore: number;
	expectedMissingControl: boolean;
}

/**
 * DANE-HTTPS parity fixture. Keyed on the TLSA records at `_443._tcp.<domain>`
 * plus the DNSSEC AD flag (DANE without DNSSEC is ineffective → RFC 7672).
 * Both repos run their full checkDANEHTTPS over these + must match.
 */
export interface DaneHttpsParityFixture {
	check: 'dane_https';
	name: string;
	domain: string;
	/** TLSA records returned at `_443._tcp.<domain>`. */
	tlsa: string[];
	/** DNSSEC AD flag from the raw query (DANE-TA/EE without DNSSEC is downgraded). */
	ad: boolean;
	expectedScore: number;
	expectedMissingControl: boolean;
}

export const DMARC_PARITY_FIXTURES: DmarcParityFixture[] = [
	{
		check: 'dmarc',
		name: 'no record (missingControl)',
		query: '_dmarc.example.com',
		records: { '_dmarc.example.com': [] },
		expectedScore: 0,
		expectedMissingControl: true,
	},
	{
		check: 'dmarc',
		name: 'p=none + rua',
		query: '_dmarc.example.com',
		records: { '_dmarc.example.com': ['v=DMARC1; p=none; rua=mailto:d@example.com'] },
		expectedScore: 70,
		expectedMissingControl: false,
	},
	{
		check: 'dmarc',
		name: 'p=quarantine + rua',
		query: '_dmarc.example.com',
		records: { '_dmarc.example.com': ['v=DMARC1; p=quarantine; rua=mailto:d@example.com'] },
		expectedScore: 80,
		expectedMissingControl: false,
	},
	{
		check: 'dmarc',
		name: 'p=reject strict alignment + rua',
		query: '_dmarc.example.com',
		records: {
			'_dmarc.example.com': [
				'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:d@example.com',
			],
		},
		expectedScore: 95,
		expectedMissingControl: false,
	},
	{
		check: 'dmarc',
		name: 't=y test mode (1.3.0 superset)',
		query: '_dmarc.example.com',
		records: { '_dmarc.example.com': ['v=DMARC1; p=reject; t=y; rua=mailto:d@example.com'] },
		expectedScore: 65,
		expectedMissingControl: false,
	},
	{
		check: 'dmarc',
		name: 'np=none spoofable (1.3.0 superset)',
		query: '_dmarc.example.com',
		records: { '_dmarc.example.com': ['v=DMARC1; p=reject; np=none; rua=mailto:d@example.com'] },
		expectedScore: 65,
		expectedMissingControl: false,
	},
	{
		check: 'dmarc',
		name: 'multiple records',
		query: '_dmarc.example.com',
		records: { '_dmarc.example.com': ['v=DMARC1; p=none', 'v=DMARC1; p=reject'] },
		expectedScore: 45,
		expectedMissingControl: false,
	},
	{
		// RFC 9989 §4.10 inheritance: the subdomain has no record, so the tree walk
		// applies the org domain's sp (=quarantine). No rua here — this fixture
		// isolates tree-walk inheritance from the (separately tested) RUA-auth path.
		check: 'dmarc',
		name: 'subdomain inherits parent sp=quarantine (tree-walk)',
		query: '_dmarc.blog.example.com',
		records: {
			'_dmarc.blog.example.com': [],
			'_dmarc.example.com': ['v=DMARC1; p=reject; sp=quarantine'],
		},
		expectedScore: 70,
		expectedMissingControl: false,
		treeWalkOnly: true,
	},
];

const SHA256_HASH = '0000000000000000000000000000000000000000000000000000000000000001';

export const DANE_HTTPS_PARITY_FIXTURES: DaneHttpsParityFixture[] = [
	{
		check: 'dane_https',
		name: 'no TLSA record',
		domain: 'example.com',
		tlsa: [],
		ad: true,
		expectedScore: 95,
		expectedMissingControl: false,
	},
	{
		check: 'dane_https',
		name: 'valid DANE-EE (3 1 1) + DNSSEC',
		domain: 'example.com',
		tlsa: [`3 1 1 ${SHA256_HASH}`],
		ad: true,
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		check: 'dane_https',
		name: 'valid DANE-EE (3 1 1) without DNSSEC',
		domain: 'example.com',
		tlsa: [`3 1 1 ${SHA256_HASH}`],
		ad: false,
		expectedScore: 75,
		expectedMissingControl: false,
	},
	{
		check: 'dane_https',
		name: 'malformed TLSA (3 fields)',
		domain: 'example.com',
		tlsa: ['3 1 1'],
		ad: true,
		expectedScore: 85,
		expectedMissingControl: false,
	},
	{
		check: 'dane_https',
		name: 'PKIX-EE (1 1 1) without DNSSEC',
		domain: 'example.com',
		tlsa: [`1 1 1 ${SHA256_HASH}`],
		ad: false,
		expectedScore: 100,
		expectedMissingControl: false,
	},
];

export const SVCB_HTTPS_PARITY_FIXTURES: SvcbParityFixture[] = [
	{
		check: 'svcb_https',
		name: 'no HTTPS record (advisory absence)',
		domain: 'example.com',
		https: [],
		expectedScore: 95,
		expectedMissingControl: false,
	},
	{
		check: 'svcb_https',
		name: 'ServiceMode + ALPN h2,h3',
		domain: 'example.com',
		https: ['1 . alpn="h2,h3"'],
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		check: 'svcb_https',
		name: 'ServiceMode + ALPN + ECH',
		domain: 'example.com',
		https: ['1 . alpn="h2,h3" ech="AEX+DQ"'],
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		check: 'svcb_https',
		name: 'AliasMode',
		domain: 'example.com',
		https: ['0 cdn.example.com.'],
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		check: 'svcb_https',
		name: 'ServiceMode no ALPN',
		domain: 'example.com',
		https: ['1 . port=443'],
		expectedScore: 90,
		expectedMissingControl: false,
	},
];

// Placeholder DNSKEY/DS records (algorithm field is what matters: alg 13 = ECDSA P-256,
// alg 8 = RSA/SHA-256). DS format "keytag algorithm digesttype hash".
export const DNSSEC_PARITY_FIXTURES: DnssecParityFixture[] = [
	{
		check: 'dnssec',
		name: 'no DNSSEC (unsigned public — near-failing, not zeroed)',
		domain: 'example.com',
		ad: false,
		dnskey: [],
		ds: [],
		nsec3param: [],
		expectedScore: 60,
		expectedMissingControl: false,
	},
	{
		check: 'dnssec',
		name: 'valid + DNSSEC (ECDSA P-256)',
		domain: 'example.com',
		ad: true,
		dnskey: ['257 3 13 AwEAAabc'],
		ds: ['12345 13 2 abc123'],
		nsec3param: [],
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		check: 'dnssec',
		name: 'valid RSA/SHA-256 (acceptable, soft-dinged)',
		domain: 'example.com',
		ad: true,
		dnskey: ['257 3 8 AwEAAabc'],
		ds: ['12345 8 2 abc123'],
		nsec3param: [],
		expectedScore: 95,
		expectedMissingControl: false,
	},
	{
		check: 'dnssec',
		name: 'broken chain (DNSKEY, no DS — BOGUS)',
		domain: 'example.com',
		ad: false,
		dnskey: ['257 3 13 AwEAAabc'],
		ds: [],
		nsec3param: [],
		expectedScore: 0,
		expectedMissingControl: true,
	},
	{
		check: 'dnssec',
		name: 'validation failing (DNSKEY+DS, AD off — BOGUS, DNSSEC-1)',
		domain: 'example.com',
		ad: false,
		dnskey: ['257 3 13 AwEAAabc'],
		ds: ['12345 13 2 abc123'],
		nsec3param: [],
		expectedScore: 0,
		expectedMissingControl: true,
	},
	{
		check: 'dnssec',
		name: 'NSEC3 RFC 9276 violations (150 iterations + non-empty salt)',
		domain: 'example.com',
		ad: true,
		dnskey: ['257 3 13 AwEAAabc'],
		ds: ['12345 13 2 abc123'],
		nsec3param: ['1 0 150 ab'],
		expectedScore: 70,
		expectedMissingControl: false,
	},
];
