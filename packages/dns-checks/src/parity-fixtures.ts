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
 * Copyright (c) 2023-2026 BLACKVEIL Security Licensed under BUSL-1.1.
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
export const PARITY_CORPUS_VERSION = '1.4.1';

/**
 * MX parity fixture. No-MX scoring is SPF-context (NIST SP 800-177r1 §4.4.2):
 * `-all`+no-MX = correct non-sender (100); SPF-without-`-all`+no-MX = soft (85);
 * no-MX+no-SPF = spoofable (0, missingControl). `hostA` provides A records for MX
 * hosts so the dangling-MX check passes.
 */
export interface MxParityFixture {
	check: 'mx';
	name: string;
	domain: string;
	mx: string[];
	txt: string[];
	/** MX-host → A records (so the hostname resolves; avoids a dangling-MX finding). */
	hostA: Record<string, string[]>;
	expectedScore: number;
	expectedMissingControl: boolean;
}

/**
 * CAA parity fixture (RFC 8659). Absence of CAA = any CA may issue → a defense-in-depth
 * gap (medium → 85, NOT zeroed even behind a managed CDN). Tags graded: missing issue
 * → medium, missing issuewild/iodef → low.
 */
export interface CaaParityFixture {
	check: 'caa';
	name: string;
	domain: string;
	/** CAA records returned for `domain`. */
	caa: string[];
	expectedScore: number;
	expectedMissingControl: boolean;
}

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

/**
 * DANE-email (SMTP) parity fixture. Keyed on the domain's MX records plus, per MX
 * host, the TLSA records at `_25._tcp.<host>` and the DNSSEC AD flag of that host's
 * zone (RFC 7672 §3.1.3 requires DNSSEC on the MX host, not the sending domain).
 * A domain with no usable MX → SMTP DANE not applicable (info, score 100).
 */
export interface DaneEmailParityFixture {
	check: 'dane';
	name: string;
	domain: string;
	/** MX records at `domain` ("priority exchange"). */
	mx: string[];
	/** TLSA records keyed by MX host (queried at `_25._tcp.<host>`). */
	tlsaByHost: Record<string, string[]>;
	/** DNSSEC AD flag per MX host (raw A query). Absent host ⇒ false. */
	adByHost: Record<string, boolean>;
	expectedScore: number;
	expectedMissingControl: boolean;
}

/** TLS-RPT parity fixture (RFC 8460). Keyed on the TXT records at `_smtp._tls.<domain>`. */
export interface TlsRptParityFixture {
	check: 'tlsrpt';
	name: string;
	domain: string;
	/** TXT records returned at `_smtp._tls.<domain>`. */
	txt: string[];
	expectedScore: number;
	expectedMissingControl: boolean;
}

/**
 * SPF parity fixture (RFC 7208). Keyed on TXT records per name so include-chains can
 * be expanded for the recursive DNS-lookup budget (>10 → PermError class).
 */
export interface SpfParityFixture {
	check: 'spf';
	name: string;
	domain: string;
	/** Lookup name → TXT records (domain + any included names for lookup counting). */
	txtByName: Record<string, string[]>;
	expectedScore: number;
	expectedMissingControl: boolean;
}

/** DKIM parity fixture (RFC 6376/8301). Keyed on the TXT record at `<selector>._domainkey.<domain>`. */
export interface DkimParityFixture {
	check: 'dkim';
	name: string;
	domain: string;
	selector: string;
	/** TXT records returned at `<selector>._domainkey.<domain>`. */
	txt: string[];
	expectedScore: number;
	expectedMissingControl: boolean;
}

/**
 * BIMI parity fixture. Keyed on the TXT records at `default._bimi.<domain>` plus the
 * DMARC record at `_dmarc.<domain>` (BIMI requires an enforcing DMARC policy). No
 * logo fetch (fetchFn omitted) — the corpus locks the DNS-derived bands only.
 */
export interface BimiParityFixture {
	check: 'bimi';
	name: string;
	domain: string;
	/** TXT records at `default._bimi.<domain>`. */
	bimi: string[];
	/** TXT records at `_dmarc.<domain>` (DMARC prerequisite). */
	dmarc: string[];
	expectedScore: number;
	expectedMissingControl: boolean;
}

/**
 * MTA-STS parity fixture (RFC 8461). Keyed on the `_mta-sts.<domain>` TXT record, the
 * `_smtp._tls.<domain>` TLS-RPT TXT, the domain MX records, and the fetched policy file
 * body (mode grading requires the HTTPS policy — supplied via a fixture `policy` string).
 */
export interface MtaStsParityFixture {
	check: 'mta_sts';
	name: string;
	domain: string;
	/** TXT records at `_mta-sts.<domain>`. */
	sts: string[];
	/** TXT records at `_smtp._tls.<domain>` (TLS-RPT). */
	tlsrpt: string[];
	/** MX records at `domain` (drives the no-inbound-mail fork). */
	mx: string[];
	/** Policy file body served at `https://mta-sts.<domain>/.well-known/mta-sts.txt`, or null = unfetchable. */
	policy: string | null;
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
		// RFC 9989: multiple DMARC records = no valid policy → unprotected (0,
		// missingControl), same as no record. Closes the prior bv-web divergence
		// (dns-worker-v2 used to parse-first → 35; now both score 0 via the classifier).
		check: 'dmarc',
		name: 'multiple records (no valid policy)',
		query: '_dmarc.example.com',
		records: { '_dmarc.example.com': ['v=DMARC1; p=none', 'v=DMARC1; p=reject'] },
		expectedScore: 0,
		expectedMissingControl: true,
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

export const DANE_EMAIL_PARITY_FIXTURES: DaneEmailParityFixture[] = [
	{
		// DANE-email-1: no MX → domain does not accept inbound mail → not applicable.
		check: 'dane',
		name: 'no MX (SMTP DANE not applicable)',
		domain: 'example.com',
		mx: [],
		tlsaByHost: {},
		adByHost: {},
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		// RFC 7505 null MX is also "no inbound mail" → not applicable, not a gap.
		check: 'dane',
		name: 'null MX (RFC 7505) — not applicable',
		domain: 'example.com',
		mx: ['0 .'],
		tlsaByHost: {},
		adByHost: {},
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		// Mail-accepting domain with no TLSA → real (but non-zeroing) gap → medium.
		check: 'dane',
		name: 'MX present, no TLSA (real gap)',
		domain: 'example.com',
		mx: ['10 mail.example.com'],
		tlsaByHost: {},
		adByHost: { 'mail.example.com': true },
		expectedScore: 85,
		expectedMissingControl: false,
	},
	{
		check: 'dane',
		name: 'valid DANE-EE (3 1 1) + DNSSEC on MX',
		domain: 'example.com',
		mx: ['10 mail.example.com'],
		tlsaByHost: { 'mail.example.com': [`3 1 1 ${SHA256_HASH}`] },
		adByHost: { 'mail.example.com': true },
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		// DANE-EE without DNSSEC on the MX zone → spoofable → high (−25) → 75.
		check: 'dane',
		name: 'DANE-EE without DNSSEC on MX',
		domain: 'example.com',
		mx: ['10 mail.example.com'],
		tlsaByHost: { 'mail.example.com': [`3 1 1 ${SHA256_HASH}`] },
		adByHost: { 'mail.example.com': false },
		expectedScore: 75,
		expectedMissingControl: false,
	},
	{
		// Malformed TLSA (3 fields) → medium (−15) → 85; absence note suppressed.
		check: 'dane',
		name: 'malformed TLSA on MX',
		domain: 'example.com',
		mx: ['10 mail.example.com'],
		tlsaByHost: { 'mail.example.com': ['3 1 1'] },
		adByHost: { 'mail.example.com': true },
		expectedScore: 85,
		expectedMissingControl: false,
	},
];

export const TLS_RPT_PARITY_FIXTURES: TlsRptParityFixture[] = [
	{ check: 'tlsrpt', name: 'no record (hardening absence)', domain: 'example.com', txt: [], expectedScore: 95, expectedMissingControl: false },
	{ check: 'tlsrpt', name: 'valid rua mailto', domain: 'example.com', txt: ['v=TLSRPTv1; rua=mailto:t@example.com'], expectedScore: 100, expectedMissingControl: false },
	{ check: 'tlsrpt', name: 'missing rua tag', domain: 'example.com', txt: ['v=TLSRPTv1;'], expectedScore: 85, expectedMissingControl: false },
	{ check: 'tlsrpt', name: 'invalid rua scheme', domain: 'example.com', txt: ['v=TLSRPTv1; rua=ftp://x/r'], expectedScore: 85, expectedMissingControl: false },
	{ check: 'tlsrpt', name: 'multiple records (≠1 = absent)', domain: 'example.com', txt: ['v=TLSRPTv1; rua=mailto:a@example.com', 'v=TLSRPTv1; rua=mailto:b@example.com'], expectedScore: 95, expectedMissingControl: false },
];

// Build a >10-lookup SPF include chain for the RFC 7208 §4.6.4 budget fixture.
const SPF_OVERLIMIT_TXT: Record<string, string[]> = (() => {
	const txtByName: Record<string, string[]> = {};
	let record = 'v=spf1';
	for (let i = 1; i <= 11; i++) {
		record += ` include:i${i}.example.com`;
		txtByName[`i${i}.example.com`] = ['v=spf1 ip4:10.0.0.0/8 -all'];
	}
	record += ' -all';
	txtByName['example.com'] = [record];
	return txtByName;
})();

export const SPF_PARITY_FIXTURES: SpfParityFixture[] = [
	{ check: 'spf', name: 'no SPF record (spoofable)', domain: 'example.com', txtByName: {}, expectedScore: 0, expectedMissingControl: true },
	{ check: 'spf', name: 'hard fail -all', domain: 'example.com', txtByName: { 'example.com': ['v=spf1 -all'] }, expectedScore: 100, expectedMissingControl: false },
	{ check: 'spf', name: 'soft fail ~all', domain: 'example.com', txtByName: { 'example.com': ['v=spf1 ~all'] }, expectedScore: 95, expectedMissingControl: false },
	{ check: 'spf', name: 'permissive +all', domain: 'example.com', txtByName: { 'example.com': ['v=spf1 +all'] }, expectedScore: 60, expectedMissingControl: false },
	{ check: 'spf', name: 'ptr mechanism (deprecated)', domain: 'example.com', txtByName: { 'example.com': ['v=spf1 ptr -all'] }, expectedScore: 85, expectedMissingControl: false },
	{ check: 'spf', name: '>10 DNS lookups (RFC 7208 §4.6.4)', domain: 'example.com', txtByName: SPF_OVERLIMIT_TXT, expectedScore: 75, expectedMissingControl: false },
];

// Real RSA public keys (SPKI base64 = DKIM p= value). Generated via
// `openssl genrsa N | openssl rsa -pubout -outform DER | base64`. PUBLIC keys only —
// needed so the bit-length classifier (RFC 8301: <1024 weak) sees a parseable key.
const DKIM_RSA_2048_P =
	'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArmqcx2roHY0AGFBJ6QQldlX0e5/BQVCL9nQKNgJqPgjhSlRVuBJmGCI4vEAe5qLkgKRbZ5WxS0F9LRI+tgDlKZvmmv/Bh7BhqN9ZpKFdsQIg4odgUa0tCFg/V9cPlzDDFFgox77fDFcKf2os+ORqBunHmhJPE6HODXD+lFF6RtTmQSyQXVZepREju5fmUd/xEkMhVYQVIKSK9YMM0D5cIkKzylpjMp9WKozrdkg9OnSE6TrtJB88hSAtKesFnU2kMzdd8+QhyP9dtSy9DQRUeUjFkPiyNdCXQf1SOxIzZZQ67SbPpEz4+RTllDgBgs2gsw9r9w6xyF665o+2K2YeZwIDAQAB';
const DKIM_RSA_1024_P =
	'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdshfa2y3h7g/BJPSw9NHhxi6teky3b+WGfl+NdW/MaV7WYWaDcvNiUQxCtD5JJnY2o023hoAZbaZdXlA/DVCS+0SnULqObqPHUd9oSd+1cNu3RVi7HiygsxC+yA/htkz46fNRSqDHFUB3M5CF4IFnA3ZuT/5SX6OkUngjGUs4lQIDAQAB';

export const DKIM_PARITY_FIXTURES: DkimParityFixture[] = [
	{ check: 'dkim', name: 'no record at selector (heuristic, not zeroed)', domain: 'example.com', selector: 'sel', txt: [], expectedScore: 50, expectedMissingControl: false },
	{ check: 'dkim', name: 'valid RSA-2048', domain: 'example.com', selector: 'sel', txt: [`v=DKIM1; k=rsa; p=${DKIM_RSA_2048_P}`], expectedScore: 100, expectedMissingControl: false },
	{ check: 'dkim', name: 'weak RSA-1024', domain: 'example.com', selector: 'sel', txt: [`v=DKIM1; k=rsa; p=${DKIM_RSA_1024_P}`], expectedScore: 75, expectedMissingControl: false },
	{ check: 'dkim', name: 'h=sha1 (RFC 8301 deprecated)', domain: 'example.com', selector: 'sel', txt: [`v=DKIM1; h=sha1; k=rsa; p=${DKIM_RSA_2048_P}`], expectedScore: 75, expectedMissingControl: false },
	{ check: 'dkim', name: 'revoked (empty p=)', domain: 'example.com', selector: 'sel', txt: ['v=DKIM1; k=rsa; p='], expectedScore: 85, expectedMissingControl: false },
];

export const BIMI_PARITY_FIXTURES: BimiParityFixture[] = [
	{ check: 'bimi', name: 'no BIMI, DMARC enforcing (advisory absence)', domain: 'example.com', bimi: [], dmarc: ['v=DMARC1; p=reject'], expectedScore: 95, expectedMissingControl: false },
	{ check: 'bimi', name: 'BIMI + DMARC enforcing (no logo fetch)', domain: 'example.com', bimi: ['v=BIMI1; l=https://x/logo.svg;'], dmarc: ['v=DMARC1; p=reject'], expectedScore: 95, expectedMissingControl: false },
	{ check: 'bimi', name: 'BIMI but DMARC p=none (ineffective)', domain: 'example.com', bimi: ['v=BIMI1; l=https://x/logo.svg;'], dmarc: ['v=DMARC1; p=none'], expectedScore: 0, expectedMissingControl: true },
	{ check: 'bimi', name: 'no BIMI, no DMARC', domain: 'example.com', bimi: [], dmarc: [], expectedScore: 95, expectedMissingControl: false },
];

export const MTA_STS_PARITY_FIXTURES: MtaStsParityFixture[] = [
	{ check: 'mta_sts', name: 'enforce mode + MX', domain: 'example.com', sts: ['v=STSv1; id=1'], tlsrpt: ['v=TLSRPTv1; rua=mailto:t@example.com'], mx: ['10 mail.example.com'], policy: 'version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800', expectedScore: 100, expectedMissingControl: false },
	{ check: 'mta_sts', name: 'testing mode + MX', domain: 'example.com', sts: ['v=STSv1; id=1'], tlsrpt: [], mx: ['10 mail.example.com'], policy: 'version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800', expectedScore: 90, expectedMissingControl: false },
	{ check: 'mta_sts', name: 'none mode + MX (disabled)', domain: 'example.com', sts: ['v=STSv1; id=1'], tlsrpt: [], mx: ['10 mail.example.com'], policy: 'version: STSv1\nmode: none\nmx: mail.example.com\nmax_age: 604800', expectedScore: 80, expectedMissingControl: false },
	{ check: 'mta_sts', name: 'no records, MX present (real gap)', domain: 'example.com', sts: [], tlsrpt: [], mx: ['10 mail.example.com'], policy: null, expectedScore: 0, expectedMissingControl: true },
	{ check: 'mta_sts', name: 'no records, no MX (parked, not applicable)', domain: 'example.com', sts: [], tlsrpt: [], mx: [], policy: null, expectedScore: 95, expectedMissingControl: false },
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
	{
		// Registry-managed (ccTLD seed-list path, no NS query): valid chain, but the
		// registry signed it → medium deduction → 85 (coherently above unsigned-60,
		// NOT the historic punitive 50 which would rank below no-DNSSEC).
		check: 'dnssec',
		name: 'registry-managed valid DNSSEC (.co.tz)',
		domain: 'example.co.tz',
		ad: true,
		dnskey: ['257 3 13 AwEAAabc'],
		ds: ['12345 13 2 abc123'],
		nsec3param: [],
		expectedScore: 85,
		expectedMissingControl: false,
	},
];

export const CAA_PARITY_FIXTURES: CaaParityFixture[] = [
	{
		check: 'caa',
		name: 'no CAA (defense-in-depth gap, not zeroed)',
		domain: 'example.com',
		caa: [],
		expectedScore: 85,
		expectedMissingControl: false,
	},
	{
		check: 'caa',
		name: 'issue only (missing issuewild + iodef)',
		domain: 'example.com',
		caa: ['0 issue "letsencrypt.org"'],
		expectedScore: 90,
		expectedMissingControl: false,
	},
	{
		check: 'caa',
		name: 'all tags (issue + issuewild + iodef)',
		domain: 'example.com',
		caa: ['0 issue "letsencrypt.org"', '0 issuewild "letsencrypt.org"', '0 iodef "mailto:sec@example.com"'],
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		check: 'caa',
		name: 'missing issuewild',
		domain: 'example.com',
		caa: ['0 issue "letsencrypt.org"', '0 iodef "mailto:sec@example.com"'],
		expectedScore: 95,
		expectedMissingControl: false,
	},
];

export const MX_PARITY_FIXTURES: MxParityFixture[] = [
	{
		check: 'mx',
		name: 'no MX + SPF -all (correct non-sender)',
		domain: 'example.com',
		mx: [],
		txt: ['v=spf1 -all'],
		hostA: {},
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		check: 'mx',
		name: 'no MX + SPF ~all (soft, should harden)',
		domain: 'example.com',
		mx: [],
		txt: ['v=spf1 ~all'],
		hostA: {},
		expectedScore: 85,
		expectedMissingControl: false,
	},
	{
		check: 'mx',
		name: 'no MX + no SPF (spoofable — real gap)',
		domain: 'example.com',
		mx: [],
		txt: [],
		hostA: {},
		expectedScore: 0,
		expectedMissingControl: true,
	},
	{
		check: 'mx',
		name: 'null MX (RFC 7505)',
		domain: 'example.com',
		mx: ['0 .'],
		txt: [],
		hostA: {},
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		check: 'mx',
		name: 'two MX (redundant)',
		domain: 'example.com',
		mx: ['10 mail1.example.com', '20 mail2.example.com'],
		txt: [],
		hostA: { 'mail1.example.com': ['10.0.0.1'], 'mail2.example.com': ['10.0.0.2'] },
		expectedScore: 100,
		expectedMissingControl: false,
	},
	{
		check: 'mx',
		name: 'single MX (no redundancy)',
		domain: 'example.com',
		mx: ['10 mail1.example.com'],
		txt: [],
		hostA: { 'mail1.example.com': ['10.0.0.1'] },
		expectedScore: 95,
		expectedMissingControl: false,
	},
];
