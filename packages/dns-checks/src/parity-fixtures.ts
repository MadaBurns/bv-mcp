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
	 * True when only bv-web can produce this via RFC 9989 tree-walk inheritance.
	 * bv-mcp's checkDMARC reads `_dmarc.<domain>` directly (no tree-walk) so it
	 * diverges here — a documented bounded-non-parity until bv-mcp gains tree-walk.
	 * The bv-mcp contract test skips these; the bv-web tree-walk test asserts them.
	 */
	treeWalkOnly?: boolean;
	/** Wrapper-only async finding bv-web can't compute (e.g. third-party RUA-auth), documented. */
	asyncDelta?: { finding: string; points: number };
}

/** Must equal the package version (asserted by both repos' version-lock). */
export const PARITY_CORPUS_VERSION = '1.3.1';

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
		// Tree-walk divergence — see the design's Decision Point. bv-web inherits the
		// parent's sp; bv-mcp reads _dmarc.blog.example.com directly (no record) -> 0.
		check: 'dmarc',
		name: 'subdomain inherits parent p=reject (tree-walk)',
		query: '_dmarc.blog.example.com',
		records: {
			'_dmarc.blog.example.com': [],
			'_dmarc.example.com': ['v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com'],
		},
		expectedScore: 80,
		expectedMissingControl: false,
		treeWalkOnly: true,
	},
];
