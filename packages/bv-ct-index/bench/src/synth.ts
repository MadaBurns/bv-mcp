// SPDX-License-Identifier: BUSL-1.1
/**
 * Synthetic NameObservations for the bv-ct-index benchmark (SQ-352). Deterministic: universe row `i` always
 * yields the same name and apex for a given seed, so a seeded bucket and a later query pick agree.
 *
 * Shapes follow the measured skew (story log #9-#11): ~12% of rows under one hot apex (amazonaws.com-style
 * ELB/EC2 names), ~7% under per-tenant `*.workers.dev` apexes (private-suffix children are their own apex),
 * the rest over a power-law of ordinary apexes across common TLDs and multi-label public suffixes.
 */

import { nameKey } from '../../src/codec';
import type { NameObservation } from '../../src/types';

const WORDS = [
	'acme',
	'blue',
	'cloud',
	'data',
	'edge',
	'fast',
	'green',
	'harbor',
	'iron',
	'jade',
	'kite',
	'lumen',
	'metro',
	'nova',
	'orbit',
	'pixel',
	'quartz',
	'river',
	'solar',
	'tidal',
	'ultra',
	'vector',
	'wave',
	'xeno',
	'yonder',
	'zen',
	'alpha',
	'bright',
	'coast',
	'delta',
	'ember',
	'forge',
	'globe',
	'height',
	'insight',
	'joint',
	'kiwi',
	'lattice',
	'maple',
	'north',
	'ocean',
	'peak',
	'quest',
	'rapid',
	'stone',
	'trust',
	'union',
	'vista',
	'west',
	'yield',
	'zone',
	'apex',
	'bridge',
	'cedar',
	'dawn',
	'echo',
	'falcon',
	'grid',
	'hive',
	'ionic',
	'jet',
	'karma',
	'lunar',
	'mesa',
];
const TLDS = [
	'com',
	'com',
	'com',
	'com',
	'net',
	'org',
	'io',
	'co.uk',
	'com.au',
	'de',
	'nz',
	'govt.nz',
	'co.nz',
	'dev',
	'app',
	'fr',
	'jp',
	'ca',
	'org.nz',
	'gov.au',
];
const SUBS = [
	'www',
	'mail',
	'api',
	'cdn',
	'dev',
	'staging',
	'vpn',
	'autodiscover',
	'portal',
	'app',
	'admin',
	'login',
	'shop',
	'blog',
	'test',
	'sso',
	'mx1',
	'smtp',
	'webmail',
	'remote',
	'status',
	'docs',
	'git',
	'grafana',
	'auth',
	'm',
	'static',
	'img',
	'assets',
	'beta',
	'uat',
	'internal',
];
const REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-2', 'ap-northeast-1', 'sa-east-1', 'ca-central-1'];
const ISSUERS = [
	"Let's Encrypt R10",
	"Let's Encrypt R11",
	"Let's Encrypt E5",
	"Let's Encrypt E6",
	'Google Trust Services WR1',
	'Google Trust Services WE1',
	'Sectigo RSA Domain Validation Secure Server CA',
	'DigiCert Global G2 TLS RSA SHA256 2020 CA1',
	'Amazon RSA 2048 M02',
	'ZeroSSL RSA Domain Secure Site CA',
];
/** Ordinary apexes in the power-law tail. */
const APEXES = 120_000;
const DAY = 86_400;

/** mulberry32: small, fast, deterministic. Not for anything but synthetic data. */
export function rng(seed: number): () => number {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
	};
}

function pick<T>(r: () => number, list: readonly T[]): T {
	return list[Math.floor(r() * list.length)]!;
}

function hex(r: () => number, digits: number): string {
	let out = '';
	for (let i = 0; i < digits; i++) out += '0123456789abcdef'[Math.floor(r() * 16)];
	return out;
}

/** Ordinary apex `j` of the tail, e.g. `harborquartz12.co.nz`. */
export function ordinaryApex(j: number): string {
	const w = WORDS.length;
	const label = `${WORDS[j % w]}${j >= w ? WORDS[Math.floor(j / w) % w] : ''}${j >= w * w ? String(Math.floor(j / (w * w))) : ''}`;
	return `${label}.${TLDS[j % TLDS.length]}`;
}

/** Universe row `i`: the certificate name (wildcards as `*.x`) and its apex. */
export function universeName(i: number, seed: number): { name: string; apex: string } {
	const r = rng(Math.imul(i, 0x9e3779b1) ^ seed);
	const u = r();
	if (u < 0.12) {
		const ip = `${Math.floor(r() * 256)}-${Math.floor(r() * 256)}-${Math.floor(r() * 256)}-${Math.floor(r() * 256)}`;
		const region = pick(r, REGIONS);
		const name = r() < 0.5 ? `ec2-${ip}.${region}.compute.amazonaws.com` : `${pick(r, WORDS)}-${hex(r, 10)}.${region}.elb.amazonaws.com`;
		return { name, apex: 'amazonaws.com' };
	}
	if (u < 0.19) {
		const apex = `${pick(r, WORDS)}-${hex(r, 6)}.workers.dev`;
		return { name: r() < 0.6 ? apex : `${pick(r, SUBS)}.${apex}`, apex };
	}
	// Power law over the tail: low j (and so a few apexes) gets most rows.
	const apex = ordinaryApex(Math.floor(APEXES * r() ** 2.5));
	const shape = r();
	let host: string;
	if (shape < 0.15) host = apex;
	else if (shape < 0.5) host = `${pick(r, SUBS)}.${apex}`;
	else if (shape < 0.65) host = `${pick(r, SUBS)}.${pick(r, SUBS)}.${apex}`;
	else if (shape < 0.85) host = `${hex(r, 8)}.${apex}`;
	else host = `k8s-${pick(r, WORDS)}-${hex(r, 10)}.${pick(r, REGIONS)}.${apex}`;
	return { name: r() < 0.08 ? `*.${host}` : host, apex };
}

/**
 * The rows of run `run` of `runs`: about rows/runs observations, mostly a disjoint stride of the universe so every
 * run spans the whole keyspace (as tiered runs do), plus ~10% drawn from other runs' strides so a merge folds keys.
 */
export function runObservations(run: number, runs: number, rows: number, seed: number, now: number): NameObservation[] {
	const r = rng(seed ^ ((run + 1) * 0x85ebca6b));
	const perRun = Math.ceil(rows / runs);
	const out: NameObservation[] = [];
	for (let k = 0; k < perRun; k++) {
		const i = r() < 0.1 ? Math.floor(r() * rows) : k * runs + run;
		const { name, apex } = universeName(i, seed);
		const key = nameKey(name);
		const firstSeen = now - Math.floor(r() * 90 * DAY);
		const notAfter = r() < 0.03 ? now - Math.floor(r() * 30 * DAY) - 1 : firstSeen + (r() < 0.7 ? 90 : 397) * DAY;
		out.push({ key: key.key, name: key.name, apex, firstSeen, notAfter, issuer: pick(r, ISSUERS), wildcard: key.wildcard });
	}
	return out;
}

/** A query domain: mostly the apex of a random universe row (row-weighted, so hot apexes recur), some uniform-random apexes (mostly absent), some public suffixes. */
export function queryDomain(r: () => number, rows: number, seed: number): { domain: string; kind: 'apex' | 'cold' | 'suffix' } {
	const u = r();
	if (u < 0.8) return { domain: universeName(Math.floor(r() * rows), seed).apex, kind: 'apex' };
	if (u < 0.9) return { domain: ordinaryApex(Math.floor(r() * APEXES * 4)), kind: 'cold' };
	return { domain: pick(r, ['govt.nz', 'co.nz', 'co.uk', 'com.au', 'gov.au', 'org.nz']), kind: 'suffix' };
}
