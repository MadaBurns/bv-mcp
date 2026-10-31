// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

/**
 * Pull the resource references out of an HTML page with a plain string tokenizer.
 *
 * No DOM and no HTMLRewriter, so it runs the same under Node tests and in a Worker. It reads
 * start tags only: tag and attribute names case-insensitively, attributes in any order, values
 * double-quoted, single-quoted or bare, with the common character references decoded. It skips
 * `<!-- -->` comments and the bodies of `<script>`, `<style>` and `<template>`, none of which
 * hold markup a browser would load from. `<base href>` is not applied: URLs resolve against
 * `baseUrl`.
 *
 * Every URL comes back absolute. The mixed-content sets (`scripts`, `stylesheets`, `passive`,
 * `active`, `forms`) keep only `http:` and `https:` URLs, because a `data:`, `javascript:` or
 * `blob:` value is not a network load. `anchors` drops only `javascript:`, `data:` and
 * `mailto:`.
 */

export interface HtmlRef {
	tag: string;
	attr: string;
	url: string;
}

export interface HtmlRefs {
	scripts: { src: string; integrity: string | null; crossorigin: string | null }[];
	stylesheets: { href: string; integrity: string | null; crossorigin: string | null }[];
	/** `img` / `video` / `audio` / `source` / `track` loads (mixed-content "passive"). */
	passive: HtmlRef[];
	/** `iframe` / `object` / `embed` loads (mixed-content "active"). */
	active: HtmlRef[];
	/** Form submit targets. A form with no or an empty `action` submits to `baseUrl`. */
	forms: { action: string }[];
	anchors: { href: string }[];
	/** `content` of every `<meta http-equiv="Content-Security-Policy">`. */
	metaCsp: string[];
}

interface StartTag {
	name: string;
	/** Lower-cased attribute name → decoded value (`''` for a bare attribute). First one wins. */
	attrs: Map<string, string>;
}

type Collector = (tag: StartTag, baseUrl: string, refs: HtmlRefs) => void;

/** Extract the script, stylesheet, media, frame, form, link and meta-CSP references of `html`. */
export function extractHtmlRefs(html: string, baseUrl: string): HtmlRefs {
	const refs: HtmlRefs = { scripts: [], stylesheets: [], passive: [], active: [], forms: [], anchors: [], metaCsp: [] };
	for (let step = readNext(html, 0); step !== null; step = readNext(html, step.next)) {
		if (step.tag) COLLECTORS.get(step.tag.name)?.(step.tag, baseUrl, refs);
	}
	return refs;
}

// ── Tokenizer ────────────────────────────────────────────────────────────────

/** `<` followed by a letter opens a start tag; anything else (`</`, `<!`, `< `) does not. */
const START_TAG = /<([a-zA-Z][^\s/>]*)/y;

/** One attribute: a name, then optionally `=` and a double-quoted, single-quoted or bare value. */
const ATTRIBUTE = /([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/y;

/** Elements whose content is not markup. Each maps to the pattern that finds its end tag. */
const RAW_TEXT_END = new Map(['script', 'style', 'template'].map((name) => [name, new RegExp(`</${name}[\\s/>]`, 'gi')]));

interface Step {
	tag?: StartTag;
	next: number;
}

/** The next start tag at or after `from` (or a skipped comment / non-tag `<`), or `null` at the end. */
function readNext(html: string, from: number): Step | null {
	const lt = html.indexOf('<', from);
	if (lt < 0) return null;
	// From `lt + 2`, so the abrupt empty comments `<!-->` and `<!--->` close where a browser closes them.
	if (html.startsWith('<!--', lt)) return { next: indexAfter(html, '-->', lt + 2) };
	return readStartTag(html, lt) ?? { next: lt + 1 };
}

function readStartTag(html: string, lt: number): Step | null {
	START_TAG.lastIndex = lt;
	const match = START_TAG.exec(html);
	if (!match) return null;
	const name = match[1].toLowerCase();
	const { attrs, end } = readAttributes(html, START_TAG.lastIndex);
	const rawTextEnd = RAW_TEXT_END.get(name);
	return { tag: { name, attrs }, next: rawTextEnd ? indexOfPattern(html, rawTextEnd, end) : end };
}

/** Parse attributes from `from` up to the closing `>`; `end` is the index just past it. */
function readAttributes(html: string, from: number): { attrs: Map<string, string>; end: number } {
	const attrs = new Map<string, string>();
	let i = from;
	while (i < html.length && html[i] !== '>') {
		ATTRIBUTE.lastIndex = i;
		const match = ATTRIBUTE.exec(html);
		// Whitespace, the self-closing `/` and stray quotes or `=` match nothing: step over them.
		if (!match) {
			i++;
			continue;
		}
		setFirstAttribute(attrs, match);
		i = ATTRIBUTE.lastIndex;
	}
	return { attrs, end: Math.min(i + 1, html.length) };
}

function setFirstAttribute(attrs: Map<string, string>, match: RegExpExecArray): void {
	const name = match[1].toLowerCase();
	if (!attrs.has(name)) attrs.set(name, decodeCharacterReferences(match[2] ?? match[3] ?? match[4] ?? ''));
}

function indexAfter(html: string, needle: string, from: number): number {
	const at = html.indexOf(needle, from);
	return at < 0 ? html.length : at + needle.length;
}

function indexOfPattern(html: string, pattern: RegExp, from: number): number {
	pattern.lastIndex = from;
	return pattern.exec(html)?.index ?? html.length;
}

const NAMED_REFERENCES = new Map([
	['amp', '&'],
	['quot', '"'],
	['apos', "'"],
	['lt', '<'],
	['gt', '>'],
]);
const CHARACTER_REFERENCE = /&(?:#(\d+)|#[xX]([0-9a-fA-F]+)|(amp|quot|apos|lt|gt));/g;

function decodeCharacterReferences(value: string): string {
	return value.includes('&') ? value.replace(CHARACTER_REFERENCE, decodeCharacterReference) : value;
}

function decodeCharacterReference(match: string, decimal: string | undefined, hex: string | undefined, named: string | undefined): string {
	if (named) return NAMED_REFERENCES.get(named) ?? match;
	const codePoint = decimal ? Number.parseInt(decimal, 10) : Number.parseInt(hex ?? '', 16);
	return codePoint > 0 && codePoint <= 0x10ffff ? String.fromCodePoint(codePoint) : match;
}

// ── Collectors ───────────────────────────────────────────────────────────────

/** Absolute `http:`/`https:` URL for an attribute value, or `null` (absent, empty, unparseable, other scheme). */
function networkUrl(raw: string | undefined, baseUrl: string): string | null {
	const trimmed = raw?.trim();
	if (!trimmed) return null;
	const url = URL.parse(trimmed, baseUrl);
	return url?.protocol === 'http:' || url?.protocol === 'https:' ? url.href : null;
}

function collectScript(tag: StartTag, baseUrl: string, refs: HtmlRefs): void {
	const src = networkUrl(tag.attrs.get('src'), baseUrl);
	if (src) refs.scripts.push({ src, integrity: tag.attrs.get('integrity') ?? null, crossorigin: tag.attrs.get('crossorigin') ?? null });
}

function collectStylesheet(tag: StartTag, baseUrl: string, refs: HtmlRefs): void {
	const rel = (tag.attrs.get('rel') ?? '').toLowerCase().split(/\s+/);
	const href = networkUrl(tag.attrs.get('href'), baseUrl);
	if (href && rel.includes('stylesheet')) {
		refs.stylesheets.push({ href, integrity: tag.attrs.get('integrity') ?? null, crossorigin: tag.attrs.get('crossorigin') ?? null });
	}
}

/** Collects every network URL in `attrNames` into the `passive` or `active` list. */
function refCollector(list: 'passive' | 'active', attrNames: readonly string[]): Collector {
	return (tag, baseUrl, refs) => {
		for (const attr of attrNames) {
			for (const raw of attributeUrls(tag, attr)) {
				const url = networkUrl(raw, baseUrl);
				if (url) refs[list].push({ tag: tag.name, attr, url });
			}
		}
	};
}

function attributeUrls(tag: StartTag, attr: string): string[] {
	const value = tag.attrs.get(attr);
	if (value === undefined) return [];
	return attr === 'srcset' ? parseSrcset(value) : [value];
}

/**
 * The candidate URLs of a `srcset`. A URL is a run of non-whitespace, so a comma inside it
 * (`/w_400,c_fill/a.jpg 400w`) stays; a comma straight after it ends a descriptor-less candidate.
 */
function parseSrcset(value: string): string[] {
	const urls: string[] = [];
	const candidate = /[\s,]*(\S+)/g;
	for (let match = candidate.exec(value); match !== null; match = candidate.exec(value)) {
		urls.push(match[1].replace(/,+$/, ''));
		if (!match[1].endsWith(',')) candidate.lastIndex = indexAfter(value, ',', candidate.lastIndex);
	}
	return urls;
}

function collectForm(tag: StartTag, baseUrl: string, refs: HtmlRefs): void {
	const raw = tag.attrs.get('action')?.trim();
	const action = networkUrl(raw || baseUrl, baseUrl);
	if (action) refs.forms.push({ action });
}

const ANCHOR_DROPPED_SCHEMES = new Set(['javascript:', 'data:', 'mailto:']);

function collectAnchor(tag: StartTag, baseUrl: string, refs: HtmlRefs): void {
	const raw = tag.attrs.get('href')?.trim();
	const url = raw ? URL.parse(raw, baseUrl) : null;
	if (url && !ANCHOR_DROPPED_SCHEMES.has(url.protocol)) refs.anchors.push({ href: url.href });
}

function collectMetaCsp(tag: StartTag, _baseUrl: string, refs: HtmlRefs): void {
	const content = tag.attrs.get('content');
	if (content !== undefined && tag.attrs.get('http-equiv')?.trim().toLowerCase() === 'content-security-policy') refs.metaCsp.push(content);
}

/** Tag name → collector. A `Map`, so a tag named like an `Object.prototype` key finds nothing. */
const COLLECTORS = new Map<string, Collector>([
	['script', collectScript],
	['link', collectStylesheet],
	['img', refCollector('passive', ['src', 'srcset'])],
	['video', refCollector('passive', ['src', 'poster'])],
	['audio', refCollector('passive', ['src'])],
	['source', refCollector('passive', ['src', 'srcset'])],
	['track', refCollector('passive', ['src'])],
	['iframe', refCollector('active', ['src'])],
	['object', refCollector('active', ['data'])],
	['embed', refCollector('active', ['src'])],
	['form', collectForm],
	['a', collectAnchor],
	['meta', collectMetaCsp],
]);
