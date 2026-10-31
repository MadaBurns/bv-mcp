// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { extractHtmlRefs } from '../../checks/html-refs';

const BASE = 'https://example.com/shop/index.html';

describe('extractHtmlRefs', () => {
	it('collects scripts with src, integrity and crossorigin, in any attribute order and quote style', () => {
		const refs = extractHtmlRefs(
			`<script src="/app.js" integrity="sha384-abc" crossorigin="anonymous"></script>
			 <SCRIPT CrossOrigin integrity='sha256-def' SRC='https://cdn.example.net/lib.js'></SCRIPT>
			 <script src=vendor.js></script>
			 <script>inline()</script>`,
			BASE,
		);
		expect(refs.scripts).toEqual([
			{ src: 'https://example.com/app.js', integrity: 'sha384-abc', crossorigin: 'anonymous' },
			{ src: 'https://cdn.example.net/lib.js', integrity: 'sha256-def', crossorigin: '' },
			{ src: 'https://example.com/shop/vendor.js', integrity: null, crossorigin: null },
		]);
	});

	it('collects only rel=stylesheet links (including alternate stylesheet)', () => {
		const refs = extractHtmlRefs(
			`<link rel="stylesheet" href="/site.css" integrity="sha384-x" crossorigin="use-credentials">
			 <link href="alt.css" rel="Alternate Stylesheet">
			 <link rel="preload" href="/font.woff2" as="font">
			 <link rel="icon" href="/favicon.ico">`,
			BASE,
		);
		expect(refs.stylesheets).toEqual([
			{ href: 'https://example.com/site.css', integrity: 'sha384-x', crossorigin: 'use-credentials' },
			{ href: 'https://example.com/shop/alt.css', integrity: null, crossorigin: null },
		]);
	});

	it('collects passive media refs (img/video/audio/source/track), including every srcset candidate and the video poster', () => {
		const refs = extractHtmlRefs(
			`<img src="http://example.com/a.png" srcset="/w_400,c_fill/b.jpg 400w, c.jpg 2x,d.jpg">
			 <video src="clip.mp4" poster="http://cdn.example.net/poster.jpg"></video>
			 <audio src="https://example.com/s.mp3"></audio>
			 <picture><source srcset="/e.webp" type="image/webp"></picture>
			 <track src="captions.vtt">`,
			BASE,
		);
		expect(refs.passive).toEqual([
			{ tag: 'img', attr: 'src', url: 'http://example.com/a.png' },
			{ tag: 'img', attr: 'srcset', url: 'https://example.com/w_400,c_fill/b.jpg' },
			{ tag: 'img', attr: 'srcset', url: 'https://example.com/shop/c.jpg' },
			{ tag: 'img', attr: 'srcset', url: 'https://example.com/shop/d.jpg' },
			{ tag: 'video', attr: 'src', url: 'https://example.com/shop/clip.mp4' },
			{ tag: 'video', attr: 'poster', url: 'http://cdn.example.net/poster.jpg' },
			{ tag: 'audio', attr: 'src', url: 'https://example.com/s.mp3' },
			{ tag: 'source', attr: 'srcset', url: 'https://example.com/e.webp' },
			{ tag: 'track', attr: 'src', url: 'https://example.com/shop/captions.vtt' },
		]);
		expect(refs.active).toEqual([]);
	});

	it('collects active refs from iframe src, object data and embed src', () => {
		const refs = extractHtmlRefs(
			`<iframe src="http://widgets.example.org/w"></iframe><object data="/flash.swf"></object><embed src="movie.swf">`,
			BASE,
		);
		expect(refs.active).toEqual([
			{ tag: 'iframe', attr: 'src', url: 'http://widgets.example.org/w' },
			{ tag: 'object', attr: 'data', url: 'https://example.com/flash.swf' },
			{ tag: 'embed', attr: 'src', url: 'https://example.com/shop/movie.swf' },
		]);
	});

	it('keeps data:, javascript: and blob: URLs out of the mixed-content sets', () => {
		const refs = extractHtmlRefs(
			`<img src="data:image/png;base64,AAAA"><script src="javascript:alert(1)"></script>
			 <iframe src="blob:https://example.com/uuid"></iframe><img src="  "><img>
			 <form action="javascript:void(0)"></form>`,
			BASE,
		);
		expect(refs.passive).toEqual([]);
		expect(refs.scripts).toEqual([]);
		expect(refs.active).toEqual([]);
		expect(refs.forms).toEqual([]);
	});

	it('resolves form actions, sending a missing or empty action to the base URL', () => {
		const refs = extractHtmlRefs(`<form action="http://example.com/login"></form><form action="search"></form><form></form><form action="">`, BASE);
		expect(refs.forms).toEqual([
			{ action: 'http://example.com/login' },
			{ action: 'https://example.com/shop/search' },
			{ action: BASE },
			{ action: BASE },
		]);
	});

	it('resolves anchors and drops javascript:, data: and mailto: hrefs', () => {
		const refs = extractHtmlRefs(
			`<a href="../about">About</a><a href="#top">Top</a><a href="http://old.example.com/">Old</a>
			 <a href="JavaScript:void(0)">x</a><a href="mailto:hi@example.com">mail</a><a href="data:text/html,hi">d</a>
			 <a href="tel:+6421000000">call</a><a name="anchor-without-href">n</a>`,
			BASE,
		);
		expect(refs.anchors).toEqual([
			{ href: 'https://example.com/about' },
			{ href: 'https://example.com/shop/index.html#top' },
			{ href: 'http://old.example.com/' },
			{ href: 'tel:+6421000000' },
		]);
	});

	it('collects the content of every meta Content-Security-Policy, and nothing from Report-Only or other metas', () => {
		const refs = extractHtmlRefs(
			`<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https:">
			 <META CONTENT="upgrade-insecure-requests" HTTP-EQUIV=content-security-policy>
			 <meta http-equiv="Content-Security-Policy-Report-Only" content="script-src 'none'">
			 <meta name="description" content="shop">`,
			BASE,
		);
		expect(refs.metaCsp).toEqual(["default-src 'self'; img-src https:", 'upgrade-insecure-requests']);
	});

	it('skips comments, script bodies, style bodies and template content', () => {
		const refs = extractHtmlRefs(
			`<!-- <img src="/commented.png"> -->
			 <!--><img src="/after-abrupt-comment.png">
			 <script>document.write('<img src="/from-script.png">')</script>
			 <style>.x::after { content: '<img src="/from-style.png">' }</style>
			 <template><img src="/from-template.png"></template>
			 <img src="/real.png">`,
			BASE,
		);
		expect(refs.passive.map((ref) => ref.url)).toEqual(['https://example.com/after-abrupt-comment.png', 'https://example.com/real.png']);
	});

	it('decodes character references in attribute values', () => {
		const refs = extractHtmlRefs(`<img src="/i.png?a=1&amp;b=2&#38;c=&#x33;"><meta http-equiv="Content-Security-Policy" content="script-src &apos;self&apos; &quot;x&quot; &bogus; &#0;">`, BASE);
		expect(refs.passive[0].url).toBe('https://example.com/i.png?a=1&b=2&c=3');
		expect(refs.metaCsp).toEqual([`script-src 'self' "x" &bogus; &#0;`]);
	});

	it('keeps the first of a repeated attribute and tolerates malformed markup', () => {
		const refs = extractHtmlRefs(
			`<img src="/first.png" src="/second.png"/><img src = "/spaced.png" alt=x><img src="/q.png" title='a>b'>
			 a < b and <3 <img src="/last.png"`,
			BASE,
		);
		expect(refs.passive.map((ref) => ref.url)).toEqual([
			'https://example.com/first.png',
			'https://example.com/spaced.png',
			'https://example.com/q.png',
			'https://example.com/last.png',
		]);
	});

	it('finds nothing in empty or tag-free input, and ignores tags named like Object.prototype keys', () => {
		expect(extractHtmlRefs('', BASE)).toEqual({ scripts: [], stylesheets: [], passive: [], active: [], forms: [], anchors: [], metaCsp: [] });
		expect(extractHtmlRefs('<constructor src="/x.png"><unclosed', BASE).passive).toEqual([]);
	});
});
