#!/usr/bin/env bash
# ema-approve.sh <list|show|approve|reject> ... | --self-test
#
# Operator helper for reviewing Enterprise Managed Auth (EMA) tenants that wait for approval. It does
# the LOCAL analysis an approval needs and builds the exact request; it does not send anything.
#
#   list    [--approval pending|approved|rejected] [--from-file <json|->]
#   show    <tenant_id> [--from-file <json|->] [--list-from-file <json|->] [--jwks-from-file <json>] [--no-jwks]
#   approve <tenant_id> --from-file <json|-> [--list-from-file <json|->] [--jwks-from-file <json>] [--no-jwks] --yes
#   reject  <tenant_id> --yes [--from-file <json|->]
#   --self-test   inline fixtures, no network, exit 0 (CI-safe)
#
# WHY IT DOES NOT SEND (checked against docs/operator-runbook.md section 8a): the operator routes
# (/internal/oauth/ema-tenants*) are reachable only over a Cloudflare service binding, because the internal
# guard answers 404 to any request that carries cf-connecting-ip. The runbook documents no non-interactive
# way to call them, so this script prints the request (method, path, body) for the channel the operator
# already uses, and analyses the GET response pasted or saved from that channel (--from-file).
#
# Typical review:
#   1. ema-approve.sh list --approval pending                   prints the GET request; run it, save the reply
#   2. ema-approve.sh list --approval pending --from-file r.json   the queue
#   3. ema-approve.sh show <id>                                 prints the GET request; run it, save the reply
#   4. ema-approve.sh show <id> --from-file rec.json --list-from-file all.json    the review report
#   5. ema-approve.sh approve <id> --from-file rec.json --yes   prints the approve request with the CAS body
#
# CAS body: {issuer, jwks_uri, rev} from the record just shown; a record with no `rev` (before the registry
# revision shipped) falls back to {issuer, jwks_uri, updated_at}, and the output says so.
#
# The bearer (BV_MCP_EMA_ADMIN_KEY) is never read here: it is unset on entry so no child process can see it,
# and the printed request names the variable instead of its value. Supply it in the sending channel.
#
# The only network call is the optional live JWKS fetch in `show` / `approve`: https only, no redirects,
# 15s and 1 MiB caps, and a client-side refusal of IP literals and internal hostnames.
#
# Style follows scripts/verify-ema.sh: bash 3.2 / BSD tools, node for JSON (no jq), curl --max-time.

set -euo pipefail
unset BV_MCP_EMA_ADMIN_KEY

usage() {
	cat >&2 <<'USAGE'
usage: ema-approve.sh list [--approval pending|approved|rejected] [--from-file <json|->]
       ema-approve.sh show <tenant_id> [--from-file <json|->] [--list-from-file <json|->] [--jwks-from-file <json>] [--no-jwks]
       ema-approve.sh approve <tenant_id> --from-file <json|-> [--list-from-file <json|->] [--jwks-from-file <json>] [--no-jwks] --yes
       ema-approve.sh reject <tenant_id> --yes [--from-file <json|->]
       ema-approve.sh --self-test
USAGE
	exit 2
}
die() { echo "error: $*" >&2; exit 2; }

# --- the analysis program (node reads it from stdin, so all data travels in files) ---------------
# Modes: selftest | jwks-url <rec> | report <cmd> <id> <rec> <jwksStatus> <jwksFile|-> <listFile|->
#        | request <list|show|approve|reject> <id|-> <rec|-> <approval|->  | list-table <file> <approval|->
ema_node() {
	node - "$@" <<'JS'
'use strict';
const fs = require('fs');
const crypto = require('crypto');
const nurl = require('url');

const TENANT_ID = /^[a-z0-9][a-z0-9-]{2,47}$/;
// C0, DEL, C1, Arabic letter mark, zero-width and direction marks, line/paragraph separators, every bidi
// embedding/override/isolate control, word joiner and friends, BOM. Printed text never carries these.
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g;
const MULTI_LABEL_SUFFIXES = new Set([
	'co.nz', 'org.nz', 'net.nz', 'govt.nz', 'ac.nz',
	'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
	'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
]);
const VENDORS = [
	['okta.com', 'Okta'],
	['oktapreview.com', 'Okta (preview)'],
	['auth0.com', 'Auth0'],
	['onelogin.com', 'OneLogin'],
	['pingone.com', 'PingOne'],
];
const ENTRA_HOSTS = ['login.microsoftonline.com', 'sts.windows.net'];
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const INTERNAL_SUFFIXES = ['.local', '.localhost', '.internal', '.lan', '.corp', '.home', '.intranet', '.test', '.invalid', '.example'];

const strip = (s) => String(s).replace(CONTROL, '');
const removedCount = (s) => String(s).length - strip(s).length;
const clip = (s, n) => (s.length > n ? s.slice(0, n) + '...' : s);
/** Safe to print: control/bidi stripped, bounded. */
const safe = (s, n = 200) => clip(strip(s), n);

function regDomain(host) {
	const labels = host.toLowerCase().replace(/\.$/, '').split('.');
	if (labels.length <= 2) return labels.join('.');
	const two = labels.slice(-2).join('.');
	return MULTI_LABEL_SUFFIXES.has(two) ? labels.slice(-3).join('.') : two;
}
const hostIs = (host, domain) => host === domain || host.endsWith('.' + domain);

function vendorOf(issuer) {
	const u = new nurl.URL(issuer);
	const host = u.hostname.toLowerCase();
	for (const [domain, name] of VENDORS) {
		if (hostIs(host, domain)) return { kind: 'vendor', name, label: host.slice(0, Math.max(0, host.length - domain.length - 1)) };
	}
	if (ENTRA_HOSTS.indexOf(host) !== -1) {
		const first = u.pathname.split('/').filter(Boolean)[0] || '';
		return GUID.test(first) ? { kind: 'entra', guid: first.toLowerCase() } : { kind: 'entra-shared', segment: first };
	}
	return { kind: 'unknown' };
}

function hasIdn(host) {
	return /(^|\.)xn--/i.test(host) || /[^\u0000-\u007f]/.test(host);
}
function unicodeHost(host) {
	try { return nurl.domainToUnicode(host); } catch (e) { return host; }
}

/** Mirror of src/oauth/ema-tenants.ts normalizeIssuer: origin plus path without trailing slashes. */
function normalizeIssuer(iss) {
	const u = new nurl.URL(iss);
	return u.origin + u.pathname.replace(/\/+$/, '');
}

const THUMBPRINT_MEMBERS = { RSA: ['e', 'kty', 'n'], EC: ['crv', 'kty', 'x', 'y'], OKP: ['crv', 'kty', 'x'], oct: ['k', 'kty'] };
/** RFC 7638: SHA-256 over the required members, lexicographic order, no whitespace; base64url. */
function thumbprint(jwk) {
	const members = THUMBPRINT_MEMBERS[jwk && jwk.kty];
	if (!members) throw new Error('unsupported kty');
	const o = {};
	for (const m of members) {
		if (typeof jwk[m] !== 'string' || jwk[m] === '') throw new Error('missing ' + m);
		o[m] = jwk[m];
	}
	return crypto.createHash('sha256').update(JSON.stringify(o)).digest('base64url');
}

function isoOf(n) {
	if (typeof n !== 'number' || !Number.isFinite(n)) return null;
	const ms = n > 1e11 ? n : n * 1000;
	const d = new Date(ms);
	return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

const effectiveApproval = (rec) => rec.approval || (rec.source === 'self-serve' ? 'pending' : 'approved');

/** A JWKS is only fetched from a public-looking https host: the operator's machine may sit on an internal network. */
function jwksFetchVerdict(uri) {
	let u;
	try { u = new nurl.URL(uri); } catch (e) { return { ok: false, reason: 'not a URL' }; }
	if (u.protocol !== 'https:') return { ok: false, reason: 'not https' };
	if (u.username || u.password) return { ok: false, reason: 'has userinfo' };
	const host = u.hostname.toLowerCase();
	if (host.indexOf('[') === 0 || /^[0-9.]+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) return { ok: false, reason: 'IP literal host' };
	if (host.indexOf('.') === -1) return { ok: false, reason: 'single-label host' };
	if (INTERNAL_SUFFIXES.some((s) => host.endsWith(s)) || host === 'localhost') return { ok: false, reason: 'internal hostname' };
	return { ok: true, url: u.href };
}

function fail(msg) { process.stderr.write('error: ' + msg + '\n'); process.exit(2); }

function readJson(file, what) {
	let text;
	try { text = fs.readFileSync(file, 'utf8'); } catch (e) { fail('cannot read ' + what); }
	try { return JSON.parse(text); } catch (e) { return fail(what + ' is not valid JSON'); }
}

function loadRecord(file, tenantId) {
	const rec = readJson(file, 'the tenant record');
	if (!rec || typeof rec !== 'object' || Array.isArray(rec)) return fail('the tenant record must be one JSON object');
	if (Array.isArray(rec.tenants)) return fail('that is a list response; save the GET for a single tenant');
	if (typeof rec.tenant_id !== 'string') return fail('the record has no tenant_id');
	if (tenantId && rec.tenant_id !== tenantId) return fail('the record is for a different tenant than ' + safe(tenantId, 60));
	if (typeof rec.issuer !== 'string' || typeof rec.jwks_uri !== 'string') return fail('the record lacks issuer or jwks_uri');
	return rec;
}

function loadList(file) {
	const body = readJson(file, 'the list response');
	const tenants = Array.isArray(body) ? body : body && body.tenants;
	if (!Array.isArray(tenants)) return fail('the list response has no tenants array');
	return { tenants: tenants.filter((t) => t && typeof t === 'object'), total: body && typeof body.total === 'number' ? body.total : null };
}

/** The CAS body for the approve route, built from the record exactly as stored. */
function casBody(rec) {
	if (Number.isInteger(rec.rev) && rec.rev >= 0) return { shape: 'rev', body: { issuer: rec.issuer, jwks_uri: rec.jwks_uri, rev: rec.rev } };
	if (Number.isInteger(rec.updated_at)) return { shape: 'updated_at', body: { issuer: rec.issuer, jwks_uri: rec.jwks_uri, updated_at: rec.updated_at } };
	return fail('the record has neither rev nor an integer updated_at');
}

function requestBlock(method, path, body, notes) {
	const out = [
		'REQUEST (not sent: the operator routes are reachable only over the service binding; send it through your existing channel)',
		'  ' + method + ' ' + path,
		'  Authorization: Bearer $BV_MCP_EMA_ADMIN_KEY   (the variable name, not its value; supply it in the sending channel)',
	];
	if (body !== undefined) {
		out.push('  Content-Type: application/json');
		out.push('  Body: ' + JSON.stringify(body));
	}
	for (const n of notes || []) out.push('  NOTE: ' + n);
	return out;
}

function checkId(id) {
	if (!TENANT_ID.test(id || '')) fail('tenant_id must match ' + TENANT_ID.source);
	return id;
}

function modeRequest(action, id, recFile, approval) {
	const lines = [];
	if (action === 'list') {
		const q = approval && approval !== '-' ? '?approval=' + approval : '';
		lines.push(...requestBlock('GET', '/internal/oauth/ema-tenants' + q));
	} else if (action === 'show') {
		lines.push(...requestBlock('GET', '/internal/oauth/ema-tenants/' + checkId(id)));
	} else if (action === 'approve') {
		const rec = loadRecord(recFile, checkId(id));
		const cas = casBody(rec);
		const notes = cas.shape === 'updated_at' ? ['the record has no rev, so the CAS body falls back to updated_at (registry revision not deployed yet)'] : [];
		lines.push(...requestBlock('POST', '/internal/oauth/ema-tenants/' + id + '/approve', cas.body, notes));
	} else if (action === 'reject') {
		lines.push(...requestBlock('POST', '/internal/oauth/ema-tenants/' + checkId(id) + '/reject'));
	} else fail('unknown request kind');
	process.stdout.write(lines.join('\n') + '\n');
}

function modeJwksUrl(recFile) {
	const rec = loadRecord(recFile);
	const v = jwksFetchVerdict(rec.jwks_uri);
	process.stdout.write(v.ok ? 'OK ' + v.url + '\n' : 'SKIP refused client-side: ' + v.reason + '\n');
}

function reportIssuer(rec, say, warn) {
	let issuerUrl;
	try { issuerUrl = new nurl.URL(rec.issuer); } catch (e) { warn('issuer is not a URL'); return null; }
	const host = issuerUrl.hostname.toLowerCase();
	say('Issuer:       ' + safe(rec.issuer));
	if (removedCount(rec.issuer)) warn('issuer contained ' + removedCount(rec.issuer) + ' control/bidi character(s); they are stripped above');
	let normalized = null;
	try { normalized = normalizeIssuer(rec.issuer); } catch (e) { normalized = null; }
	if (normalized !== rec.issuer) warn('stored issuer is not in normalized form' + (normalized ? ' (normalized: ' + safe(normalized) + ')' : ''));
	if (hasIdn(host)) warn('issuer host is IDN/punycode: ' + safe(host) + ' displays as ' + safe(unicodeHost(host)) + '; confirm that is the customer\'s real domain, not a look-alike');
	return issuerUrl;
}

function reportJwksUri(rec, issuerUrl, say, warn) {
	let jwksUrl;
	try { jwksUrl = new nurl.URL(rec.jwks_uri); } catch (e) { warn('jwks_uri is not a URL'); return; }
	const host = jwksUrl.hostname.toLowerCase();
	say('JWKS URI:     ' + safe(rec.jwks_uri) + '  (host ' + safe(host) + ')');
	if (removedCount(rec.jwks_uri)) warn('jwks_uri contained ' + removedCount(rec.jwks_uri) + ' control/bidi character(s); they are stripped above');
	if (hasIdn(host)) warn('jwks_uri host is IDN/punycode: ' + safe(host) + ' displays as ' + safe(unicodeHost(host)));
	if (!jwksFetchVerdict(rec.jwks_uri).ok && /^[0-9.]+$|^\[/.test(host)) warn('jwks_uri host is an IP literal');
	if (!issuerUrl) return;
	const a = regDomain(issuerUrl.hostname);
	const b = regDomain(host);
	if (a === b) say('  registrable domain ' + safe(b) + ' matches the issuer\'s');
	else warn('jwks_uri registrable domain ' + safe(b) + ' differs from the issuer\'s ' + safe(a) + '; the signing keys are hosted elsewhere, confirm that is intended');
}

function reportVendor(issuerUrl, rec, say, warn) {
	if (!issuerUrl) return;
	const v = vendorOf(rec.issuer);
	if (v.kind === 'vendor') say('IdP vendor:   ' + v.name + ' domain (tenant label "' + safe(v.label, 80) + '"); the label is what must be the customer\'s');
	else if (v.kind === 'entra') say('IdP vendor:   Microsoft Entra, per-tenant GUID ' + v.guid);
	else if (v.kind === 'entra-shared') warn('Microsoft Entra issuer without a tenant GUID ("' + safe(v.segment, 40) + '"): a shared issuer that serves many organisations');
	else warn('issuer host is not a known IdP vendor domain (custom domain or self-hosted): verify the customer owns it out of band');
}

function reportJwks(jwksStatus, jwksFile, say, warn) {
	if (jwksStatus !== 'ok') { say('JWKS (live):  not fetched: ' + safe(jwksStatus)); return; }
	let jwks;
	try { jwks = JSON.parse(fs.readFileSync(jwksFile, 'utf8')); } catch (e) { warn('JWKS response is not valid JSON'); return; }
	const keys = jwks && Array.isArray(jwks.keys) ? jwks.keys : null;
	if (!keys) { warn('JWKS response has no keys array'); return; }
	say('JWKS (live):  ' + keys.length + ' key(s)');
	if (keys.length === 0) warn('the JWKS holds no keys');
	keys.forEach((k, i) => {
		let tp;
		try { tp = thumbprint(k); } catch (e) { warn('key ' + (i + 1) + ' has no usable thumbprint (' + safe(e.message, 60) + ')'); return; }
		const meta = ['kid', 'kty', 'alg', 'use'].filter((f) => typeof k[f] === 'string').map((f) => f + '=' + safe(k[f], 60)).join(' ');
		say('  ' + (i + 1) + '. ' + meta + ' sha256-thumbprint=' + tp);
	});
}

function reportOthers(rec, listFile, say, warn) {
	if (listFile === '-') { say('Same issuer:  NOT CHECKED (pass --list-from-file with the saved list response)'); return; }
	const list = loadList(listFile);
	let issuerKey;
	try { issuerKey = normalizeIssuer(rec.issuer); } catch (e) { issuerKey = rec.issuer; }
	const others = list.tenants.filter((t) => {
		if (t.tenant_id === rec.tenant_id || typeof t.issuer !== 'string') return false;
		try { return normalizeIssuer(t.issuer) === issuerKey; } catch (e) { return t.issuer === rec.issuer; }
	});
	if (list.total !== null && list.total > list.tenants.length) warn('the list holds ' + list.tenants.length + ' of ' + list.total + ' tenants; the same-issuer check is incomplete');
	if (others.length === 0) { say('Same issuer:  no other tenant in the supplied list (' + list.tenants.length + ' tenant(s))'); return; }
	warn(others.length + ' other tenant(s) list this issuer:');
	for (const t of others) say('    ' + safe(String(t.tenant_id), 60) + '  approval=' + safe(effectiveApproval(t), 20) + ' enabled=' + safe(String(t.enabled), 8));
}

function modeReport(cmd, id, recFile, jwksStatus, jwksFile, listFile) {
	const rec = loadRecord(recFile, checkId(id));
	const lines = [];
	let warns = 0;
	const say = (s) => lines.push(s);
	const warn = (s) => { warns++; lines.push('  WARN  ' + s); };

	say('Tenant:       ' + safe(rec.tenant_id, 60) + '  approval=' + safe(effectiveApproval(rec), 20) + ' source=' + safe(rec.source || 'operator', 20) + ' enabled=' + safe(String(rec.enabled), 8));
	if (removedCount(rec.tenant_id)) warn('tenant_id contained control/bidi character(s)');
	const name = typeof rec.name === 'string' ? rec.name : '';
	say('Name:         ' + safe(name, 120));
	if (removedCount(name)) warn('name contained ' + removedCount(name) + ' control/bidi character(s); they are stripped above, so the name can read differently when rendered raw');
	const exp = isoOf(rec.entitlement_expires_at);
	say('Tier:         ' + safe(String(rec.tier), 20));
	say('Expires:      ' + (exp || 'none (no expiry)'));
	if (exp && new Date(exp).getTime() < Date.now()) warn('the entitlement has already lapsed');
	say('Updated:      ' + (isoOf(rec.updated_at) || 'unknown') + (Number.isInteger(rec.rev) ? '   rev=' + rec.rev : '   rev=absent'));
	if (effectiveApproval(rec) === 'rejected') warn('this tenant is currently rejected; approving overrides the ban for this issuer');
	const issuerUrl = reportIssuer(rec, say, warn);
	reportJwksUri(rec, issuerUrl, say, warn);
	reportVendor(issuerUrl, rec, say, warn);
	reportJwks(jwksStatus, jwksFile, say, warn);
	reportOthers(rec, listFile, say, warn);
	if (cmd === 'approve') {
		const cas = casBody(rec);
		say('CAS body:     ' + JSON.stringify(cas.body) + (cas.shape === 'updated_at' ? '   (rev absent: updated_at fallback)' : ''));
	}
	say(warns === 0 ? 'No warnings.' : warns + ' warning(s) above.');
	process.stdout.write(lines.join('\n') + '\n');
}

function modeListTable(file, approval) {
	const list = loadList(file);
	const rows = list.tenants.filter((t) => approval === '-' || effectiveApproval(t) === approval);
	const out = ['approval  enabled  tier        tenant_id                                  issuer / name'];
	for (const t of rows) {
		out.push([
			safe(effectiveApproval(t), 8).padEnd(9),
			safe(String(t.enabled), 7).padEnd(8),
			safe(String(t.tier), 10).padEnd(11),
			safe(String(t.tenant_id), 42).padEnd(42),
			safe(String(t.issuer), 80) + '  | ' + safe(String(t.name), 60),
		].join(' '));
	}
	out.push(rows.length + ' tenant(s)' + (approval === '-' ? '' : ' with approval=' + approval) + (list.total !== null && list.total > list.tenants.length ? '; the response holds ' + list.tenants.length + ' of ' + list.total + ', fetch the rest' : ''));
	process.stdout.write(out.join('\n') + '\n');
}

// --- self-test: pure helpers on inline data -------------------------------------------------------
function modeSelfTest() {
	const assert = require('assert');
	// control + bidi stripping
	assert.strictEqual(strip('Ac\u202eme\u0007 \u200bCo\u2066rp\u001b[31m'), 'Acme Corp[31m');
	assert.strictEqual(removedCount('a\u202eb\u0000c'), 2);
	// registrable domain, including the short public-suffix list
	assert.strictEqual(regDomain('keys.acme.okta.com'), 'okta.com');
	assert.strictEqual(regDomain('login.acme.co.nz'), 'acme.co.nz');
	assert.strictEqual(regDomain('a.b.acme.com.au'), 'acme.com.au');
	assert.strictEqual(regDomain('idp.acme.co.uk'), 'acme.co.uk');
	assert.strictEqual(regDomain('acme.nz'), 'acme.nz');
	assert.notStrictEqual(regDomain('idp.acme.co.nz'), regDomain('idp.evil.co.nz'));
	// IDN / punycode detection
	assert.ok(hasIdn('xn--acm-9ua.example.com'));
	assert.ok(hasIdn('acm\u00e9.example.com'));
	assert.ok(!hasIdn('acme.example.com'));
	// vendor domains match on a dot boundary only
	assert.strictEqual(vendorOf('https://acme.okta.com').name, 'Okta');
	assert.strictEqual(vendorOf('https://acme.oktapreview.com').name, 'Okta (preview)');
	assert.strictEqual(vendorOf('https://acme.auth0.com/').name, 'Auth0');
	assert.strictEqual(vendorOf('https://acme.onelogin.com').name, 'OneLogin');
	assert.strictEqual(vendorOf('https://auth.pingone.com/abc').name, 'PingOne');
	assert.strictEqual(vendorOf('https://evilokta.com').kind, 'unknown');
	assert.strictEqual(vendorOf('https://okta.com.evil.test').kind, 'unknown');
	assert.strictEqual(vendorOf('https://login.microsoftonline.com/0a1b2c3d-0000-4000-8000-0123456789ab/v2.0').kind, 'entra');
	assert.strictEqual(vendorOf('https://login.microsoftonline.com/common/v2.0').kind, 'entra-shared');
	// RFC 7638 section 3.1 test vector
	const rfc = {
		kty: 'RSA',
		n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
		e: 'AQAB',
		alg: 'RS256',
		kid: '2011-04-29',
	};
	assert.strictEqual(thumbprint(rfc), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
	assert.throws(() => thumbprint({ kty: 'RSA', e: 'AQAB' }));
	assert.throws(() => thumbprint({ kty: 'XYZ' }));
	// CAS body shapes
	const withRev = casBody({ issuer: 'https://a.example.com', jwks_uri: 'https://a.example.com/k', updated_at: 5, rev: 3 });
	assert.strictEqual(withRev.shape, 'rev');
	assert.strictEqual(JSON.stringify(withRev.body), '{"issuer":"https://a.example.com","jwks_uri":"https://a.example.com/k","rev":3}');
	const noRev = casBody({ issuer: 'https://a.example.com', jwks_uri: 'https://a.example.com/k', updated_at: 5 });
	assert.strictEqual(noRev.shape, 'updated_at');
	assert.strictEqual(JSON.stringify(noRev.body), '{"issuer":"https://a.example.com","jwks_uri":"https://a.example.com/k","updated_at":5}');
	// client-side JWKS fetch refusals
	assert.ok(jwksFetchVerdict('https://acme.okta.com/oauth2/v1/keys').ok);
	for (const bad of ['http://acme.okta.com/k', 'https://127.0.0.1/k', 'https://[::1]/k', 'https://localhost/k', 'https://intranet/k', 'https://printer.local/k', 'https://u:p' + '@acme.okta.com/k', 'https://2130706433/k']) {
		assert.ok(!jwksFetchVerdict(bad).ok, bad);
	}
	// approval default mirrors the server rule
	assert.strictEqual(effectiveApproval({ source: 'self-serve' }), 'pending');
	assert.strictEqual(effectiveApproval({}), 'approved');
	assert.strictEqual(effectiveApproval({ approval: 'rejected', source: 'self-serve' }), 'rejected');
	process.stdout.write('node helpers OK\n');
}

const [mode, ...rest] = process.argv.slice(2);
switch (mode) {
	case 'selftest': modeSelfTest(); break;
	case 'jwks-url': modeJwksUrl(rest[0]); break;
	case 'report': modeReport(rest[0], rest[1], rest[2], rest[3], rest[4], rest[5]); break;
	case 'request': modeRequest(rest[0], rest[1], rest[2], rest[3]); break;
	case 'list-table': modeListTable(rest[0], rest[1]); break;
	default: fail('internal: unknown mode');
}
JS
}

# --- self-test -----------------------------------------------------------------------------------
self_test() {
	command -v node >/dev/null 2>&1 || { echo "missing prerequisite: node" >&2; exit 2; }
	command -v openssl >/dev/null 2>&1 || { echo "missing prerequisite: openssl (self-test cross-checks thumbprints)" >&2; exit 2; }
	t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
	local self="$0" out rc sentinel="ema-sentinel-0123456789abcdef"
	st_fail() { echo "self-test FAIL: $*" >&2; exit 1; }
	has() { printf '%s' "$out" | grep -qF -- "$1" || st_fail "missing '$1' in: $(printf '%s' "$out" | head -c 600)"; }
	hasnt() { if printf '%s' "$out" | grep -qF -- "$1"; then st_fail "unexpected '$1'"; fi; }
	# run <args...>: capture stdout+stderr in $out and the exit code in $rc, with a sentinel key in the environment
	run() { set +e; out=$(BV_MCP_EMA_ADMIN_KEY="$sentinel" bash "$self" "$@" 2>&1); rc=$?; set -e; ALL="${ALL:-}$out"$'\n'; }
	ALL=""

	ema_node selftest >"$t/node.out" || st_fail "node helper assertions"

	# fixtures: a pending self-serve record with a control/bidi name, an IDN record with a mismatched JWKS host
	printf '%s' '{"tenant_id":"web-4f1c9a2e-77aa","name":"Acme\u202e Corp\u0007 Ltd","issuer":"https://acme.okta.com","jwks_uri":"https://acme.okta.com/oauth2/v1/keys","tier":"enterprise","enabled":true,"approval":"pending","source":"self-serve","created_at":1761700000,"updated_at":1761700100,"rev":3,"entitlement_expires_at":4102444800}' >"$t/rec.json"
	printf '%s' '{"tenant_id":"web-4f1c9a2e-77aa","name":"Acme","issuer":"https://acme.okta.com","jwks_uri":"https://acme.okta.com/oauth2/v1/keys","tier":"developer","enabled":true,"source":"self-serve","created_at":1761700000,"updated_at":1761700100}' >"$t/norev.json"
	printf '%s' '{"tenant_id":"web-idn00001-aaaa","name":"Bad","issuer":"https://xn--acm-9ua.example.co.nz","jwks_uri":"https://keys.other.example.com/jwks","tier":"developer","enabled":true,"approval":"pending","source":"self-serve","created_at":1,"updated_at":2,"rev":1}' >"$t/idn.json"
	printf '%s' '{"tenants":[{"tenant_id":"web-4f1c9a2e-77aa","issuer":"https://acme.okta.com","approval":"pending","tier":"enterprise","enabled":true,"name":"x"},{"tenant_id":"other-tenant-1","issuer":"https://ACME.okta.com/","approval":"approved","enabled":true,"tier":"developer","name":"y"},{"tenant_id":"unrelated-2","issuer":"https://z.example.com","tier":"developer","enabled":false,"name":"z"}],"total":3}' >"$t/list.json"
	# JWKS: the RFC 7638 vector plus an EC and an RSA key generated now, cross-checked below with openssl
	node -e '
const c=require("crypto"),fs=require("fs");
const ec=c.generateKeyPairSync("ec",{namedCurve:"P-256"}).publicKey.export({format:"jwk"});
const rsa=c.generateKeyPairSync("rsa",{modulusLength:2048}).publicKey.export({format:"jwk"});
ec.kid="ec-1";rsa.kid="rsa-1";
fs.writeFileSync(process.argv[1],JSON.stringify({keys:[ec,rsa,{kty:"RSA",kid:"broken",e:"AQAB"}]}));
' "$t/jwks.json"

	# thumbprints cross-checked against openssl over the canonical member string
	local ec_canon ec_tp want_ec
	ec_canon=$(node -e 'const k=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).keys[0];process.stdout.write("{\"crv\":\""+k.crv+"\",\"kty\":\"EC\",\"x\":\""+k.x+"\",\"y\":\""+k.y+"\"}")' "$t/jwks.json")
	want_ec=$(printf '%s' "$ec_canon" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
	local rsa_canon want_rsa
	rsa_canon=$(node -e 'const k=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).keys[1];process.stdout.write("{\"e\":\""+k.e+"\",\"kty\":\"RSA\",\"n\":\""+k.n+"\"}")' "$t/jwks.json")
	want_rsa=$(printf '%s' "$rsa_canon" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

	# show: full report from fixtures, no network
	run show web-4f1c9a2e-77aa --from-file "$t/rec.json" --list-from-file "$t/list.json" --jwks-from-file "$t/jwks.json"
	[ "$rc" = 0 ] || st_fail "show exited $rc: $out"
	has "Name:         Acme Corp Ltd"
	has "control/bidi character(s)"
	hasnt "$(printf '\342\200\256')"
	has "registrable domain okta.com matches the issuer's"
	has "IdP vendor:   Okta domain"
	has "Expires:      2100-01-01T00:00:00.000Z"
	has "rev=3"
	has "3 key(s)"
	has "sha256-thumbprint=$want_ec"
	has "sha256-thumbprint=$want_rsa"
	has "key 3 has no usable thumbprint"
	has "1 other tenant(s) list this issuer"
	has "other-tenant-1"
	hasnt "unrelated-2"

	# show: IDN issuer and a JWKS host on a different registrable domain
	run show web-idn00001-aaaa --from-file "$t/idn.json" --no-jwks
	[ "$rc" = 0 ] || st_fail "show idn exited $rc"
	has "IDN/punycode"
	has "displays as"
	has "differs from the issuer's example.co.nz"
	has "not a known IdP vendor domain"
	has "JWKS (live):  not fetched: skipped (--no-jwks)"
	has "Same issuer:  NOT CHECKED"

	# a JWKS URI on an IP literal is flagged and never fetched, even without --no-jwks (no network is touched)
	sed 's|https://acme.okta.com/oauth2/v1/keys|https://127.0.0.1/keys|' "$t/rec.json" >"$t/ip.json"
	run show web-4f1c9a2e-77aa --from-file "$t/ip.json"
	[ "$rc" = 0 ] || st_fail "show ip exited $rc"
	has "jwks_uri host is an IP literal"
	has "not fetched: refused client-side: IP literal host"

	# a record for a different tenant, a path-injection id, and a list response are refused
	run show web-other-0000 --from-file "$t/rec.json" --no-jwks;   [ "$rc" = 2 ] || st_fail "tenant mismatch should exit 2, got $rc"
	run show '../x' --from-file "$t/rec.json" --no-jwks;          [ "$rc" = 2 ] || st_fail "bad id should exit 2, got $rc"
	run show web-4f1c9a2e-77aa --from-file "$t/list.json" --no-jwks; [ "$rc" = 2 ] || st_fail "list as record should exit 2, got $rc"

	# approve: refuses without --yes, then emits the exact CAS body
	run approve web-4f1c9a2e-77aa --from-file "$t/rec.json" --jwks-from-file "$t/jwks.json"
	[ "$rc" = 2 ] || st_fail "approve without --yes should exit 2, got $rc"
	hasnt "POST /internal"
	has "CAS body:     {\"issuer\":\"https://acme.okta.com\",\"jwks_uri\":\"https://acme.okta.com/oauth2/v1/keys\",\"rev\":3}"
	run approve web-4f1c9a2e-77aa --from-file "$t/rec.json" --jwks-from-file "$t/jwks.json" --yes
	[ "$rc" = 0 ] || st_fail "approve --yes exited $rc: $out"
	has "POST /internal/oauth/ema-tenants/web-4f1c9a2e-77aa/approve"
	has "Body: {\"issuer\":\"https://acme.okta.com\",\"jwks_uri\":\"https://acme.okta.com/oauth2/v1/keys\",\"rev\":3}"
	has 'Authorization: Bearer $BV_MCP_EMA_ADMIN_KEY'
	run approve web-4f1c9a2e-77aa --from-file "$t/norev.json" --no-jwks --yes
	[ "$rc" = 0 ] || st_fail "approve (no rev) exited $rc: $out"
	has "Body: {\"issuer\":\"https://acme.okta.com\",\"jwks_uri\":\"https://acme.okta.com/oauth2/v1/keys\",\"updated_at\":1761700100}"
	has "falls back to updated_at"
	run approve web-4f1c9a2e-77aa --yes;                          [ "$rc" = 2 ] || st_fail "approve without a record should exit 2, got $rc"

	# reject: needs --yes; emits a POST with no body
	run reject web-4f1c9a2e-77aa;                                 [ "$rc" = 2 ] || st_fail "reject without --yes should exit 2, got $rc"
	hasnt "POST /internal"
	run reject web-4f1c9a2e-77aa --yes
	[ "$rc" = 0 ] || st_fail "reject --yes exited $rc"
	has "POST /internal/oauth/ema-tenants/web-4f1c9a2e-77aa/reject"
	hasnt "Body:"

	# list: request form and the table from a saved response
	run list --approval pending
	[ "$rc" = 0 ] || st_fail "list exited $rc"
	has "GET /internal/oauth/ema-tenants?approval=pending"
	run list --approval nonsense;                                 [ "$rc" = 2 ] || st_fail "bad approval should exit 2, got $rc"
	run list --approval pending --from-file "$t/list.json"
	[ "$rc" = 0 ] || st_fail "list table exited $rc"
	has "web-4f1c9a2e-77aa"
	hasnt "other-tenant-1"
	has "1 tenant(s) with approval=pending"

	# the bearer never appears in anything any command printed
	if printf '%s' "$ALL" | grep -qF -- "$sentinel"; then st_fail "the admin key leaked into output"; fi
	echo "self-test OK"
}

# --- argument parsing ----------------------------------------------------------------------------
[ $# -ge 1 ] || usage
CMD="$1"; shift
if [ "$CMD" = "--self-test" ]; then [ $# -eq 0 ] || usage; self_test; exit 0; fi
case "$CMD" in list|show|approve|reject) ;; *) usage ;; esac

ID="-"; APPROVAL="-"; REC_FILE=""; LIST_FILE=""; JWKS_FILE=""; NO_JWKS=0; YES=0
if [ "$CMD" != "list" ]; then
	[ $# -ge 1 ] || usage
	ID="$1"; shift
fi
while [ $# -gt 0 ]; do
	case "$1" in
	--from-file) [ $# -ge 2 ] || usage; REC_FILE="$2"; shift ;;
	--list-from-file) [ $# -ge 2 ] || usage; LIST_FILE="$2"; shift ;;
	--jwks-from-file) [ $# -ge 2 ] || usage; JWKS_FILE="$2"; shift ;;
	--approval) [ $# -ge 2 ] || usage; APPROVAL="$2"; shift ;;
	--no-jwks) NO_JWKS=1 ;;
	--yes) YES=1 ;;
	*) usage ;;
	esac
	shift
done
case "$APPROVAL" in -|pending|approved|rejected) ;; *) die "--approval must be pending, approved or rejected" ;; esac
[ "$APPROVAL" = "-" ] || [ "$CMD" = "list" ] || die "--approval only applies to list"
[ "$REC_FILE" != "-" ] || [ "$LIST_FILE" != "-" ] || die "only one input can read stdin"

command -v node >/dev/null 2>&1 || { echo "missing prerequisite: node" >&2; exit 2; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# stage_input <src|-> <dest>: copy a file or stdin (bounded to 4 MiB) into the temp dir
stage_input() {
	if [ "$1" = "-" ]; then head -c 4194304 >"$2"
	else [ -r "$1" ] || die "cannot read $1"; head -c 4194304 <"$1" >"$2"; fi
}

case "$CMD" in
list)
	if [ -z "$REC_FILE" ]; then ema_node request list - - "$APPROVAL"; exit 0; fi
	stage_input "$REC_FILE" "$TMP/list.json"
	ema_node list-table "$TMP/list.json" "$APPROVAL"
	;;
reject)
	[ "$YES" = 1 ] || die "reject needs --yes (nothing was prepared)"
	if [ -n "$REC_FILE" ]; then
		stage_input "$REC_FILE" "$TMP/rec.json"
		ema_node report reject "$ID" "$TMP/rec.json" "skipped (reject)" - -
	fi
	ema_node request reject "$ID" - -
	;;
show|approve)
	if [ -z "$REC_FILE" ]; then
		[ "$CMD" = "show" ] || die "approve needs --from-file <the saved GET for this tenant>"
		ema_node request show "$ID" - -
		exit 0
	fi
	stage_input "$REC_FILE" "$TMP/rec.json"
	LIST_ARG="-"
	if [ -n "$LIST_FILE" ]; then stage_input "$LIST_FILE" "$TMP/list.json"; LIST_ARG="$TMP/list.json"; fi
	JWKS_STATUS="skipped (--no-jwks)"; JWKS_ARG="-"
	if [ -n "$JWKS_FILE" ]; then
		stage_input "$JWKS_FILE" "$TMP/jwks.json"; JWKS_STATUS="ok"; JWKS_ARG="$TMP/jwks.json"
	elif [ "$NO_JWKS" = 0 ]; then
		verdict=$(ema_node jwks-url "$TMP/rec.json")
		case "$verdict" in
		"OK "*)
			command -v curl >/dev/null 2>&1 || { echo "missing prerequisite: curl" >&2; exit 2; }
			code=$(curl -sS --max-time 15 --proto '=https' --max-filesize 1048576 -o "$TMP/jwks.json" -w '%{http_code}' \
				-H 'accept: application/json' --url "${verdict#OK }" 2>"$TMP/curl.err") || code="curl-error"
			if [ "$code" = "200" ]; then JWKS_STATUS="ok"; JWKS_ARG="$TMP/jwks.json"
			else JWKS_STATUS="fetch failed (HTTP $code $(head -c 160 "$TMP/curl.err" | tr -d '\n'))"; fi
			;;
		*) JWKS_STATUS="${verdict#SKIP }" ;;
		esac
	fi
	ema_node report "$CMD" "$ID" "$TMP/rec.json" "$JWKS_STATUS" "$JWKS_ARG" "$LIST_ARG"
	if [ "$CMD" = "approve" ]; then
		if [ "$YES" != 1 ]; then
			echo
			echo "Not prepared: read the report above, then re-run with --yes to print the approve request." >&2
			exit 2
		fi
		echo
		ema_node request approve "$ID" "$TMP/rec.json" -
	fi
	;;
esac
