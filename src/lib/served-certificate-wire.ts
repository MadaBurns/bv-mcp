// SPDX-License-Identifier: BUSL-1.1

/**
 * Wire codec for reading the certificate a server presents: a TLS 1.2 ClientHello
 * builder, a reader for the server's plaintext handshake flight, and a minimal
 * X.509 decoder for issuer, validity and serial.
 *
 * WHY TLS 1.2. In TLS 1.2 the server's Certificate message is sent in the clear, so
 * the leaf can be read without completing a key exchange. In TLS 1.3 it is encrypted.
 * The hello therefore offers 1.2 only; a server that refuses it is reported as not
 * assessed, never guessed at.
 *
 * WHY HAND-ROLLED DER. This Worker runs without `nodejs_compat`, so there is no
 * `node:crypto` X509Certificate. Only the handful of fields below are decoded, every
 * read is bounds-checked, and any malformed input returns null.
 *
 * Pure: no sockets, no clock, no I/O. Never throws.
 */

const RECORD_HANDSHAKE = 22;
const RECORD_ALERT = 21;
const HANDSHAKE_CLIENT_HELLO = 1;
const HANDSHAKE_CERTIFICATE = 11;
const HANDSHAKE_SERVER_HELLO_DONE = 14;
const ALERT_LEVEL_FATAL = 2;
const ALERT_HANDSHAKE_FAILURE = 40;
const ALERT_PROTOCOL_VERSION = 70;
const ALERT_INSUFFICIENT_SECURITY = 71;
/** RFC 5246 caps a record at 2^14 plaintext bytes; allow the standard expansion margin. */
const MAX_RECORD_BYTES = 16_384 + 2_048;

/** Suites offered: the common ECDHE and RSA families, so an ordinary server finds a match. */
const CIPHER_SUITES = [
	0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x00ff,
];
const SUPPORTED_GROUPS = [0x001d, 0x0017, 0x0018];
const SIGNATURE_ALGORITHMS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201];

function u16(value: number): number[] {
	return [(value >> 8) & 0xff, value & 0xff];
}

function u24(value: number): number[] {
	return [(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff];
}

function extension(type: number, body: number[]): number[] {
	return [...u16(type), ...u16(body.length), ...body];
}

/** Build one TLS record holding a TLS 1.2 ClientHello with SNI for `serverName`. */
export function buildClientHello(serverName: string, random: Uint8Array): Uint8Array {
	const name = [...new TextEncoder().encode(serverName)];
	const sniEntry = [0, ...u16(name.length), ...name];
	const extensions = [
		...extension(0, [...u16(sniEntry.length), ...sniEntry]),
		...extension(10, [...u16(SUPPORTED_GROUPS.length * 2), ...SUPPORTED_GROUPS.flatMap(u16)]),
		...extension(11, [1, 0]),
		...extension(13, [...u16(SIGNATURE_ALGORITHMS.length * 2), ...SIGNATURE_ALGORITHMS.flatMap(u16)]),
		...extension(23, []),
	];
	const body = [
		0x03,
		0x03,
		...random.subarray(0, 32),
		0,
		...u16(CIPHER_SUITES.length * 2),
		...CIPHER_SUITES.flatMap(u16),
		1,
		0,
		...u16(extensions.length),
		...extensions,
	];
	const handshake = [HANDSHAKE_CLIENT_HELLO, ...u24(body.length), ...body];
	return new Uint8Array([RECORD_HANDSHAKE, 0x03, 0x01, ...u16(handshake.length), ...handshake]);
}

export type ServerFlightResult =
	| { state: 'certificate'; leafDer: Uint8Array }
	| { state: 'need_more' }
	| { state: 'refused' }
	| { state: 'unreadable' };

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
	const out = new Uint8Array(a.length + b.length);
	out.set(a, 0);
	out.set(b, a.length);
	return out;
}

/** A fatal alert that means "I will not speak TLS 1.2 with these parameters". */
function alertState(payload: Uint8Array): 'refused' | 'unreadable' | 'ignore' {
	if (payload.length < 2) return 'unreadable';
	if (payload[0] !== ALERT_LEVEL_FATAL) return 'ignore';
	const refusal = [ALERT_HANDSHAKE_FAILURE, ALERT_PROTOCOL_VERSION, ALERT_INSUFFICIENT_SECURITY];
	return refusal.includes(payload[1]) ? 'refused' : 'unreadable';
}

/** First certificate of a Certificate message body, or null when the lengths do not add up. */
function leafFromCertificateBody(body: Uint8Array): Uint8Array | null {
	if (body.length < 6) return null;
	const listLength = (body[0] << 16) | (body[1] << 8) | body[2];
	const leafLength = (body[3] << 16) | (body[4] << 8) | body[5];
	if (listLength > body.length - 3 || leafLength === 0 || leafLength > listLength - 3) return null;
	return body.slice(6, 6 + leafLength);
}

/** Walk complete handshake messages; stop at the Certificate. */
function scanHandshake(handshake: Uint8Array): ServerFlightResult {
	let offset = 0;
	while (handshake.length - offset >= 4) {
		const type = handshake[offset];
		const length = (handshake[offset + 1] << 16) | (handshake[offset + 2] << 8) | handshake[offset + 3];
		if (handshake.length - offset - 4 < length) return { state: 'need_more' };
		const body = handshake.subarray(offset + 4, offset + 4 + length);
		if (type === HANDSHAKE_CERTIFICATE) {
			const leafDer = leafFromCertificateBody(body);
			return leafDer ? { state: 'certificate', leafDer } : { state: 'unreadable' };
		}
		if (type === HANDSHAKE_SERVER_HELLO_DONE) return { state: 'unreadable' };
		offset += 4 + length;
	}
	return { state: 'need_more' };
}

/**
 * Read as much of the server's first flight as `bytes` holds.
 *
 * `need_more` means every byte so far was well-formed but the Certificate message is
 * not complete yet: the caller reads more from the socket and calls again with the
 * whole buffer.
 */
export function parseServerFlight(bytes: Uint8Array): ServerFlightResult {
	let handshake: Uint8Array = new Uint8Array(0);
	let offset = 0;
	while (bytes.length - offset >= 5) {
		const type = bytes[offset];
		const length = (bytes[offset + 3] << 8) | bytes[offset + 4];
		if (bytes[offset + 1] !== 0x03 || length > MAX_RECORD_BYTES) return { state: 'unreadable' };
		if (bytes.length - offset - 5 < length) break;
		const payload = bytes.subarray(offset + 5, offset + 5 + length);
		if (type === RECORD_ALERT) {
			const alert = alertState(payload);
			if (alert !== 'ignore') return { state: alert };
		} else if (type === RECORD_HANDSHAKE) {
			handshake = concat(handshake, payload);
			const scanned = scanHandshake(handshake);
			if (scanned.state !== 'need_more') return scanned;
		} else {
			return { state: 'unreadable' };
		}
		offset += 5 + length;
	}
	return { state: 'need_more' };
}

// ─── Minimal X.509 ───────────────────────────────────────────────────────────

interface Tlv {
	tag: number;
	value: Uint8Array;
	/** Offset of the first byte after this element. */
	end: number;
}

function readTlv(bytes: Uint8Array, offset: number): Tlv | null {
	if (offset + 2 > bytes.length) return null;
	const tag = bytes[offset];
	let length = bytes[offset + 1];
	let cursor = offset + 2;
	if (length & 0x80) {
		const count = length & 0x7f;
		if (count === 0 || count > 4 || cursor + count > bytes.length) return null;
		length = 0;
		for (let i = 0; i < count; i++) length = length * 256 + bytes[cursor + i];
		cursor += count;
	}
	if (cursor + length > bytes.length) return null;
	return { tag, value: bytes.subarray(cursor, cursor + length), end: cursor + length };
}

function children(bytes: Uint8Array): Tlv[] | null {
	const out: Tlv[] = [];
	let offset = 0;
	while (offset < bytes.length) {
		const tlv = readTlv(bytes, offset);
		if (!tlv) return null;
		out.push(tlv);
		offset = tlv.end;
	}
	return out;
}

/** The X.520 attribute-type arc, as it comes out of `decodeOid`. Every entry below sits under it. */
const X520_ARC = [2, 5, 4].join('.') + '.';
/** Keyed by the last number of the X.520 attribute type. */
const X520_ATTRIBUTE_NAMES: Record<string, string> = {
	'3': 'CN',
	'5': 'serialNumber',
	'6': 'C',
	'7': 'L',
	'8': 'ST',
	'10': 'O',
	'11': 'OU',
};
const DOMAIN_COMPONENT_OID = '0.9.2342.19200300.100.1.25';

function attributeName(oid: string): string {
	if (oid === DOMAIN_COMPONENT_OID) return 'DC';
	if (!oid.startsWith(X520_ARC)) return oid;
	return X520_ATTRIBUTE_NAMES[oid.slice(X520_ARC.length)] ?? oid;
}

function decodeOid(bytes: Uint8Array): string | null {
	if (bytes.length === 0) return null;
	const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
	let value = 0;
	for (let i = 1; i < bytes.length; i++) {
		value = value * 128 + (bytes[i] & 0x7f);
		if (!(bytes[i] & 0x80)) {
			parts.push(value);
			value = 0;
		}
	}
	return parts.join('.');
}

function decodeString(tlv: Tlv): string {
	if (tlv.tag === 0x1e) {
		let out = '';
		for (let i = 0; i + 1 < tlv.value.length; i += 2) out += String.fromCharCode((tlv.value[i] << 8) | tlv.value[i + 1]);
		return out;
	}
	return new TextDecoder().decode(tlv.value);
}

/** Render a Name as `C=GB, O=Example Ltd, CN=Example CA`, in the certificate's own order. */
function decodeName(name: Tlv): string | null {
	const sets = children(name.value);
	if (!sets) return null;
	const parts: string[] = [];
	for (const set of sets) {
		for (const attribute of children(set.value) ?? []) {
			const pair = children(attribute.value);
			if (!pair || pair.length < 2) return null;
			const oid = decodeOid(pair[0].value);
			if (!oid) return null;
			parts.push(`${attributeName(oid)}=${decodeString(pair[1])}`);
		}
	}
	return parts.length > 0 ? parts.join(', ') : null;
}

/** UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`) → epoch seconds. */
function decodeTime(tlv: Tlv): number | null {
	const text = new TextDecoder().decode(tlv.value);
	const match = tlv.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
	if (!match) return null;
	const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
	const fullYear = tlv.tag === 0x17 ? (year < 50 ? 2000 + year : 1900 + year) : year;
	const ms = Date.UTC(fullYear, month - 1, day, hour, minute, second);
	return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}

function hex(bytes: Uint8Array): string {
	return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export interface DecodedCertificate {
	issuer: string | null;
	subject: string | null;
	/** Epoch seconds. */
	notBefore: number | null;
	notAfter: number | null;
	/** Lowercase hex, leading zero octets removed. */
	serial: string | null;
}

/** Decode issuer, subject, validity and serial from a DER certificate. Null when it is not one. */
export function decodeCertificate(der: Uint8Array): DecodedCertificate | null {
	const certificate = readTlv(der, 0);
	if (!certificate || certificate.tag !== 0x30) return null;
	const tbs = readTlv(certificate.value, 0);
	if (!tbs || tbs.tag !== 0x30) return null;
	const fields = children(tbs.value);
	if (!fields) return null;
	// An explicit [0] version is present on every v2/v3 certificate and absent on v1.
	const start = fields[0]?.tag === 0xa0 ? 1 : 0;
	const [serial, , issuer, validity, subject] = fields.slice(start);
	if (!serial || !issuer || !validity || !subject) return null;
	if (serial.tag !== 0x02 || issuer.tag !== 0x30 || validity.tag !== 0x30 || subject.tag !== 0x30) return null;
	const times = children(validity.value);
	if (!times || times.length < 2) return null;
	return {
		issuer: decodeName(issuer),
		subject: decodeName(subject),
		notBefore: decodeTime(times[0]),
		notAfter: decodeTime(times[1]),
		serial: hex(serial.value).replace(/^(00)+(?=.)/, '') || null,
	};
}
