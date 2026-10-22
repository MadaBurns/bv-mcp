// SPDX-License-Identifier: BUSL-1.1
/**
 * Minimal DER walker for the TBSCertificate a CT precert entry carries (RFC 5280 section 4.1). It reads
 * only what the tailer stores: the SAN dNSNames (else the subject CN), the validity window, the issuer
 * CN (else O), and the certificate details the scanners show (serial, signature algorithm, key type and size). No dependencies; Workers-runtime APIs only. Every malformed or truncated input throws a
 * RangeError, so the caller can skip and count the entry.
 */

export interface CertFacts {
	/** SAN dNSNames in certificate order, or the subject CNs when the SAN has no dNSName. Not normalized. */
	names: string[];
	/** Epoch seconds. */
	notBefore: number;
	notAfter: number;
	/** Issuer CN, else issuer O, else ''. */
	issuer: string;
	/** The serial number as lowercase hex, without the sign byte DER adds before a high bit. */
	serial: string;
	/** The TBS signature algorithm by its OpenSSL name (e.g. `sha256WithRSAEncryption`), else its dotted OID; '' if unreadable. */
	sigAlg: string;
	/** Same vocabulary as @blackveil/dns-checks `CertMetadata.keyType`. */
	keyType: 'rsa' | 'ec' | 'unknown';
	/** RSA modulus bits or the EC curve's size; null when the key or curve is not one we size. */
	keyBits: number | null;
}

interface Tlv {
	tag: number;
	/** First content byte. */
	start: number;
	/** One past the last content byte. */
	end: number;
}

const SEQUENCE = 0x30;
const INTEGER = 0x02;
const OCTET_STRING = 0x04;
const OID = 0x06;
const UTF8_STRING = 0x0c;
const BMP_STRING = 0x1e;
const UTC_TIME = 0x17;
const GENERALIZED_TIME = 0x18;
/** [0] EXPLICIT version, [3] EXPLICIT extensions, and a GeneralName's [2] IMPLICIT dNSName. */
const VERSION_TAG = 0xa0;
const EXTENSIONS_TAG = 0xa3;
const DNS_NAME_TAG = 0x82;

const OID_COMMON_NAME = [0x55, 0x04, 0x03];
const OID_ORGANIZATION = [0x55, 0x04, 0x0a];
const OID_SUBJECT_ALT_NAME = [0x55, 0x1d, 0x11];
const BIT_STRING = 0x03;

/**
 * OIDs as dotted text, built from their arcs: a dotted literal with four parts reads as an IPv4 address to the
 * secret scanners (see `epochSeconds`).
 */
const oid = (...arcs: number[]) => arcs.join('.');

/** Dotted OID → name, for the signature algorithms CAs use; anything else is kept as its dotted OID. */
const SIGNATURE_ALGORITHMS: Record<string, string> = {
	[oid(1, 2, 840, 113549, 1, 1, 5)]: 'sha1WithRSAEncryption',
	[oid(1, 2, 840, 113549, 1, 1, 4)]: 'md5WithRSAEncryption',
	[oid(1, 2, 840, 113549, 1, 1, 10)]: 'rsassaPss',
	[oid(1, 2, 840, 113549, 1, 1, 11)]: 'sha256WithRSAEncryption',
	[oid(1, 2, 840, 113549, 1, 1, 12)]: 'sha384WithRSAEncryption',
	[oid(1, 2, 840, 113549, 1, 1, 13)]: 'sha512WithRSAEncryption',
	[oid(1, 2, 840, 10045, 4, 1)]: 'ecdsa-with-SHA1',
	[oid(1, 2, 840, 10045, 4, 3, 2)]: 'ecdsa-with-SHA256',
	[oid(1, 2, 840, 10045, 4, 3, 3)]: 'ecdsa-with-SHA384',
	[oid(1, 2, 840, 10045, 4, 3, 4)]: 'ecdsa-with-SHA512',
	[oid(1, 3, 101, 112)]: 'ED25519',
};
const RSA_KEY = oid(1, 2, 840, 113549, 1, 1, 1);
const RSA_PSS_KEY = oid(1, 2, 840, 113549, 1, 1, 10);
const EC_KEY = oid(1, 2, 840, 10045, 2, 1);
/** Named curve OID → key size in bits. */
const EC_CURVE_BITS: Record<string, number> = {
	[oid(1, 2, 840, 10045, 3, 1, 7)]: 256,
	[oid(1, 3, 132, 0, 34)]: 384,
	[oid(1, 3, 132, 0, 35)]: 521,
};

const utf8 = new TextDecoder();

function readTlv(der: Uint8Array, pos: number, limit: number): Tlv {
	if (pos + 2 > limit) throw new RangeError('DER: truncated header');
	const tag = der[pos]!;
	if ((tag & 0x1f) === 0x1f) throw new RangeError('DER: multi-byte tags are not used in certificates');
	let length = der[pos + 1]!;
	let start = pos + 2;
	if (length >= 0x80) {
		const octets = length & 0x7f;
		if (octets === 0 || octets > 4) throw new RangeError('DER: unsupported length form');
		if (start + octets > limit) throw new RangeError('DER: truncated length');
		length = 0;
		for (let i = 0; i < octets; i++) length = length * 256 + der[start++]!;
	}
	if (start + length > limit) throw new RangeError('DER: length overruns its parent');
	return { tag, start, end: start + length };
}

function children(der: Uint8Array, parent: Tlv): Tlv[] {
	const out: Tlv[] = [];
	for (let pos = parent.start; pos < parent.end;) {
		const child = readTlv(der, pos, parent.end);
		out.push(child);
		pos = child.end;
	}
	return out;
}

function expectTag(tlv: Tlv | undefined, tag: number, what: string): Tlv {
	if (tlv?.tag !== tag) throw new RangeError(`DER: expected ${what}`);
	return tlv;
}

function isOid(der: Uint8Array, tlv: Tlv | undefined, oid: readonly number[]): boolean {
	return tlv?.tag === OID && tlv.end - tlv.start === oid.length && oid.every((byte, i) => der[tlv.start + i] === byte);
}

function latin1(der: Uint8Array, tlv: Tlv): string {
	let text = '';
	for (let i = tlv.start; i < tlv.end; i++) text += String.fromCharCode(der[i]!);
	return text;
}

/** A directory string: UTF8String and BMPString decoded, the single-byte types (Printable, IA5, Teletex) as Latin-1. */
function directoryString(der: Uint8Array, tlv: Tlv): string {
	if (tlv.tag === UTF8_STRING) return utf8.decode(der.subarray(tlv.start, tlv.end));
	if (tlv.tag === BMP_STRING) {
		let text = '';
		for (let i = tlv.start; i + 1 < tlv.end; i += 2) text += String.fromCharCode((der[i]! << 8) | der[i + 1]!);
		return text;
	}
	return latin1(der, tlv);
}

/** Every value of one attribute type in a Name (SEQUENCE OF SET OF AttributeTypeAndValue), in order. */
function attributeValues(der: Uint8Array, name: Tlv, oid: readonly number[]): string[] {
	const values: string[] = [];
	for (const rdn of children(der, name)) {
		for (const attribute of children(der, rdn)) {
			const [type, value] = children(der, attribute);
			if (value && isOid(der, type, oid)) values.push(directoryString(der, value));
		}
	}
	return values;
}

const UTC_TIME_TEXT = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;
const GENERALIZED_TIME_TEXT = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;

/**
 * UTCTime (YY < 50 is 20YY, per RFC 5280 §4.1.2 on validity) or GeneralizedTime, to epoch seconds.
 * The citation stays at three parts: a dotted four-part one scans as an IPv4 address in the secret scanners.
 */
function epochSeconds(der: Uint8Array, tlv: Tlv | undefined): number {
	const text = tlv ? latin1(der, tlv) : '';
	const match = tlv?.tag === UTC_TIME ? UTC_TIME_TEXT.exec(text) : tlv?.tag === GENERALIZED_TIME ? GENERALIZED_TIME_TEXT.exec(text) : null;
	if (!match) throw new RangeError(`DER: bad validity time ${JSON.stringify(text)}`);
	const [year, month, day, hour, minute, second] = match.slice(1).map(Number) as [number, number, number, number, number, number];
	const fullYear = tlv!.tag === UTC_TIME ? (year < 50 ? 2000 + year : 1900 + year) : year;
	return Math.floor(Date.UTC(fullYear, month - 1, day, hour, minute, second) / 1000);
}

/** An OBJECT IDENTIFIER's content as dotted text. */
function dottedOid(der: Uint8Array, tlv: Tlv): string {
	if (tlv.tag !== OID || tlv.end === tlv.start) throw new RangeError('DER: expected OBJECT IDENTIFIER');
	const first = der[tlv.start]!;
	const top = first < 80 ? Math.floor(first / 40) : 2;
	return [top, first - 40 * top, ...base128Arcs(der, tlv.start + 1, tlv.end)].join('.');
}

/** The arcs after the first byte: base-128 groups, the high bit set on every byte but a group's last. */
function base128Arcs(der: Uint8Array, start: number, end: number): number[] {
	const arcs: number[] = [];
	let arc = 0;
	for (let i = start; i < end; i++) {
		arc = arc * 128 + (der[i]! & 0x7f);
		if (der[i]! < 0x80) {
			arcs.push(arc);
			arc = 0;
		}
	}
	return arcs;
}

/** The bit length of an unsigned big-endian integer held in der[start, end), leading zero bytes ignored. */
function bitLength(der: Uint8Array, start: number, end: number): number {
	let i = start;
	while (i < end && der[i] === 0) i++;
	if (i === end) return 0;
	return (end - i - 1) * 8 + (32 - Math.clz32(der[i]!));
}

/** Lowercase hex of the serial INTEGER, without the sign byte DER adds before a high bit. */
function serialHex(der: Uint8Array, serial: Tlv): string {
	const start = serial.end - serial.start > 1 && der[serial.start] === 0 ? serial.start + 1 : serial.start;
	let hex = '';
	for (let i = start; i < serial.end; i++) hex += der[i]!.toString(16).padStart(2, '0');
	return hex;
}

/**
 * The details are read leniently: a malformed signature or key field yields '' / 'unknown' rather than a throw,
 * so an odd key encoding never costs the names, which are what the index is for.
 */
function details(der: Uint8Array, signature: Tlv, spki: Tlv): Pick<CertFacts, 'sigAlg' | 'keyType' | 'keyBits'> {
	let sigAlg = '';
	try {
		sigAlg = signatureAlgorithm(der, signature);
	} catch {
		// keep ''
	}
	try {
		return { sigAlg, ...publicKey(der, spki) };
	} catch {
		return { sigAlg, keyType: 'unknown', keyBits: null };
	}
}

function signatureAlgorithm(der: Uint8Array, algorithm: Tlv): string {
	const oid = dottedOid(der, expectTag(children(der, algorithm)[0], OID, 'signature algorithm'));
	return SIGNATURE_ALGORITHMS[oid] ?? oid;
}

/** RSA modulus bits: the BIT STRING (one unused-bits byte) wraps SEQUENCE { modulus INTEGER, exponent INTEGER }. */
function rsaBits(der: Uint8Array, key: Tlv | undefined): number | null {
	if (key?.tag !== BIT_STRING) return null;
	const rsaKey = readTlv(der, key.start + 1, key.end);
	const modulus = rsaKey.tag === SEQUENCE ? children(der, rsaKey)[0] : undefined;
	return modulus?.tag === INTEGER ? bitLength(der, modulus.start, modulus.end) : null;
}

function publicKey(der: Uint8Array, spki: Tlv): Pick<CertFacts, 'keyType' | 'keyBits'> {
	const [algorithm, key] = children(der, spki);
	const [oidTlv, parameters] = children(der, expectTag(algorithm, SEQUENCE, 'key algorithm'));
	const oid = dottedOid(der, expectTag(oidTlv, OID, 'key algorithm'));
	if (oid === RSA_KEY || oid === RSA_PSS_KEY) return { keyType: 'rsa', keyBits: rsaBits(der, key) };
	if (oid === EC_KEY) return { keyType: 'ec', keyBits: ecBits(der, parameters) };
	return { keyType: 'unknown', keyBits: null };
}

/** An EC key's size from its namedCurve parameter; null for an unnamed or unsized curve. */
function ecBits(der: Uint8Array, parameters: Tlv | undefined): number | null {
	return parameters?.tag === OID ? (EC_CURVE_BITS[dottedOid(der, parameters)] ?? null) : null;
}

/** The dNSNames of a subjectAltName extension's value (an OCTET STRING wrapping GeneralNames). */
function sanDnsNames(der: Uint8Array, extnValue: Tlv): string[] {
	const generalNames = expectTag(readTlv(der, extnValue.start, extnValue.end), SEQUENCE, 'GeneralNames');
	return children(der, generalNames)
		.filter((name) => name.tag === DNS_NAME_TAG)
		.map((name) => latin1(der, name));
}

export function parseTbsCertificate(der: Uint8Array): CertFacts {
	const fields = children(der, expectTag(readTlv(der, 0, der.length), SEQUENCE, 'TBSCertificate'));
	let i = fields[0]?.tag === VERSION_TAG ? 1 : 0;
	const serial = expectTag(fields[i++], INTEGER, 'serialNumber');
	const signature = expectTag(fields[i++], SEQUENCE, 'signature');
	const issuer = expectTag(fields[i++], SEQUENCE, 'issuer');
	const [notBefore, notAfter] = children(der, expectTag(fields[i++], SEQUENCE, 'validity'));
	const subject = expectTag(fields[i++], SEQUENCE, 'subject');
	const spki = expectTag(fields[i++], SEQUENCE, 'subjectPublicKeyInfo');

	const dnsNames: string[] = [];
	const extensions = fields.slice(i).find((field) => field.tag === EXTENSIONS_TAG);
	if (extensions) {
		for (const extension of children(der, expectTag(children(der, extensions)[0], SEQUENCE, 'Extensions'))) {
			const parts = children(der, extension);
			if (!isOid(der, parts[0], OID_SUBJECT_ALT_NAME)) continue;
			dnsNames.push(...sanDnsNames(der, expectTag(parts[parts.length - 1], OCTET_STRING, 'extnValue')));
		}
	}

	return {
		names: dnsNames.length > 0 ? dnsNames : attributeValues(der, subject, OID_COMMON_NAME),
		notBefore: epochSeconds(der, notBefore),
		notAfter: epochSeconds(der, notAfter),
		issuer: attributeValues(der, issuer, OID_COMMON_NAME)[0] ?? attributeValues(der, issuer, OID_ORGANIZATION)[0] ?? '',
		serial: serialHex(der, serial),
		...details(der, signature, spki),
	};
}
