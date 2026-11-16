// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { buildClientHello, decodeCertificate, parseServerFlight } from '../../src/lib/served-certificate-wire';
import { observeServedCertificate, type ServedCertificateSocket } from '../../src/lib/served-certificate';

/**
 * A throwaway self-signed certificate made with openssl for this file. openssl reads
 * it as: issuer `C=GB, O=Example Trust Ltd, CN=Example Issuing CA R1`, serial
 * `0A1B2C3D4E5F`, valid 2026-11-16T20:16:52Z to 2027-02-14T20:16:52Z, SHA-256
 * fingerprint `f3d089b2…94f17066`. The expectations below are openssl's reading, not
 * this decoder's own output.
 */
const FIXTURE_DER_B64 =
	'MIIBtzCCAV6gAwIBAgIGChssPU5fMAoGCCqGSM49BAMCMEkxCzAJBgNVBAYTAkdCMRowGAYDVQQKDBFFeGFtcGxlIFRydXN0IEx0ZDEeMBwGA1UEAwwVRXhhbXBsZSBJc3N1aW5nIENBIFIxMB4XDTI2MTExNjIwMTY1MloXDTI3MDIxNDIwMTY1MlowSTELMAkGA1UEBhMCR0IxGjAYBgNVBAoMEUV4YW1wbGUgVHJ1c3QgTHRkMR4wHAYDVQQDDBVFeGFtcGxlIElzc3VpbmcgQ0EgUjEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQJIfflqVrebNavrB+x2JIBwzAoB0ZOkXXPBTLOT2PIx+kmHgOSYCfQIY43yNIEcbTCUxtBTNQQ+3P1CcZFu0YxozIwMDAdBgNVHQ4EFgQUPGnnVubHfvcBJwh8d9FRlHsNkowwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiASjLp1NvfVWjiBZbtpIPu1ZM7SbaMHIfb3VRowMbu4agIgHhywovMuwQBncO/dkFwdrA9Q9prhpeI9SJgA3EUKRiU=';
const FIXTURE_DER = Uint8Array.from(atob(FIXTURE_DER_B64), (c) => c.charCodeAt(0));
const FIXTURE_ISSUER = 'C=GB, O=Example Trust Ltd, CN=Example Issuing CA R1';
const FIXTURE_FINGERPRINT = 'f3d089b2661fd41bfad00b78ff68c31ea341e67d3cff8a7e2b2bb56394f17066';
/** 2026-12-01T00:00:00Z: inside the fixture's validity window. */
const NOW = Math.floor(Date.UTC(2026, 11, 1) / 1000);
const PUBLIC_IP = '93.184.216.34';

const u24 = (n: number) => [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
const record = (type: number, payload: number[]) => [type, 0x03, 0x03, (payload.length >> 8) & 0xff, payload.length & 0xff, ...payload];
const handshake = (type: number, body: number[]) => [type, ...u24(body.length), ...body];

/** ServerHello (opaque body) followed by a Certificate message carrying `der` then a second chain entry. */
function serverFlight(der: Uint8Array): number[] {
	const chainEntry = [1, 2, 3, 4];
	const list = [...u24(der.length), ...der, ...u24(chainEntry.length), ...chainEntry];
	const certificate = handshake(11, [...u24(list.length), ...list]);
	const serverHello = handshake(2, new Array(40).fill(0));
	return [...record(22, serverHello), ...record(22, certificate)];
}

function fakeSocket(chunks: number[][], opts: { openError?: Error; hang?: boolean } = {}): ServedCertificateSocket & { written: Uint8Array[]; closeCalls: number } {
	const written: Uint8Array[] = [];
	const state = {
		written,
		closeCalls: 0,
		opened: opts.openError ? Promise.reject(opts.openError) : Promise.resolve(),
		closed: Promise.resolve(),
		readable: new ReadableStream<Uint8Array>({
			start(controller) {
				for (const chunk of chunks) controller.enqueue(new Uint8Array(chunk));
				if (!opts.hang) controller.close();
			},
		}),
		writable: new WritableStream<Uint8Array>({
			write(chunk) {
				written.push(chunk);
			},
		}),
		async close() {
			state.closeCalls += 1;
		},
	};
	state.opened.catch(() => undefined);
	return state;
}

const deps = (socket: ServedCertificateSocket, over: Record<string, unknown> = {}) => ({
	resolveAddresses: async () => [PUBLIC_IP],
	openSocket: async () => socket,
	nowSeconds: NOW,
	...over,
});

describe('decodeCertificate', () => {
	it('reads issuer, validity and serial the way openssl does', () => {
		expect(decodeCertificate(FIXTURE_DER)).toEqual({
			issuer: FIXTURE_ISSUER,
			subject: FIXTURE_ISSUER,
			notBefore: Math.floor(Date.UTC(2026, 10, 16, 20, 16, 52) / 1000),
			notAfter: Math.floor(Date.UTC(2027, 1, 14, 20, 16, 52) / 1000),
			serial: '0a1b2c3d4e5f',
		});
	});

	it('returns null for bytes that are not a certificate, and for a truncated one', () => {
		expect(decodeCertificate(new Uint8Array([1, 2, 3, 4]))).toBeNull();
		expect(decodeCertificate(FIXTURE_DER.subarray(0, 120))).toBeNull();
		expect(decodeCertificate(new Uint8Array(0))).toBeNull();
	});
});

describe('buildClientHello', () => {
	it('offers TLS 1.2 only and names the host in SNI', () => {
		const hello = buildClientHello('example.com', new Uint8Array(32).fill(7));
		expect([...hello.subarray(0, 3)]).toEqual([22, 3, 1]);
		// Record length and handshake length both agree with the bytes present.
		expect((hello[3] << 8) | hello[4]).toBe(hello.length - 5);
		expect((hello[6] << 16) | (hello[7] << 8) | hello[8]).toBe(hello.length - 9);
		// client_version 1.2, and no supported_versions extension (type 43), which is
		// what would let a server pick 1.3 and encrypt its certificate.
		expect([hello[9], hello[10]]).toEqual([3, 3]);
		expect(new TextDecoder().decode(hello)).toContain('example.com');
		const extensionsStart = 9 + 2 + 32 + 1 + 2 + ((hello[44] << 8) | hello[45]) + 2 + 2;
		const types: number[] = [];
		for (let i = extensionsStart; i < hello.length; ) {
			types.push((hello[i] << 8) | hello[i + 1]);
			i += 4 + ((hello[i + 2] << 8) | hello[i + 3]);
		}
		expect(types).toEqual([0, 10, 11, 13, 23]);
	});
});

describe('parseServerFlight', () => {
	it('returns the FIRST certificate of the chain', () => {
		const out = parseServerFlight(new Uint8Array(serverFlight(FIXTURE_DER)));
		expect(out.state).toBe('certificate');
		expect(out.state === 'certificate' && [...out.leafDer]).toEqual([...FIXTURE_DER]);
	});

	it('asks for more at every cut point short of the full flight', () => {
		const full = serverFlight(FIXTURE_DER);
		for (const cut of [0, 3, 5, 30, 60, full.length - 20]) {
			expect(parseServerFlight(new Uint8Array(full.slice(0, cut))).state).toBe('need_more');
		}
	});

	it('reassembles a Certificate message split across two records', () => {
		const list = [...u24(FIXTURE_DER.length), ...FIXTURE_DER];
		const message = handshake(11, [...u24(list.length), ...list]);
		const split = [...record(22, message.slice(0, 100)), ...record(22, message.slice(100))];
		expect(parseServerFlight(new Uint8Array(split)).state).toBe('certificate');
	});

	it('reads a fatal protocol_version or handshake_failure alert as a refusal', () => {
		expect(parseServerFlight(new Uint8Array(record(21, [2, 70]))).state).toBe('refused');
		expect(parseServerFlight(new Uint8Array(record(21, [2, 40]))).state).toBe('refused');
	});

	it('does not treat a warning alert as a refusal, and calls other fatal alerts unreadable', () => {
		const warningThenFlight = [...record(21, [1, 112]), ...serverFlight(FIXTURE_DER)];
		expect(parseServerFlight(new Uint8Array(warningThenFlight)).state).toBe('certificate');
		expect(parseServerFlight(new Uint8Array(record(21, [2, 80]))).state).toBe('unreadable');
	});

	it('calls non-TLS bytes and a flight with no certificate unreadable', () => {
		expect(parseServerFlight(new TextEncoder().encode('HTTP/1.1 400 Bad Request\r\n\r\n')).state).toBe('unreadable');
		const noCertificate = [...record(22, handshake(2, new Array(40).fill(0))), ...record(22, handshake(14, []))];
		expect(parseServerFlight(new Uint8Array(noCertificate)).state).toBe('unreadable');
	});

	it('rejects a certificate list whose lengths overrun the message', () => {
		const lying = handshake(11, [...u24(9000), ...u24(8000), 1, 2, 3]);
		expect(parseServerFlight(new Uint8Array(record(22, lying))).state).toBe('unreadable');
	});
});

describe('observeServedCertificate', () => {
	it('reports the served certificate, read from a flight that arrives in pieces', async () => {
		const flight = serverFlight(FIXTURE_DER);
		const socket = fakeSocket([flight.slice(0, 50), flight.slice(50, 200), flight.slice(200)]);
		const out = await observeServedCertificate('example.com', deps(socket));
		expect(out).toEqual({
			status: 'observed',
			issuer: FIXTURE_ISSUER,
			subject: FIXTURE_ISSUER,
			notBefore: '2026-11-16T20:16:52.000Z',
			notAfter: '2027-02-14T20:16:52.000Z',
			expiryBand: 'ok',
			daysRemaining: 75,
			serial: '0a1b2c3d4e5f',
			fingerprintSha256: FIXTURE_FINGERPRINT,
			source: 'handshake',
		});
		expect(socket.written).toHaveLength(1);
		expect(socket.written[0][0]).toBe(22);
		expect(socket.closeCalls).toBeGreaterThanOrEqual(1);
	});

	it('connects to the resolved IP literal, never to the host name', async () => {
		const seen: string[] = [];
		const socket = fakeSocket([serverFlight(FIXTURE_DER)]);
		await observeServedCertificate('example.com', deps(socket, { openSocket: async (a: string) => (seen.push(a), socket) }));
		expect(seen).toEqual([PUBLIC_IP]);
	});

	it('opens NO socket when the name resolves to a private address', async () => {
		let opened = 0;
		const socket = fakeSocket([]);
		for (const address of ['10.0.0.5', '127.0.0.1', '169.254.169.254', '::1']) {
			const out = await observeServedCertificate(
				'internal.example',
				deps(socket, { resolveAddresses: async () => [address], openSocket: async () => (opened++, socket) }),
			);
			expect(out).toEqual({ status: 'not_assessed', reason: 'no_public_address', source: 'handshake' });
		}
		expect(opened).toBe(0);
	});

	it('names each way of not reading a certificate', async () => {
		const reason = async (socket: ServedCertificateSocket, over: Record<string, unknown> = {}) => {
			const out = await observeServedCertificate('example.com', deps(socket, over));
			return out.status === 'not_assessed' ? out.reason : out.status;
		};
		expect(await reason(fakeSocket([]), { resolveAddresses: async () => Promise.reject(new Error('nxdomain')) })).toBe('no_public_address');
		expect(await reason(fakeSocket([], { openError: new Error('proxy request failed, cannot connect to the specified address') }))).toBe(
			'runtime_blocked_address',
		);
		expect(await reason(fakeSocket([], { openError: new Error('connection refused') }))).toBe('connect_failed');
		expect(await reason(fakeSocket([record(21, [2, 70])]))).toBe('tls12_refused');
		expect(await reason(fakeSocket([]))).toBe('handshake_unreadable');
		expect(await reason(fakeSocket([serverFlight(new Uint8Array([1, 2, 3, 4]))]))).toBe('certificate_unparseable');
		expect(await reason(fakeSocket([], { hang: true }), { timeoutMs: 30 })).toBe('timeout');
	});

	it('hangs up on a server that never answers', async () => {
		const socket = fakeSocket([], { hang: true });
		await observeServedCertificate('example.com', deps(socket, { timeoutMs: 30 }));
		expect(socket.closeCalls).toBeGreaterThanOrEqual(1);
	});

	it('stops reading a server that sends well-formed records forever', async () => {
		const filler = record(22, handshake(2, new Array(16000).fill(0)));
		const socket = fakeSocket([filler, filler, filler, filler, filler], { hang: true });
		const out = await observeServedCertificate('example.com', deps(socket, { timeoutMs: 2000 }));
		expect(out).toEqual({ status: 'not_assessed', reason: 'handshake_unreadable', source: 'handshake' });
	});
});
