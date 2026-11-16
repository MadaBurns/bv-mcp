// SPDX-License-Identifier: BUSL-1.1

/**
 * Served-certificate observation for `check_ssl`: the issuer and expiry of the
 * certificate a host presents on port 443 right now.
 *
 * WHY THIS EXISTS. `metadata.certificate` describes the newest certificate in the
 * Certificate Transparency logs. That is the NEXT certificate whenever a renewal has
 * been issued but not deployed, and a different company's certificate whenever the
 * host is mid-migration between authorities. A consumer asking "which authority does
 * this site use" needs the one actually presented.
 *
 * VANTAGE. A raw TCP connection, not the browser probe: that probe's handshake is
 * re-signed by an intercepting proxy, so what it captures is not the origin's
 * certificate. A raw socket has no such layer.
 *
 * WHERE IT RUNS. Only in the infra-probe sidecar, beside the other raw-socket lanes.
 * The main Worker and the published package reach it through
 * `served-certificate-client.ts` and must never import this module: it would pull the
 * socket API into bundles that have none.
 *
 * STRICTLY NON-SCORING. The caller attaches the block as `metadata.servedCertificate`;
 * nothing here builds a `Finding`, so an unreachable host or a refused handshake
 * cannot move a grade.
 *
 * NOT ASSESSED IS A RESULT. Every path that did not read a certificate reports
 * `status: 'not_assessed'` with a reason. The block is never omitted and never
 * defaulted, because "we could not look" and "nothing is there" are different claims.
 *
 * SSRF. The host name is resolved once through the trusted resolver, every answer must
 * be globally routable, and the socket connects to that IP literal. The name itself is
 * only ever sent as SNI.
 */

import { assessExpiry } from '@blackveil/dns-checks';
import { isGloballyRoutableIp, resolvePublicNameserverAddresses } from './authoritative-dns-infra/dns-tcp';
import { buildClientHello, decodeCertificate, parseServerFlight } from './served-certificate-wire';
import type { ServedCertificateBlock, ServedCertificateNotAssessedReason } from './served-certificate-types';

const HTTPS_PORT = 443;
/** One deadline for resolve, connect and read together. */
export const SERVED_CERTIFICATE_TIMEOUT_MS = 3_000;
/** A leaf plus chain is a few kilobytes; anything past this is not a handshake worth reading. */
const MAX_FLIGHT_BYTES = 65_536;

export type { ServedCertificateBlock, ServedCertificateNotAssessedReason } from './served-certificate-types';

/** The slice of a `cloudflare:sockets` Socket this module uses. */
export interface ServedCertificateSocket {
	opened: Promise<unknown>;
	closed: Promise<unknown>;
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	close(): Promise<void>;
}

export interface ServedCertificateDeps {
	/** Returns SSRF-checked public IP literals for the host, or throws. */
	resolveAddresses?: (host: string, timeoutMs: number) => Promise<string[]>;
	/** Opens a plain TCP socket to an IP literal on port 443. */
	openSocket?: (pinnedAddress: string) => Promise<ServedCertificateSocket>;
	nowSeconds?: number;
	timeoutMs?: number;
}

class ProbeFailure extends Error {
	constructor(readonly reason: ServedCertificateNotAssessedReason) {
		super(reason);
	}
}

const defaultOpenSocket = async (pinnedAddress: string): Promise<ServedCertificateSocket> => {
	let connect: (typeof import('cloudflare:sockets'))['connect'];
	try {
		// Behind a dynamic import so Node-side tooling can load this module.
		({ connect } = await import('cloudflare:sockets'));
	} catch {
		throw new ProbeFailure('socket_unavailable');
	}
	const socket = connect({ hostname: pinnedAddress, port: HTTPS_PORT }, { secureTransport: 'off', allowHalfOpen: false });
	void socket.closed.catch(() => undefined);
	return socket;
};

function not(reason: ServedCertificateNotAssessedReason): ServedCertificateBlock {
	return { status: 'not_assessed', reason, source: 'handshake' };
}

function toIso(epochSeconds: number | null): string | null {
	return epochSeconds == null ? null : new Date(epochSeconds * 1000).toISOString();
}

function classifyConnectError(err: unknown): ServedCertificateNotAssessedReason {
	if (err instanceof ProbeFailure) return err.reason;
	// The runtime's message for an address it will not open a socket to.
	return /cannot connect to the specified address/i.test(String((err as Error)?.message ?? err)) ? 'runtime_blocked_address' : 'connect_failed';
}

/** Read the server's first flight until the Certificate message is complete. */
async function readLeaf(socket: ServedCertificateSocket, hello: Uint8Array): Promise<Uint8Array> {
	try {
		await socket.opened;
	} catch (err) {
		throw new ProbeFailure(classifyConnectError(err));
	}
	const writer = socket.writable.getWriter();
	try {
		await writer.write(hello);
	} catch {
		throw new ProbeFailure('connect_failed');
	} finally {
		writer.releaseLock();
	}

	const reader = socket.readable.getReader();
	let buffered: Uint8Array = new Uint8Array(0);
	try {
		while (buffered.length <= MAX_FLIGHT_BYTES) {
			const { value, done } = await reader.read();
			if (value?.length) {
				const next = new Uint8Array(buffered.length + value.length);
				next.set(buffered, 0);
				next.set(value, buffered.length);
				buffered = next;
				const flight = parseServerFlight(buffered);
				if (flight.state === 'certificate') return flight.leafDer;
				if (flight.state === 'refused') throw new ProbeFailure('tls12_refused');
				if (flight.state === 'unreadable') throw new ProbeFailure('handshake_unreadable');
			}
			if (done) break;
		}
		throw new ProbeFailure('handshake_unreadable');
	} catch (err) {
		if (err instanceof ProbeFailure) throw err;
		throw new ProbeFailure('handshake_unreadable');
	} finally {
		await reader.cancel().catch(() => undefined);
		reader.releaseLock();
	}
}

async function describeLeaf(leafDer: Uint8Array, nowSeconds: number): Promise<ServedCertificateBlock> {
	const decoded = decodeCertificate(leafDer);
	if (!decoded) return not('certificate_unparseable');
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(leafDer)));
	const expiry = assessExpiry(decoded.notAfter, nowSeconds);
	return {
		status: 'observed',
		issuer: decoded.issuer,
		subject: decoded.subject,
		notBefore: toIso(decoded.notBefore),
		notAfter: toIso(decoded.notAfter),
		expiryBand: expiry.band,
		daysRemaining: expiry.daysRemaining,
		serial: decoded.serial,
		fingerprintSha256: [...digest].map((b) => b.toString(16).padStart(2, '0')).join(''),
		source: 'handshake',
	};
}

async function probe(
	host: string,
	deps: ServedCertificateDeps,
	timeoutMs: number,
	onSocket: (socket: ServedCertificateSocket) => void,
): Promise<ServedCertificateBlock> {
	let address: string | undefined;
	try {
		const resolve = deps.resolveAddresses ?? ((h, t) => resolvePublicNameserverAddresses(h, undefined, t));
		const addresses = await resolve(host, timeoutMs);
		// IPv4 first: it is the address family an ordinary visitor is most likely to reach.
		address = addresses.find((a) => !a.includes(':')) ?? addresses[0];
	} catch {
		return not('no_public_address');
	}
	// Re-checked here so an injected resolver can never widen what the socket may reach.
	if (!address || !isGloballyRoutableIp(address)) return not('no_public_address');

	let socket: ServedCertificateSocket;
	try {
		socket = await (deps.openSocket ?? defaultOpenSocket)(address);
	} catch (err) {
		return not(classifyConnectError(err));
	}
	onSocket(socket);
	try {
		const hello = buildClientHello(host, crypto.getRandomValues(new Uint8Array(32)));
		const leafDer = await readLeaf(socket, hello);
		return await describeLeaf(leafDer, deps.nowSeconds ?? Math.floor(Date.now() / 1000));
	} catch (err) {
		return not(err instanceof ProbeFailure ? err.reason : 'handshake_unreadable');
	} finally {
		await socket.close().catch(() => undefined);
	}
}

/**
 * Observe the certificate `host` serves on port 443. Never throws: every failure is a
 * `not_assessed` block with its reason.
 */
export async function observeServedCertificate(host: string, deps: ServedCertificateDeps = {}): Promise<ServedCertificateBlock> {
	const timeoutMs = deps.timeoutMs ?? SERVED_CERTIFICATE_TIMEOUT_MS;
	let timer: ReturnType<typeof setTimeout> | undefined;
	let opened: ServedCertificateSocket | undefined;
	try {
		return await Promise.race([
			probe(host, deps, timeoutMs, (socket) => {
				opened = socket;
			}),
			new Promise<ServedCertificateBlock>((resolve) => {
				timer = setTimeout(() => {
					// Hang up, so a slow server cannot hold the connection past the deadline.
					void opened?.close().catch(() => undefined);
					resolve(not('timeout'));
				}, timeoutMs);
			}),
		]);
	} catch {
		return not('handshake_unreadable');
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}
