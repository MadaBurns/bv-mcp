// SPDX-License-Identifier: BUSL-1.1

/**
 * C2 — blob12 priorTool dimension on tool_call events.
 *
 * Tests:
 *  (a) tool_call event carries blob12 with correct priorTool values:
 *      - first call in session → 'none'
 *      - second call in same session → prior tool name
 *      - session not found / no session → 'unknown'
 *  (b) the emit path adds NO awaited blocking call (no new storage dependency
 *      is awaited on the hot path — priorTool is resolved synchronously from
 *      in-memory session state, the same as the existing ACTIVE_SESSIONS map).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createAnalyticsClient } from '../src/lib/analytics';
import { readAndUpdateLastTool } from '../src/lib/session-memory';
import { ACTIVE_SESSIONS, resetSessions } from '../src/lib/session-memory';

beforeEach(() => {
	resetSessions();
});

// ---------------------------------------------------------------------------
// (a) blob12 priorTool values
// ---------------------------------------------------------------------------

describe('emitToolEvent blob12 priorTool', () => {
	it('is positioned at blob index 11 (blob12 in 1-based) and blobs total 12', () => {
		const ds = { writeDataPoint: vi.fn() };
		const client = createAnalyticsClient(ds);
		client.emitToolEvent({
			toolName: 'check_spf',
			status: 'pass',
			durationMs: 50,
			isError: false,
			priorTool: 'scan_domain',
		});
		const point = ds.writeDataPoint.mock.calls[0][0] as { blobs: string[]; doubles: number[] };
		expect(point.blobs).toHaveLength(12);
		expect(point.blobs[11]).toBe('scan_domain');
	});

	it('emits "none" for the first call in a session (priorTool = "none")', () => {
		const ds = { writeDataPoint: vi.fn() };
		const client = createAnalyticsClient(ds);
		client.emitToolEvent({
			toolName: 'scan_domain',
			status: 'pass',
			durationMs: 100,
			isError: false,
			priorTool: 'none',
		});
		const point = ds.writeDataPoint.mock.calls[0][0] as { blobs: string[] };
		expect(point.blobs[11]).toBe('none');
	});

	it('emits "unknown" when session continuity is unavailable', () => {
		const ds = { writeDataPoint: vi.fn() };
		const client = createAnalyticsClient(ds);
		client.emitToolEvent({
			toolName: 'check_dmarc',
			status: 'pass',
			durationMs: 80,
			isError: false,
			priorTool: 'unknown',
		});
		const point = ds.writeDataPoint.mock.calls[0][0] as { blobs: string[] };
		expect(point.blobs[11]).toBe('unknown');
	});

	it('defaults priorTool to "unknown" when not provided (backward-compatible)', () => {
		const ds = { writeDataPoint: vi.fn() };
		const client = createAnalyticsClient(ds);
		client.emitToolEvent({
			toolName: 'check_dmarc',
			status: 'pass',
			durationMs: 80,
			isError: false,
			// priorTool intentionally omitted
		});
		const point = ds.writeDataPoint.mock.calls[0][0] as { blobs: string[] };
		expect(point.blobs[11]).toBe('unknown');
	});

	it('preserves blobs[0..10] (existing positions) unchanged after adding blob12', () => {
		const ds = { writeDataPoint: vi.fn() };
		const client = createAnalyticsClient(ds);
		client.emitToolEvent({
			toolName: 'scan_domain',
			status: 'pass',
			durationMs: 200,
			domain: 'example.com',
			isError: false,
			score: 90,
			cacheStatus: 'hit',
			country: 'NZ',
			clientType: 'claude_code',
			authTier: 'developer',
			keyHash: 'k_abc123',
			ipHash: 'i_deadbeef',
			colo: 'AKL',
			priorTool: 'check_spf',
		});
		const point = ds.writeDataPoint.mock.calls[0][0] as { blobs: string[]; doubles: number[] };
		// Existing layout: [toolName, status, ok|error, domainFP, country, clientType, authTier, cacheStatus, keyHash, ipHash, colo]
		expect(point.blobs[0]).toBe('scan_domain');  // blob1 toolName
		expect(point.blobs[1]).toBe('pass');          // blob2 status
		expect(point.blobs[2]).toBe('ok');            // blob3 ok|error
		// blobs[3] = domainFingerprint (hashed)
		expect(point.blobs[4]).toBe('NZ');            // blob5 country
		expect(point.blobs[5]).toBe('claude_code');   // blob6 clientType
		expect(point.blobs[6]).toBe('developer');     // blob7 authTier
		expect(point.blobs[7]).toBe('hit');           // blob8 cacheStatus
		expect(point.blobs[8]).toBe('k_abc123');      // blob9 keyHash
		expect(point.blobs[9]).toBe('i_deadbeef');    // blob10 ipHash
		expect(point.blobs[10]).toBe('AKL');          // blob11 colo
		expect(point.blobs[11]).toBe('check_spf');    // blob12 priorTool (NEW)
		// doubles unchanged
		expect(point.doubles).toHaveLength(2);
		expect(point.doubles[0]).toBe(200);
		expect(point.doubles[1]).toBe(90);
	});
});

// ---------------------------------------------------------------------------
// (b) readAndUpdateLastTool — synchronous in-memory state, no async/blocking I/O
// ---------------------------------------------------------------------------

describe('readAndUpdateLastTool', () => {
	it('returns "none" for the first call in a session', () => {
		// Seed a session into ACTIVE_SESSIONS (as createSession does)
		const sessionId = 'a'.repeat(64);
		ACTIVE_SESSIONS.set(sessionId, { createdAt: Date.now(), lastAccessedAt: Date.now() });

		const prior = readAndUpdateLastTool(sessionId, 'scan_domain');
		expect(prior).toBe('none');
	});

	it('returns the previous tool name on the second call', () => {
		const sessionId = 'b'.repeat(64);
		ACTIVE_SESSIONS.set(sessionId, { createdAt: Date.now(), lastAccessedAt: Date.now() });

		readAndUpdateLastTool(sessionId, 'scan_domain');
		const prior = readAndUpdateLastTool(sessionId, 'check_spf');
		expect(prior).toBe('scan_domain');
	});

	it('correctly tracks a three-call sequence', () => {
		const sessionId = 'c'.repeat(64);
		ACTIVE_SESSIONS.set(sessionId, { createdAt: Date.now(), lastAccessedAt: Date.now() });

		const p1 = readAndUpdateLastTool(sessionId, 'scan_domain');
		const p2 = readAndUpdateLastTool(sessionId, 'check_spf');
		const p3 = readAndUpdateLastTool(sessionId, 'check_dmarc');
		expect(p1).toBe('none');
		expect(p2).toBe('scan_domain');
		expect(p3).toBe('check_spf');
	});

	it('returns "unknown" when the session does not exist in ACTIVE_SESSIONS', () => {
		const prior = readAndUpdateLastTool('missing-session-id', 'scan_domain');
		expect(prior).toBe('unknown');
	});

	it('returns "unknown" when sessionId is undefined or empty', () => {
		expect(readAndUpdateLastTool(undefined, 'scan_domain')).toBe('unknown');
		expect(readAndUpdateLastTool('', 'scan_domain')).toBe('unknown');
	});

	it('is synchronous — the function is not async and returns a string (not a Promise)', () => {
		const sessionId = 'd'.repeat(64);
		ACTIVE_SESSIONS.set(sessionId, { createdAt: Date.now(), lastAccessedAt: Date.now() });

		const result = readAndUpdateLastTool(sessionId, 'scan_domain');
		// If it returned a Promise, this check would fail
		expect(typeof result).toBe('string');
		expect(result instanceof Promise).toBe(false);
	});

	it('independent sessions track their own lastTool state', () => {
		const s1 = '1'.repeat(64);
		const s2 = '2'.repeat(64);
		ACTIVE_SESSIONS.set(s1, { createdAt: Date.now(), lastAccessedAt: Date.now() });
		ACTIVE_SESSIONS.set(s2, { createdAt: Date.now(), lastAccessedAt: Date.now() });

		readAndUpdateLastTool(s1, 'scan_domain');
		readAndUpdateLastTool(s2, 'check_spf');

		expect(readAndUpdateLastTool(s1, 'check_dmarc')).toBe('scan_domain');
		expect(readAndUpdateLastTool(s2, 'check_dmarc')).toBe('check_spf');
	});
});
