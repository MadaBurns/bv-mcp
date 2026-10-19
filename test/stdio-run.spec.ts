// SPDX-License-Identifier: BUSL-1.1

/**
 * runStdioServer wires process.stdin / process.stdout to the JSON-RPC server. These specs drive it
 * through the exported entry point: stdin listeners are captured instead of attaching to a real
 * stream, so the data/end handlers can be fed chunks and the written output observed.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runStdioServer } from '../src/stdio';

type Listener = (...args: unknown[]) => void;

const originalConsoleLog = console.log;
const originalExitCode = process.exitCode;

let listeners: Map<string, Listener>;
let stdoutWrite: ReturnType<typeof vi.spyOn>;
let stderrWrite: ReturnType<typeof vi.spyOn>;

const initializeLine = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
const pingLine = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping', params: {} });

function writtenLines(): string[] {
	return (stdoutWrite.mock.calls as unknown[][]).map(([chunk]) => String(chunk));
}

function listener(event: string): Listener {
	const handler = listeners.get(event);
	if (!handler) throw new Error(`stdin listener for ${event} was not registered`);
	return handler;
}

beforeEach(() => {
	listeners = new Map();
	vi.spyOn(process.stdin, 'setEncoding').mockImplementation(() => process.stdin);
	vi.spyOn(process.stdin, 'resume').mockImplementation(() => process.stdin);
	vi.spyOn(process.stdin, 'on').mockImplementation(((event: string, handler: Listener) => {
		listeners.set(event, handler);
		return process.stdin;
	}) as unknown as typeof process.stdin.on);
	stdoutWrite = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
	stderrWrite = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
	vi.restoreAllMocks();
	console.log = originalConsoleLog;
	process.exitCode = originalExitCode;
});

describe('runStdioServer', () => {
	it('registers the stdin handlers, resumes the stream and routes console.log to stderr', async () => {
		await runStdioServer();

		expect(process.stdin.setEncoding).toHaveBeenCalledWith('utf8');
		expect(process.stdin.resume).toHaveBeenCalledTimes(1);
		expect([...listeners.keys()].sort()).toEqual(['data', 'end']);
		expect(console.log).not.toBe(originalConsoleLog);
	});

	it('answers each complete line of a data chunk and buffers the trailing partial line', async () => {
		await runStdioServer();
		const onData = listener('data');

		// CRLF-terminated initialize, a complete ping, and the first half of a second ping.
		onData(`${initializeLine}\r\n${pingLine}\n${pingLine.slice(0, 10)}`);
		await vi.waitFor(() => expect(writtenLines()).toHaveLength(2));

		const [initResponse, pingResponse] = writtenLines().map((line) => JSON.parse(line) as { id: number; result: unknown });
		expect(initResponse!.id).toBe(1);
		expect(pingResponse).toEqual({ jsonrpc: '2.0', id: 2, result: {} });
		expect(writtenLines().every((line) => line.endsWith('\n'))).toBe(true);

		// The remainder arrives in a later chunk and completes the buffered line.
		onData(`${pingLine.slice(10)}\n`);
		await vi.waitFor(() => expect(writtenLines()).toHaveLength(3));
		expect(JSON.parse(writtenLines()[2]!)).toEqual({ jsonrpc: '2.0', id: 2, result: {} });
	});

	it('writes nothing for a notification line', async () => {
		await runStdioServer();
		listener('data')(`${initializeLine}\n${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n${pingLine}\n`);

		await vi.waitFor(() => expect(writtenLines()).toHaveLength(2));
		expect(writtenLines().map((line) => (JSON.parse(line) as { id: number }).id)).toEqual([1, 2]);
	});

	it('flushes an unterminated final line when stdin ends', async () => {
		await runStdioServer();
		listener('data')(initializeLine);
		expect(writtenLines()).toHaveLength(0);

		listener('end')();
		await vi.waitFor(() => expect(writtenLines()).toHaveLength(1));
		expect((JSON.parse(writtenLines()[0]!) as { id: number }).id).toBe(1);

		// The buffer was cleared: a second end event has nothing left to flush.
		listener('end')();
		await new Promise((resolve) => setTimeout(resolve, 20));
		expect(writtenLines()).toHaveLength(1);
	});

	it('ignores stdin end when only whitespace remains buffered', async () => {
		await runStdioServer();
		listener('data')('   ');
		listener('end')();

		await new Promise((resolve) => setTimeout(resolve, 20));
		expect(writtenLines()).toHaveLength(0);
		expect(stderrWrite).not.toHaveBeenCalled();
	});

	it('reports a write failure on stderr, sets a failing exit code and keeps processing later lines', async () => {
		await runStdioServer();
		stdoutWrite.mockImplementationOnce(() => {
			throw new Error('EPIPE: broken pipe');
		});
		const onData = listener('data');

		onData(`${initializeLine}\n`);
		await vi.waitFor(() => expect(stderrWrite).toHaveBeenCalledWith('[blackveil-dns-mcp] EPIPE: broken pipe\n'));
		expect(process.exitCode).toBe(1);

		onData(`${pingLine}\n`);
		await vi.waitFor(() => expect(writtenLines()).toHaveLength(2));
	});

	it('uses a generic message when the failure is not an Error instance', async () => {
		await runStdioServer();
		stdoutWrite.mockImplementationOnce(() => {
			throw 'plain string failure';
		});

		listener('data')(`${initializeLine}\n`);
		await vi.waitFor(() => expect(stderrWrite).toHaveBeenCalledWith('[blackveil-dns-mcp] Unknown stdio server error\n'));
		expect(process.exitCode).toBe(1);
	});
});
