// SPDX-License-Identifier: BUSL-1.1

/** Pure, bounded SMTP reply parsing and STARTTLS-only session sequencing. */

const MAX_SESSION_BYTES = 64 * 1024;
const MAX_REPLY_BYTES = 16 * 1024;
const MAX_REPLY_LINES = 64;
const MAX_LINE_BYTES = 1_000;

export interface SmtpReply {
	code: number;
	lines: string[];
}

/** Classify one reply line (`NNN-text` continuation or `NNN text` final); throws on bad syntax or code range. */
function parseReplyLine(line: string): { code: number; final: boolean; text: string } {
	const match = /^(\d{3})([ -])(.*)$/u.exec(line);
	if (!match) throw new Error('Invalid SMTP reply syntax');
	const code = Number(match[1]);
	if (code < 200 || code > 599) throw new Error('Invalid SMTP reply code');
	return { code, final: match[2] === ' ', text: match[3] ?? '' };
}

/** Incremental CRLF SMTP reply parser with strict byte and line ceilings. */
export class SmtpReplyParser {
	private pending = '';
	private sessionBytes = 0;
	private replyBytes = 0;
	private replyCode: number | undefined;
	private replyLines: string[] = [];

	push(chunk: Uint8Array | string): SmtpReply[] {
		this.append(chunk);
		const replies: SmtpReply[] = [];
		for (;;) {
			const line = this.takeLine();
			if (line === undefined) break;
			const reply = this.acceptLine(line);
			if (reply) replies.push(reply);
		}
		return replies;
	}

	/** Buffer a chunk, enforcing the session and pending-reply byte ceilings. */
	private append(chunk: Uint8Array | string): void {
		const bytes = typeof chunk === 'string' ? new TextEncoder().encode(chunk) : chunk;
		this.sessionBytes += bytes.byteLength;
		if (this.sessionBytes > MAX_SESSION_BYTES) throw new RangeError('SMTP session reply limit exceeded');
		this.pending += new TextDecoder().decode(bytes);
		if (new TextEncoder().encode(this.pending).byteLength > MAX_REPLY_BYTES) throw new RangeError('SMTP reply limit exceeded');
	}

	/** Remove and return the next complete CRLF line; undefined (after validating the partial tail) when none is buffered. */
	private takeLine(): string | undefined {
		const lineEnd = this.pending.indexOf('\r\n');
		if (lineEnd < 0) {
			if (this.pending.includes('\n')) throw new Error('Invalid SMTP reply line ending');
			if (new TextEncoder().encode(this.pending).byteLength > MAX_LINE_BYTES) throw new RangeError('SMTP reply line limit exceeded');
			return undefined;
		}
		const line = this.pending.slice(0, lineEnd);
		this.pending = this.pending.slice(lineEnd + 2);
		return line;
	}

	/** Fold one line into the in-flight reply; returns the reply when this was its final line. */
	private acceptLine(line: string): SmtpReply | undefined {
		const lineBytes = new TextEncoder().encode(line).byteLength + 2;
		if (lineBytes > MAX_LINE_BYTES) throw new RangeError('SMTP reply line limit exceeded');
		const { code, final, text } = parseReplyLine(line);
		this.extendReply(code, text, lineBytes);
		return final ? this.completeReply(code) : undefined;
	}

	/** Append a parsed line to the in-flight reply, enforcing code continuity and the reply ceilings. */
	private extendReply(code: number, text: string, lineBytes: number): void {
		if (this.replyCode !== undefined && code !== this.replyCode) throw new Error('Invalid SMTP multiline reply code');
		this.replyCode = code;
		this.replyBytes += lineBytes;
		if (this.replyBytes > MAX_REPLY_BYTES) throw new RangeError('SMTP reply limit exceeded');
		this.replyLines.push(text);
		if (this.replyLines.length > MAX_REPLY_LINES) throw new RangeError('SMTP reply line count exceeded');
	}

	/** Emit the in-flight reply and reset reply state for the next one. */
	private completeReply(code: number): SmtpReply {
		const reply = { code, lines: [...this.replyLines] };
		this.replyCode = undefined;
		this.replyLines = [];
		this.replyBytes = 0;
		return reply;
	}

	finish(): void {
		if (this.pending.length > 0 || this.replyCode !== undefined) throw new Error('Incomplete SMTP reply');
	}
}

export type SmtpSessionState =
	'await_banner' | 'await_ehlo' | 'await_starttls' | 'await_tls' | 'await_secure_ehlo' | 'await_quit' | 'complete';

const EHLO_IDENTITY = 'scanner.invalid';

export type SmtpProbeCommand = `EHLO ${typeof EHLO_IDENTITY}\r\n` | 'STARTTLS\r\n' | 'QUIT\r\n';

export type SmtpSessionAction =
	| { type: 'send'; command: SmtpProbeCommand }
	| { type: 'upgrade_tls' }
	| { type: 'complete'; outcome: 'starttls_available' | 'starttls_unavailable' };

/**
 * Minimal state machine. Its command vocabulary is closed over greeting,
 * STARTTLS negotiation, and graceful disconnect; it has no message transaction
 * state or payload API.
 */
export class SmtpStarttlsStateMachine {
	private state: SmtpSessionState = 'await_banner';
	private outcome: 'starttls_available' | 'starttls_unavailable' | undefined;

	currentState(): SmtpSessionState {
		return this.state;
	}

	accept(reply: SmtpReply): SmtpSessionAction {
		switch (this.state) {
			case 'await_banner':
				if (reply.code !== 220) throw new Error('Invalid SMTP banner reply');
				this.state = 'await_ehlo';
				return { type: 'send', command: `EHLO ${EHLO_IDENTITY}\r\n` };
			case 'await_ehlo': {
				if (reply.code !== 250) throw new Error('Invalid SMTP greeting reply');
				const advertised = reply.lines.some((line) => /^STARTTLS(?:\s|$)/iu.test(line.trim()));
				if (advertised) {
					this.state = 'await_starttls';
					return { type: 'send', command: 'STARTTLS\r\n' };
				}
				this.outcome = 'starttls_unavailable';
				this.state = 'await_quit';
				return { type: 'send', command: 'QUIT\r\n' };
			}
			case 'await_starttls':
				if (reply.code !== 220) {
					this.outcome = 'starttls_unavailable';
					this.state = 'await_quit';
					return { type: 'send', command: 'QUIT\r\n' };
				}
				this.state = 'await_tls';
				return { type: 'upgrade_tls' };
			case 'await_secure_ehlo':
				if (reply.code !== 250) throw new Error('Invalid SMTP post-TLS greeting reply');
				this.outcome = 'starttls_available';
				this.state = 'await_quit';
				return { type: 'send', command: 'QUIT\r\n' };
			case 'await_quit':
				if (reply.code !== 221) throw new Error('Invalid SMTP disconnect reply');
				this.state = 'complete';
				return { type: 'complete', outcome: this.outcome ?? 'starttls_unavailable' };
			case 'await_tls':
				throw new Error('TLS upgrade must complete before another SMTP reply');
			case 'complete':
				throw new Error('SMTP session is already complete');
		}
	}

	tlsEstablished(): SmtpSessionAction {
		if (this.state !== 'await_tls') throw new Error('SMTP session is not awaiting TLS');
		this.state = 'await_secure_ehlo';
		return { type: 'send', command: `EHLO ${EHLO_IDENTITY}\r\n` };
	}
}
