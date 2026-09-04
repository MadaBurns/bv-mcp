// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';

describe('bounded SMTP reply parser', () => {
	it('parses fragmented multiline replies', async () => {
		const { SmtpReplyParser } = await import('../src/lib/smtp-starttls-protocol');
		const parser = new SmtpReplyParser();
		expect(parser.push('250-example.com\r\n250-PIPE')).toEqual([]);
		expect(parser.push('LINING\r\n250 STARTTLS\r\n')).toEqual([{ code: 250, lines: ['example.com', 'PIPELINING', 'STARTTLS'] }]);
		parser.finish();
	});

	it('rejects malformed line endings, mixed reply codes, oversized lines and incomplete replies', async () => {
		const { SmtpReplyParser } = await import('../src/lib/smtp-starttls-protocol');
		expect(() => new SmtpReplyParser().push('220 hello\n')).toThrow('line ending');
		const mixed = new SmtpReplyParser();
		mixed.push('250-first\r\n');
		expect(() => mixed.push('550 second\r\n')).toThrow('multiline reply code');
		expect(() => new SmtpReplyParser().push(`220 ${'x'.repeat(1_100)}\r\n`)).toThrow('line limit');
		const incomplete = new SmtpReplyParser();
		incomplete.push('250-more\r\n');
		expect(() => incomplete.finish()).toThrow('Incomplete SMTP reply');
	});
});

describe('STARTTLS-only state machine', () => {
	it('allows only greeting, STARTTLS, post-TLS greeting and graceful disconnect', async () => {
		const { SmtpStarttlsStateMachine } = await import('../src/lib/smtp-starttls-protocol');
		const session = new SmtpStarttlsStateMachine();
		const actions = [
			session.accept({ code: 220, lines: ['ready'] }),
			session.accept({ code: 250, lines: ['mx.example.com', 'STARTTLS'] }),
			session.accept({ code: 220, lines: ['begin TLS'] }),
			session.tlsEstablished(),
			session.accept({ code: 250, lines: ['mx.example.com'] }),
			session.accept({ code: 221, lines: ['bye'] }),
		];
		const commands = actions.flatMap((action) => (action.type === 'send' ? [action.command.trim()] : []));
		const forbidden = [`M${'AIL'} FROM`, `R${'CPT'} TO`, `D${'ATA'}`];

		expect(commands).toEqual(['EHLO scanner.invalid', 'STARTTLS', 'EHLO scanner.invalid', 'QUIT']);
		expect(commands.some((command) => forbidden.some((token) => command.startsWith(token)))).toBe(false);
		expect(actions.at(-1)).toEqual({ type: 'complete', outcome: 'starttls_available' });
	});

	it('disconnects without attempting TLS when the capability is absent', async () => {
		const { SmtpStarttlsStateMachine } = await import('../src/lib/smtp-starttls-protocol');
		const session = new SmtpStarttlsStateMachine();
		session.accept({ code: 220, lines: ['ready'] });
		expect(session.accept({ code: 250, lines: ['PIPELINING'] })).toEqual({ type: 'send', command: 'QUIT\r\n' });
		expect(session.accept({ code: 221, lines: ['bye'] })).toEqual({ type: 'complete', outcome: 'starttls_unavailable' });
	});

	it('requires the TLS boundary before accepting the secure greeting', async () => {
		const { SmtpStarttlsStateMachine } = await import('../src/lib/smtp-starttls-protocol');
		const session = new SmtpStarttlsStateMachine();
		session.accept({ code: 220, lines: ['ready'] });
		session.accept({ code: 250, lines: ['STARTTLS'] });
		session.accept({ code: 220, lines: ['begin TLS'] });
		expect(() => session.accept({ code: 250, lines: ['premature'] })).toThrow('TLS upgrade must complete');
	});
});
