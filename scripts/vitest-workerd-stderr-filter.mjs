// Importable core of scripts/vitest-filter-workerd.mjs, split out so
// test/audits/vitest-workerd-stderr-filter.node.test.ts can exercise the
// filtering logic directly instead of only through a nested vitest spawn.
// Same shape as scripts/vitest-unhandled-error-filter.mjs. No behaviour
// change versus the inline version this replaced.
export const workerdPeerDisconnectPattern =
	/^exception = workerd\/api\/web-socket\.c\+\+:\d+: disconnected: WebSocket peer disconnected$/;

export function createFilteredWriter(target) {
	let pending = '';

	function writeLine(line) {
		if (workerdPeerDisconnectPattern.test(line.trim())) {
			return;
		}

		target.write(`${line}\n`);
	}

	return {
		write(chunk) {
			const text = pending + chunk.toString('utf8');
			const lines = text.split(/\r?\n/);
			pending = text.endsWith('\n') || text.endsWith('\r') ? '' : lines.pop() ?? '';

			for (const line of lines) {
				writeLine(line);
			}
		},
		flush() {
			if (pending.length > 0) {
				writeLine(pending);
				pending = '';
			}
		},
	};
}
