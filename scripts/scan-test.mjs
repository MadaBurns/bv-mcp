// Quick regression scan against local dev server
const EP = 'http://localhost:8787/mcp';

async function rpc(method, params, sessionId) {
	const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
	if (sessionId) headers['Mcp-Session-Id'] = sessionId;
	const res = await fetch(EP, {
		method: 'POST',
		headers,
		body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
	});
	const sid = res.headers.get('mcp-session-id') || sessionId;
	const body = await res.json();
	return { result: body.result, error: body.error, sessionId: sid };
}

async function scanDomain(domain) {
	const init = await rpc('initialize', {
		protocolVersion: '2025-03-26',
		capabilities: {},
		clientInfo: { name: 'scan-test', version: '1.0.0' },
	});
	const scan = await rpc('tools/call', { name: 'scan_domain', arguments: { domain } }, init.sessionId);
	if (scan.error) return `ERROR: ${scan.error.message}`;
	const text = scan.result?.content?.[0]?.text || '';
	const lines = text.split('\n').slice(0, 8);
	return lines.join('\n');
}

const domains = ['cloudflare.com', 'google.com', 'github.com'];
for (const d of domains) {
	console.log('\n' + '='.repeat(50));
	console.log(`Scanning: ${d}`);
	console.log('='.repeat(50));
	try {
		console.log(await scanDomain(d));
	} catch (e) {
		console.error(`Error: ${e.message}`);
	}
}
