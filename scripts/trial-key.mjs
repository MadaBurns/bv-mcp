#!/usr/bin/env node

/**
 * Trial API Key Management CLI
 *
 * Usage:
 *   node scripts/trial-key.mjs create --label "Customer X" [--tier developer] [--days 14] [--uses 1000]
 *   node scripts/trial-key.mjs status <hash>
 *   node scripts/trial-key.mjs revoke <hash>
 *   node scripts/trial-key.mjs list [--limit 100]
 *
 * Prerequisites:
 *   - wrangler CLI installed and authenticated
 *   - RATE_LIMIT KV namespace ID set in wrangler.jsonc (or pass --namespace-id)
 *
 * Environment variables:
 *   BV_KV_NAMESPACE_ID  — override KV namespace ID for RATE_LIMIT
 */

import { execSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { webcrypto } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const DEFAULTS = {
	tier: 'developer',
	days: 14,
	uses: 1000,
};

const MCP_URL = 'https://dns-mcp.blackveilsecurity.com/mcp';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getNamespaceId() {
	if (process.env.BV_KV_NAMESPACE_ID) return process.env.BV_KV_NAMESPACE_ID;

	// Try to extract from wrangler.jsonc
	try {
		// Try .dev/wrangler.deploy.jsonc first, then wrangler.jsonc
		for (const file of ['.dev/wrangler.deploy.jsonc', 'wrangler.jsonc']) {
			const fullPath = resolve(file);
			if (existsSync(fullPath)) {
				const content = readFileSync(fullPath, 'utf-8');
				// Strip JSON comments
				const stripped = content.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
				const config = JSON.parse(stripped);
				const binding = config.kv_namespaces?.find((ns) => ns.binding === 'RATE_LIMIT');
				if (binding?.id) return binding.id;
			}
		}
	} catch {
		// Fall through
	}

	console.error('Error: Could not determine RATE_LIMIT KV namespace ID.');
	console.error('Set BV_KV_NAMESPACE_ID env var or ensure wrangler.jsonc has the RATE_LIMIT binding.');
	process.exit(1);
}

async function hashToken(token) {
	const data = new TextEncoder().encode(token);
	const hashBuffer = await webcrypto.subtle.digest('SHA-256', data);
	return Array.from(new Uint8Array(hashBuffer))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

function kvGet(namespaceId, key) {
	try {
		return execSync(`npx wrangler kv key get --namespace-id=${namespaceId} --remote "${key}"`, {
			encoding: 'utf-8',
			stdio: ['pipe', 'pipe', 'pipe'],
		}).trim();
	} catch {
		return null;
	}
}

function kvPut(namespaceId, key, value, ttlSeconds) {
	const ttlArg = ttlSeconds ? `--ttl=${ttlSeconds}` : '';
	execSync(`npx wrangler kv key put --namespace-id=${namespaceId} --remote "${key}" '${value.replace(/'/g, "'\\'\''") }' ${ttlArg}`, {
		encoding: 'utf-8',
		stdio: ['pipe', 'pipe', 'pipe'],
	});
}

function kvDelete(namespaceId, key) {
	try {
		execSync(`npx wrangler kv key delete --namespace-id=${namespaceId} --remote "${key}" --force`, {
			encoding: 'utf-8',
			stdio: ['pipe', 'pipe', 'pipe'],
		});
		return true;
	} catch {
		return false;
	}
}

function kvList(namespaceId, prefix, limit = 100) {
	try {
		const output = execSync(`npx wrangler kv key list --namespace-id=${namespaceId} --remote --prefix="${prefix}" --limit=${limit}`, {
			encoding: 'utf-8',
			stdio: ['pipe', 'pipe', 'pipe'],
		});
		return JSON.parse(output);
	} catch {
		return [];
	}
}

function printClaudeDesktopConfig(rawKey) {
	const isWindows = process.platform === 'win32';
	const npxPath = isWindows ? 'npx' : '/opt/homebrew/bin/npx';

	console.log('\n📋 Claude Desktop config (add to claude_desktop_config.json):\n');
	console.log(
		JSON.stringify(
			{
				mcpServers: {
					'blackveil-dns': {
						command: npxPath,
						args: ['-y', 'mcp-remote', MCP_URL, '--header', `Authorization: Bearer ${rawKey}`],
					},
				},
			},
			null,
			2,
		),
	);

	console.log('\n📋 Claude Desktop native connector URL (Settings → Connectors):');
	console.log(`   ${MCP_URL}?api_key=${rawKey}`);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function cmdCreate(args) {
	const { values } = parseArgs({
		args,
		options: {
			label: { type: 'string', short: 'l' },
			tier: { type: 'string', short: 't', default: DEFAULTS.tier },
			days: { type: 'string', short: 'd', default: String(DEFAULTS.days) },
			uses: { type: 'string', short: 'u', default: String(DEFAULTS.uses) },
		},
		allowPositionals: false,
	});

	if (!values.label) {
		console.error('Error: --label is required');
		console.error('Usage: node scripts/trial-key.mjs create --label "Customer Name"');
		process.exit(1);
	}

	const tier = values.tier;
	const days = parseInt(values.days, 10);
	const maxUses = parseInt(values.uses, 10);

	if (!['free', 'agent', 'developer', 'enterprise', 'partner'].includes(tier)) {
		console.error(`Error: Invalid tier "${tier}". Must be one of: free, agent, developer, enterprise, partner`);
		process.exit(1);
	}
	if (isNaN(days) || days < 1 || days > 365) {
		console.error('Error: --days must be between 1 and 365');
		process.exit(1);
	}
	if (isNaN(maxUses) || maxUses < 1 || maxUses > 1_000_000) {
		console.error('Error: --uses must be between 1 and 1,000,000');
		process.exit(1);
	}

	const namespaceId = await getNamespaceId();

	// Generate 32 crypto-random bytes → 64-char hex key
	const bytes = new Uint8Array(32);
	webcrypto.getRandomValues(bytes);
	const rawKey = Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');

	const hash = await hashToken(rawKey);
	const now = Date.now();
	const expiresAt = now + days * 24 * 60 * 60 * 1000;

	const record = {
		tier,
		expiresAt,
		maxUses,
		currentUses: 0,
		label: values.label.slice(0, 200),
		createdAt: now,
	};

	const ttlSeconds = Math.ceil((expiresAt - now) / 1000) + 3600;
	kvPut(namespaceId, `trial:${hash}`, JSON.stringify(record), ttlSeconds);

	console.log('\n✅ Trial key created successfully!\n');
	console.log(`   Label:       ${record.label}`);
	console.log(`   Tier:        ${tier}`);
	console.log(`   Expires:     ${new Date(expiresAt).toISOString()} (${days} days)`);
	console.log(`   Max uses:    ${maxUses.toLocaleString()}`);
	console.log(`   Hash:        ${hash}`);
	console.log(`\n🔑 API Key (save this — it cannot be retrieved later):\n`);
	console.log(`   ${rawKey}`);

	printClaudeDesktopConfig(rawKey);
}

async function cmdStatus(args) {
	const hash = args[0];
	if (!hash || !/^[0-9a-f]{64}$/.test(hash)) {
		console.error('Error: Provide a valid 64-char hex hash');
		console.error('Usage: node scripts/trial-key.mjs status <hash>');
		process.exit(1);
	}

	const namespaceId = await getNamespaceId();
	const raw = kvGet(namespaceId, `trial:${hash}`);

	if (!raw) {
		console.log('Trial key not found (may have expired and been cleaned up).');
		process.exit(1);
	}

	const record = JSON.parse(raw);
	const now = Date.now();
	const expired = now >= record.expiresAt;
	const exhausted = record.currentUses >= record.maxUses;
	const usesRemaining = Math.max(0, record.maxUses - record.currentUses);
	const daysRemaining = Math.max(0, Math.ceil((record.expiresAt - now) / (24 * 60 * 60 * 1000)));

	console.log('\n📊 Trial Key Status\n');
	console.log(`   Hash:           ${hash}`);
	console.log(`   Label:          ${record.label}`);
	console.log(`   Tier:           ${record.tier}`);
	console.log(`   Created:        ${new Date(record.createdAt).toISOString()}`);
	console.log(`   Expires:        ${new Date(record.expiresAt).toISOString()}`);
	console.log(`   Uses:           ${record.currentUses} / ${record.maxUses}`);
	console.log(`   Status:         ${expired ? '❌ EXPIRED' : exhausted ? '❌ EXHAUSTED' : '✅ ACTIVE'}`);
	if (!expired && !exhausted) {
		console.log(`   Days remaining: ${daysRemaining}`);
		console.log(`   Uses remaining: ${usesRemaining}`);
	}
}

async function cmdRevoke(args) {
	const hash = args[0];
	if (!hash || !/^[0-9a-f]{64}$/.test(hash)) {
		console.error('Error: Provide a valid 64-char hex hash');
		console.error('Usage: node scripts/trial-key.mjs revoke <hash>');
		process.exit(1);
	}

	const namespaceId = await getNamespaceId();
	const deleted = kvDelete(namespaceId, `trial:${hash}`);

	if (deleted) {
		console.log(`✅ Trial key ${hash.slice(0, 16)}... revoked successfully.`);
	} else {
		console.log('Trial key not found (may have already been revoked or expired).');
	}
}

async function cmdList(args) {
	const { values } = parseArgs({
		args,
		options: {
			limit: { type: 'string', default: '100' },
		},
		allowPositionals: false,
	});

	const limit = Math.min(parseInt(values.limit, 10) || 100, 1000);
	const namespaceId = await getNamespaceId();
	const keys = kvList(namespaceId, 'trial:', limit);

	if (keys.length === 0) {
		console.log('No trial keys found.');
		return;
	}

	console.log(`\n📋 Trial Keys (${keys.length})\n`);

	for (const key of keys) {
		const hash = key.name.replace('trial:', '');
		const raw = kvGet(namespaceId, key.name);
		if (!raw) continue;

		const record = JSON.parse(raw);
		const now = Date.now();
		const expired = now >= record.expiresAt;
		const exhausted = record.currentUses >= record.maxUses;
		const status = expired ? 'EXPIRED' : exhausted ? 'EXHAUSTED' : 'ACTIVE';

		console.log(`   ${hash.slice(0, 16)}...  ${record.label.padEnd(30)}  ${record.tier.padEnd(12)}  ${record.currentUses}/${record.maxUses} uses  ${status}`);
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const command = process.argv[2];
const commandArgs = process.argv.slice(3);

switch (command) {
	case 'create':
		await cmdCreate(commandArgs);
		break;
	case 'status':
		await cmdStatus(commandArgs);
		break;
	case 'revoke':
		await cmdRevoke(commandArgs);
		break;
	case 'list':
		await cmdList(commandArgs);
		break;
	default:
		console.log(`
Trial API Key Management

Usage:
  node scripts/trial-key.mjs create --label "Customer Name" [--tier developer] [--days 14] [--uses 1000]
  node scripts/trial-key.mjs status <hash>
  node scripts/trial-key.mjs revoke <hash>
  node scripts/trial-key.mjs list [--limit 100]

Options for create:
  --label, -l   Customer/key label (required)
  --tier, -t    API tier: free, agent, developer, enterprise, partner (default: developer)
  --days, -d    Expiration in days (default: 14, max: 365)
  --uses, -u    Max tool invocations (default: 1000, max: 1,000,000)
`);
		process.exit(command ? 1 : 0);
}
