// SPDX-License-Identifier: BUSL-1.1
//
// Column contract for the access-log store (binding INTELLIGENCE_DB, database mcp-access-log-v1).
//
// ACCESS_LOG_INSERT_COLUMNS is a COPY of ACCESS_LOG_COLUMNS in src/mcp/execute.ts, in the same order: the
// 25 columns every live write path binds (inline insert, internal insert, queue consumer). It is a copy
// rather than an import because its two readers - the deploy preflight and the operator copy script - run
// under bare node, where execute.ts cannot load (it transitively imports cloudflare:workers).
// test/audits/access-log-schema.audit.test.ts pins it to accessLogInsertSql(), so a one-sided edit fails CI.
// This module must stay free of Node built-ins: that audit imports it inside the Workers test pool.

export const ACCESS_LOG_TABLE = 'mcp_access_log';
export const ACCESS_LOG_AUDIT_TABLE = 'mcp_access_log_audit';

export const ACCESS_LOG_INSERT_COLUMNS = Object.freeze([
	'ip_hash',
	'ip_masked',
	'tool_name',
	'domain',
	'country',
	'user_agent',
	'response_ms',
	'rate_limited',
	'ip_ciphertext',
	'ip_key_version',
	'city',
	'region',
	'latitude',
	'longitude',
	'asn',
	'as_org',
	'ptr_hostname',
	'key_hash',
	'client_type',
	'colo',
	'session_hash',
	'method',
	'transport',
	'status',
	'source',
]);

/** Every mcp_access_log column: the two table defaults the writers rely on, then the 25 written ones. */
export const ACCESS_LOG_COLUMNS = Object.freeze(['id', 'created_at', ...ACCESS_LOG_INSERT_COLUMNS]);

/** Every mcp_access_log_audit column. The forensics and erase routes in src/internal.ts write all but created_at. */
export const ACCESS_LOG_AUDIT_COLUMNS = Object.freeze(['id', 'created_at', 'actor', 'action', 'ip_hash', 'scope', 'outcome']);
