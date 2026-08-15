/** Default hosted MCP endpoint for operator scripts. */
export const DEFAULT_MCP_ENDPOINT = 'https://dns-mcp.blackveilsecurity.com/mcp';

/** Resolve the endpoint while preserving the established BV_MCP_ENDPOINT override. */
export function resolveMcpEndpoint(environment = process.env) {
	return environment.BV_MCP_ENDPOINT || DEFAULT_MCP_ENDPOINT;
}
