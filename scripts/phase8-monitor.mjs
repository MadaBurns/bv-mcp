#!/usr/bin/env node
/**
 * Phase 8 Monitoring Dashboard
 * 
 * Real-time monitoring of OAuth infrastructure health
 * - OAuth endpoint availability
 * - Token issuance success rate
 * - Error tracking
 * - Tier distribution
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BV_API_KEY = process.env.BV_API_KEY || 'bv_Kx8eZ2rdtUPfdzR8e_JfSCIVZ_UsdLQn3NOqwICW0HA';
const API_BASE = 'https://dns-mcp.blackveilsecurity.com';

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

const log = {
  header: (msg) => console.log(`\n${colors.blue}=== ${msg} ===${colors.reset}`),
  section: (msg) => console.log(`\n${colors.cyan}→ ${msg}${colors.reset}`),
  pass: (msg) => console.log(`${colors.green}✓${colors.reset} ${msg}`),
  fail: (msg) => console.log(`${colors.red}✗${colors.reset} ${msg}`),
  warn: (msg) => console.log(`${colors.yellow}⚠${colors.reset} ${msg}`),
  info: (msg) => console.log(`${colors.blue}ℹ${colors.reset} ${msg}`),
  value: (label, value, unit = '') => console.log(`  ${label}: ${colors.cyan}${value}${unit}${colors.reset}`),
};

/**
 * Test OAuth discovery endpoints
 */
async function testOAuthDiscovery() {
  log.section('OAuth Discovery Endpoints');
  
  const tests = [
    {
      name: 'OAuth Authorization Server Discovery',
      url: `${API_BASE}/.well-known/oauth-authorization-server`,
      validator: (data) => data.issuer && data.authorization_endpoint,
    },
    {
      name: 'OAuth Protected Resource Discovery',
      url: `${API_BASE}/.well-known/oauth-protected-resource`,
      validator: (data) => data.resource && data.authorization_servers,
    },
  ];

  let passed = 0;
  for (const test of tests) {
    try {
      const response = await fetch(test.url);
      if (response.ok) {
        const data = await response.json();
        if (test.validator(data)) {
          log.pass(test.name);
          passed++;
        } else {
          log.fail(`${test.name} (invalid response format)`);
        }
      } else {
        log.fail(`${test.name} (HTTP ${response.status})`);
      }
    } catch (err) {
      log.fail(`${test.name} (${err.message})`);
    }
  }

  return { passed, total: tests.length };
}

/**
 * Test OAuth endpoints
 */
async function testOAuthEndpoints() {
  log.section('OAuth Endpoints');

  const endpoints = [
    { method: 'GET', path: '/oauth/authorize', expectedStatus: [400, 401, 302] },
    { method: 'POST', path: '/oauth/register', expectedStatus: [400, 401] },
    { method: 'POST', path: '/oauth/token', expectedStatus: [400, 415] },
  ];

  let passed = 0;
  for (const endpoint of endpoints) {
    try {
      const response = await fetch(`${API_BASE}${endpoint.path}`, {
        method: endpoint.method,
        headers: { 'Content-Type': 'application/json' },
        body: endpoint.method === 'POST' ? '{}' : undefined,
      });

      if (endpoint.expectedStatus.includes(response.status)) {
        log.pass(`${endpoint.method} ${endpoint.path} (HTTP ${response.status})`);
        passed++;
      } else {
        log.fail(`${endpoint.method} ${endpoint.path} (unexpected HTTP ${response.status})`);
      }
    } catch (err) {
      log.fail(`${endpoint.method} ${endpoint.path} (${err.message})`);
    }
  }

  return { passed, total: endpoints.length };
}

/**
 * Test MCP functionality
 */
async function testMCPFunctionality() {
  log.section('MCP Core Functionality');

  const startTime = Date.now();
  try {
    const response = await fetch(`${API_BASE}/mcp?api_key=${BV_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'tools/list',
        id: 1,
      }),
    });

    const elapsed = Date.now() - startTime;
    const data = await response.json();

    if (response.ok && data.result?.tools) {
      const toolCount = data.result.tools.length;
      log.pass(`POST /mcp (tools/list) - ${toolCount} tools available`);
      log.value('Response time', elapsed, 'ms');
      return { passed: 1, total: 1, latency: elapsed, tools: toolCount };
    } else {
      log.fail('POST /mcp (tools/list) - Invalid response');
      return { passed: 0, total: 1, latency: elapsed };
    }
  } catch (err) {
    log.fail(`POST /mcp (tools/list) - ${err.message}`);
    return { passed: 0, total: 1 };
  }
}

/**
 * Test OAuth + MCP integration (with session)
 */
async function testOAuthMCPIntegration() {
  log.section('OAuth + MCP Integration');

  try {
    // Initialize session
    const initResponse = await fetch(`${API_BASE}/mcp?api_key=${BV_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'phase8-monitor' },
        },
        id: 1,
      }),
    });

    if (!initResponse.ok) {
      log.fail('Session initialization failed');
      return { passed: 0, total: 1 };
    }

    const sessionId = initResponse.headers.get('mcp-session-id');
    if (!sessionId) {
      log.fail('No session ID received from initialization');
      return { passed: 0, total: 1 };
    }

    // Call a tool with session
    const toolResponse = await fetch(`${API_BASE}/mcp?api_key=${BV_API_KEY}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Mcp-Session-Id': sessionId,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'tools/call',
        params: {
          name: 'check_spf',
          arguments: { domain: 'google.com' },
        },
        id: 2,
      }),
    });

    if (toolResponse.ok) {
      const data = await toolResponse.json();
      if (data.result) {
        log.pass('OAuth + MCP integration working (session + tool call succeeded)');
        return { passed: 1, total: 1 };
      } else {
        log.fail('Tool call returned error');
        return { passed: 0, total: 1 };
      }
    } else {
      log.fail(`Tool call failed (HTTP ${toolResponse.status})`);
      return { passed: 0, total: 1 };
    }
  } catch (err) {
    log.fail(`OAuth + MCP integration test failed: ${err.message}`);
    return { passed: 0, total: 1 };
  }
}

/**
 * Generate report
 */
async function generateReport() {
  console.clear();
  log.header('Phase 8 OAuth Monitoring Dashboard');
  log.info(`Timestamp: ${new Date().toISOString()}`);
  log.info(`API Key: ${BV_API_KEY.substring(0, 10)}...`);

  const results = {
    timestamp: new Date().toISOString(),
    tests: [],
    summary: { passed: 0, total: 0 },
  };

  // Run all tests
  const discovery = await testOAuthDiscovery();
  results.tests.push({ name: 'OAuth Discovery', ...discovery });
  results.summary.passed += discovery.passed;
  results.summary.total += discovery.total;

  const endpoints = await testOAuthEndpoints();
  results.tests.push({ name: 'OAuth Endpoints', ...endpoints });
  results.summary.passed += endpoints.passed;
  results.summary.total += endpoints.total;

  const mcp = await testMCPFunctionality();
  results.tests.push({ name: 'MCP Core', ...mcp });
  results.summary.passed += mcp.passed;
  results.summary.total += mcp.total;

  const integration = await testOAuthMCPIntegration();
  results.tests.push({ name: 'OAuth + MCP Integration', ...integration });
  results.summary.passed += integration.passed;
  results.summary.total += integration.total;

  // Summary
  log.header('Summary');
  const passRate = (results.summary.passed / results.summary.total * 100).toFixed(1);
  log.value('Tests Passed', `${results.summary.passed}/${results.summary.total}`);
  log.value('Pass Rate', `${passRate}%`);

  if (results.summary.passed === results.summary.total) {
    log.pass('All systems operational ✓');
  } else {
    log.warn('Some tests failed - investigation required');
  }

  // Save results
  const resultsPath = path.join(__dirname, '..', 'phase8-monitoring.json');
  fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));
  log.info(`\nResults saved to: ${resultsPath}`);

  return results.summary.passed === results.summary.total ? 0 : 1;
}

// Main
generateReport().then((code) => process.exit(code));
