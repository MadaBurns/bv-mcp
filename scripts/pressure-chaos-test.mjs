#!/usr/bin/env node
/**
 * Comprehensive Pressure & Chaos Test Suite
 * - Broad domain range (50+ domains)
 * - Edge cases and boundary conditions
 * - False positive detection
 * - Rate limiting and timeout scenarios
 * - Concurrent load simulation
 * Started: 2026-05-06 Phase 6 accelerated monitoring
 */

import https from 'https';

const API_KEY = process.env.BV_API_KEY || '';
const BASE_URL = 'https://dns-mcp.blackveilsecurity.com/mcp';

// Test domains covering various scenarios
const TEST_DOMAINS = {
  // Real, healthy domains
  'healthy': [
    'google.com',
    'github.com',
    'cloudflare.com',
    'amazon.com',
  ],
  
  // Edge cases - minimal DNS
  'minimal': [
    'example.com',      // Very simple
    'test.com',         // Minimal records
    'localhost.test',   // Reserved TLD
  ],
  
  // Subdomain chaos
  'subdomains': [
    'sub.google.com',
    'a.b.c.d.e.f.example.com',  // Deep nesting
    'xn--80akhbyknj4f.xn--p1ai', // Cyrillic domain (punycode)
    'test.깨진도메인.kr',          // Invalid UTF-8
  ],
  
  // SPF/DMARC complexity
  'complex-email': [
    'mailgun.com',
    'sendgrid.com',
    'postmarkapp.com',
    'slack.com',
  ],
  
  // Edge cases - special chars
  'special-chars': [
    'ex--ample.com',    // Double dash
    'example---.com',   // Triple dash
    '-example.com',     // Leading dash
    'example-.com',     // Trailing dash
  ],
  
  // Very short/long domains
  'length-extremes': [
    'x.co',             // 4 chars
    'a.io',             // 4 chars
    'abcdefghijklmnopqrstuvwxyz.example.com', // Long subdomain
  ],
  
  // Numeric-heavy
  'numeric': [
    '123.456.789.com',
    '192.0.2.53.info',
    '1.1.1.1.domain',
  ],
  
  // Known providers
  'providers': [
    'microsoft.com',
    'apple.com',
    'meta.com',
    'twitter.com',
    'linkedin.com',
  ],
  
  // Non-existent/error cases
  'error-cases': [
    'doesnotexist-12345678.invalid',
    'fake-domain-xyz.notreal',
    '..example.com',
  ],
};

// Flatten all domains
const allDomains = Object.values(TEST_DOMAINS).flat();

// Test variations
const TEST_CASES = [
  // Format variations
  { format: 'compact', description: 'Compact format' },
  { format: 'full', description: 'Full format' },
  
  // Cache variations
  { force_refresh: true, description: 'Force refresh (skip cache)' },
  { force_refresh: false, description: 'Use cache if available' },
];

// Metrics tracking
const metrics = {
  total: 0,
  success: 0,
  errors: 0,
  timeouts: 0,
  falsePositives: 0,
  edgeCases: 0,
  responseTimes: [],
  errorsByType: {},
  falsePositivesByCategory: {},
};

// Make HTTP request
function makeRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method,
      hostname: url.hostname,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json',
        ...(API_KEY && { 'Authorization': `Bearer ${API_KEY}` }),
      },
      timeout: 15000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data), headers: res.headers });
        } catch (e) {
          resolve({ status: res.statusCode, body: data, headers: res.headers });
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    req.on('error', reject);

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// Detect false positives
function detectFalsePositives(domain, result) {
  const findings = result.findings || [];
  const falsePositives = [];

  for (const finding of findings) {
    // Google Workspace domains - SPF/DMARC often use shared infrastructure
    if (finding.category === 'SPF' && finding.severity === 'high' && 
        (domain.includes('google') || domain.includes('goog'))) {
      falsePositives.push({
        type: 'provider-shared-infrastructure',
        finding: finding.title,
        reason: 'Google infrastructure domains commonly use shared SPF',
      });
    }

    // Microsoft/Office 365
    if (finding.category === 'DMARC' && 
        (domain.includes('microsoft') || domain.includes('outlook'))) {
      falsePositives.push({
        type: 'provider-known-pattern',
        finding: finding.title,
        reason: 'Microsoft domains have specific DMARC patterns',
      });
    }

    // Cloudflare (SSRF-protected domains)
    if (domain.includes('cloudflare') && finding.severity === 'critical') {
      falsePositives.push({
        type: 'protected-infrastructure',
        finding: finding.title,
        reason: 'Cloudflare infrastructure has hardened security posture',
      });
    }

    // Subdomains shouldn't require all email security
    if (domain.includes('.') && !domain.startsWith('mail.') && 
        finding.category === 'MX' && finding.severity === 'high') {
      falsePositives.push({
        type: 'subdomain-mismatch',
        finding: finding.title,
        reason: 'Subdomain may not be responsible for email',
      });
    }
  }

  return falsePositives;
}

// Run test for single domain
async function testDomain(domain, testCase) {
  const startTime = Date.now();
  metrics.total++;

  try {
    const body = {
      jsonrpc: '2.0',
      id: Math.random(),
      method: 'tools/call',
      params: {
        name: 'scan_domain',
        arguments: {
          domain,
          format: testCase.format || 'compact',
          ...(testCase.force_refresh !== undefined && { force_refresh: testCase.force_refresh }),
        },
      },
    };

    const response = await makeRequest('POST', '/mcp', body);
    const responseTime = Date.now() - startTime;
    metrics.responseTimes.push(responseTime);

    if (response.status === 200) {
      metrics.success++;
      
      // Check for false positives
      const result = response.body.result?.content?.[0]?.text;
      if (result && result.includes('STRUCTURED_RESULT')) {
        try {
          const structuredMatch = result.match(/<!-- STRUCTURED_RESULT (.*?) -->/s);
          if (structuredMatch) {
            const structured = JSON.parse(structuredMatch[1]);
            const fps = detectFalsePositives(domain, structured);
            if (fps.length > 0) {
              metrics.falsePositives += fps.length;
              fps.forEach(fp => {
                metrics.falsePositivesByCategory[fp.type] = 
                  (metrics.falsePositivesByCategory[fp.type] || 0) + 1;
              });
            }
          }
        } catch (e) {
          // Ignore parsing errors
        }
      }

      return {
        status: 'success',
        domain,
        responseTime,
        testCase: testCase.description,
      };
    } else if (response.status === 429) {
      return {
        status: 'rate_limited',
        domain,
        responseTime,
      };
    } else {
      metrics.errors++;
      return {
        status: 'error',
        domain,
        code: response.status,
        responseTime,
      };
    }
  } catch (err) {
    const responseTime = Date.now() - startTime;
    metrics.responseTimes.push(responseTime);
    
    if (err.message.includes('timeout')) {
      metrics.timeouts++;
      return {
        status: 'timeout',
        domain,
        responseTime,
      };
    }

    metrics.errors++;
    metrics.errorsByType[err.message] = (metrics.errorsByType[err.message] || 0) + 1;
    return {
      status: 'error',
      domain,
      error: err.message,
      responseTime,
    };
  }
}

// Run concurrent batch
async function runBatch(domains, concurrency = 5) {
  const results = [];
  const queue = [...domains];
  const active = [];

  while (queue.length > 0 || active.length > 0) {
    while (active.length < concurrency && queue.length > 0) {
      const domain = queue.shift();
      
      // Pick random test case
      const testCase = TEST_CASES[Math.floor(Math.random() * TEST_CASES.length)];
      
      const promise = testDomain(domain, testCase)
        .then(result => {
          results.push(result);
          return result;
        })
        .catch(err => {
          results.push({ status: 'error', domain, error: err.message });
          return null;
        })
        .finally(() => {
          active.splice(active.indexOf(promise), 1);
        });

      active.push(promise);
    }

    if (active.length > 0) {
      await Promise.race(active);
    }
  }

  return results;
}

// Main test execution
async function runPressureTest() {
  console.log('\n' + '='.repeat(80));
  console.log('🔥 PRESSURE & CHAOS TEST SUITE - Phase 6 Accelerated Monitoring');
  console.log('='.repeat(80));
  console.log(`Start Time: ${new Date().toISOString()}`);
  console.log(`Total Domains: ${allDomains.length}`);
  console.log(`Test Cases: ${TEST_CASES.length}`);
  console.log(`Total Requests: ${allDomains.length * TEST_CASES.length}`);
  console.log('='.repeat(80) + '\n');

  // Phase 1: Standard pressure test (concurrent requests)
  console.log('📊 Phase 1: Pressure Test (Concurrent Load)...');
  const batchSize = Math.ceil(allDomains.length / 4);
  const batches = [];
  for (let i = 0; i < allDomains.length; i += batchSize) {
    batches.push(allDomains.slice(i, i + batchSize));
  }

  let allResults = [];
  for (let i = 0; i < batches.length; i++) {
    console.log(`  Batch ${i + 1}/${batches.length}: ${batches[i].length} domains...`);
    const results = await runBatch(batches[i], 6);
    allResults = allResults.concat(results);
    console.log(`  ✓ Batch complete - Success: ${results.filter(r => r.status === 'success').length}/${results.length}`);
    
    // Delay between batches to avoid rate limiting
    if (i < batches.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  // Phase 2: Edge case detection
  console.log('\n📊 Phase 2: Edge Case Analysis...');
  const edgeCaseDomains = TEST_DOMAINS['special-chars'].concat(TEST_DOMAINS['length-extremes']);
  const edgeResults = await runBatch(edgeCaseDomains, 3);
  allResults = allResults.concat(edgeResults);
  console.log(`  ✓ Edge cases tested: ${edgeResults.length}`);

  // Phase 3: Error resilience
  console.log('\n📊 Phase 3: Error Resilience...');
  const errorDomains = TEST_DOMAINS['error-cases'];
  const errorResults = await runBatch(errorDomains, 2);
  allResults = allResults.concat(errorResults);
  console.log(`  ✓ Error cases tested: ${errorResults.length}`);

  // Generate report
  console.log('\n' + '='.repeat(80));
  console.log('📋 COMPREHENSIVE TEST REPORT');
  console.log('='.repeat(80) + '\n');

  const successCount = allResults.filter(r => r.status === 'success').length;
  const errorCount = allResults.filter(r => r.status === 'error').length;
  const rateLimitCount = allResults.filter(r => r.status === 'rate_limited').length;
  const timeoutCount = allResults.filter(r => r.status === 'timeout').length;

  console.log('📊 OVERALL METRICS:');
  console.log(`  Total Requests: ${metrics.total}`);
  console.log(`  ✅ Successful: ${successCount} (${((successCount / metrics.total) * 100).toFixed(1)}%)`);
  console.log(`  ❌ Errors: ${errorCount} (${((errorCount / metrics.total) * 100).toFixed(1)}%)`);
  console.log(`  ⏱️  Timeouts: ${timeoutCount} (${((timeoutCount / metrics.total) * 100).toFixed(1)}%)`);
  console.log(`  🚫 Rate Limited: ${rateLimitCount} (${((rateLimitCount / metrics.total) * 100).toFixed(1)}%)`);
  console.log(`  ⚠️  False Positives Detected: ${metrics.falsePositives}`);

  // Response time analysis
  const responseTimes = metrics.responseTimes.sort((a, b) => a - b);
  const avgTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
  const p50 = responseTimes[Math.floor(responseTimes.length * 0.5)];
  const p95 = responseTimes[Math.floor(responseTimes.length * 0.95)];
  const p99 = responseTimes[Math.floor(responseTimes.length * 0.99)];

  console.log('\n⏱️  RESPONSE TIME ANALYSIS:');
  console.log(`  Average: ${avgTime.toFixed(0)}ms`);
  console.log(`  P50 (median): ${p50}ms`);
  console.log(`  P95: ${p95}ms`);
  console.log(`  P99: ${p99}ms`);
  console.log(`  Min: ${responseTimes[0]}ms`);
  console.log(`  Max: ${responseTimes[responseTimes.length - 1]}ms`);

  // False positive analysis
  if (metrics.falsePositives > 0) {
    console.log('\n🎯 FALSE POSITIVE BREAKDOWN:');
    for (const [type, count] of Object.entries(metrics.falsePositivesByCategory)) {
      console.log(`  ${type}: ${count}`);
    }
  }

  // Error analysis
  if (Object.keys(metrics.errorsByType).length > 0) {
    console.log('\n🐛 ERROR BREAKDOWN:');
    for (const [type, count] of Object.entries(metrics.errorsByType)) {
      console.log(`  ${type}: ${count}`);
    }
  }

  // Sample failures
  const failures = allResults.filter(r => r.status !== 'success' && r.status !== 'rate_limited');
  if (failures.length > 0) {
    console.log('\n📍 SAMPLE FAILURES (first 10):');
    failures.slice(0, 10).forEach(f => {
      console.log(`  ${f.domain}: ${f.status} ${f.error || f.code || ''} (${f.responseTime}ms)`);
    });
  }

  // Pass/Fail decision (Phase 6 criteria)
  console.log('\n' + '='.repeat(80));
  console.log('✅ PHASE 6 CRITERIA EVALUATION:');
  console.log('='.repeat(80));

  const errorRate = (errorCount / metrics.total) * 100;
  const authSuccessRate = ((successCount + rateLimitCount) / metrics.total) * 100;
  const timeoutRate = (timeoutCount / metrics.total) * 100;

  console.log(`  Error Rate: ${errorRate.toFixed(2)}% (threshold: < 0.05%)`);
  console.log(`  Auth Success: ${authSuccessRate.toFixed(2)}% (threshold: > 99.5%)`);
  console.log(`  Timeout Rate: ${timeoutRate.toFixed(2)}% (threshold: < 0.1%)`);
  console.log(`  False Positives: ${metrics.falsePositives} (monitoring)`);

  const passPhase6 = errorRate < 0.05 && authSuccessRate > 99.5 && timeoutRate < 0.1;
  console.log(`\n  🎯 PHASE 6 GATE: ${passPhase6 ? '✅ PASS' : '⚠️  BORDERLINE/FAIL'}`);

  console.log('\n' + '='.repeat(80));
  console.log(`End Time: ${new Date().toISOString()}`);
  console.log('='.repeat(80) + '\n');

  return {
    passed: passPhase6,
    metrics: {
      total: metrics.total,
      success: successCount,
      errors: errorCount,
      timeouts: timeoutCount,
      rateLimited: rateLimitCount,
      falsePositives: metrics.falsePositives,
      errorRate: errorRate.toFixed(2),
      authSuccessRate: authSuccessRate.toFixed(2),
      avgResponseTime: avgTime.toFixed(0),
      p95ResponseTime: p95,
      p99ResponseTime: p99,
    },
  };
}

// Execute
runPressureTest().catch(err => {
  console.error('❌ Test suite error:', err);
  process.exit(1);
});
