/**
 * BLACKVEIL Scanner — Core DNS/email security library
 * Exports reusable scan, check, validation, and scoring functions
 */

/**
 * BLACKVEIL Scanner npm package main entry point.
 * Exports all DNS/email security check tools, orchestrator, and scoring utilities.
 */

export * from './lib/sanitize';
export * from './lib/scoring';
export * from './lib/dns';

export * from './tools/check-spf';
export * from './tools/check-dmarc';
export * from './tools/check-dkim';
export * from './tools/check-dnssec';
export * from './tools/check-ssl';
export * from './tools/check-mta-sts';
export * from './tools/check-ns';
export * from './tools/check-caa';
export * from './tools/check-mx';
export * from './tools/explain-finding';
export * from './tools/scan-domain';
