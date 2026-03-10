// SPDX-License-Identifier: MIT

/**
 * DNS query library using Cloudflare DNS-over-HTTPS (DoH).
 * All queries go through https://cloudflare-dns.com/dns-query
 * using the JSON wire format (application/dns-json).
 *
 * Workers-compatible: uses only fetch API, no Node.js APIs.
 */

export * from './dns-types';
export { DnsQueryError, queryDns } from './dns-transport';
export { type CaaRecord, checkDnssec, parseCaaRecord, queryCaaRecords, queryDnsRecords, queryMxRecords, queryTxtRecords } from './dns-records';
