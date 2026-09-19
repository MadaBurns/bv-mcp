// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS query library using Cloudflare DNS-over-HTTPS (DoH).
 * All queries go through https://cloudflare-dns.com/dns-query
 * using the JSON wire format (application/dns-json).
 *
 * Workers-compatible: uses only fetch API, no Node.js APIs.
 */

export * from './dns-types';
export { DnsQueryError, queryDns } from './dns-transport';
export {
	type CaaRecord,
	type DnsRecordsOutcome,
	type PtrRecord,
	type SrvRecord,
	type TlsaRecord,
	checkDnssec,
	parseCaaRecord,
	parseTlsaRecord,
	queryCaaRecords,
	queryDnsRecords,
	queryDnsRecordsWithRcode,
	queryMxRecords,
	queryPtrRecords,
	querySrvRecords,
	queryTxtRecords,
	queryTxtRecordsWithRcode,
} from './dns-records';
