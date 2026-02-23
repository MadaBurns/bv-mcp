/**
 * DNS query library using Cloudflare DNS-over-HTTPS (DoH).
 * All queries go through https://cloudflare-dns.com/dns-query
 * using the JSON wire format (application/dns-json).
 *
 * Workers-compatible: uses only fetch API, no Node.js APIs.
 */

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

/** Standard DNS record type codes */
export const RecordType = {
  A: 1,
  AAAA: 28,
  CNAME: 5,
  MX: 15,
  TXT: 16,
  NS: 2,
  SOA: 6,
  CAA: 257,
  TLSA: 52,
  DNSKEY: 48,
  DS: 43,
  RRSIG: 46,
} as const;

export type RecordTypeName = keyof typeof RecordType;

/** A single DNS answer record from the DoH JSON response */
export interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

/** A single DNS authority record */
export interface DnsAuthority {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

/** Cloudflare DoH JSON wire-format response */
export interface DohResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean; // Authenticated Data - true if DNSSEC validated
  CD: boolean;
  Question: Array<{ name: string; type: number }>;
  Answer?: DnsAnswer[];
  Authority?: DnsAuthority[];
}

/** Error thrown when a DNS query fails */
export class DnsQueryError extends Error {
  constructor(
    message: string,
    public readonly domain: string,
    public readonly recordType: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "DnsQueryError";
  }
}

/**
 * Query Cloudflare DoH for DNS records.
 *
 * @param domain - The domain name to query
 * @param type - DNS record type name (e.g. "TXT", "MX", "A")
 * @param dnssecCheck - If true, sets the CD=0 flag to request DNSSEC validation
 * @returns The full DoH JSON response
 */
export async function queryDns(
  domain: string,
  type: RecordTypeName,
  dnssecCheck = false,
): Promise<DohResponse> {
  const params = new URLSearchParams({
    name: domain,
    type,
    ...(dnssecCheck ? { cd: "0" } : {}),
  });

  const url = `${DOH_ENDPOINT}?${params.toString()}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/dns-json" },
    });
  } catch (err) {
    throw new DnsQueryError(
      `DNS query failed: ${err instanceof Error ? err.message : String(err)}`,
      domain,
      type,
    );
  }

  if (!response.ok) {
    throw new DnsQueryError(
      `DoH returned HTTP ${response.status}`,
      domain,
      type,
      response.status,
    );
  }

  const data: DohResponse = await response.json();
  return data;
}

/**
 * Query DNS and return just the answer data strings.
 * Returns an empty array if no answers are found.
 */
export async function queryDnsRecords(
  domain: string,
  type: RecordTypeName,
): Promise<string[]> {
  const resp = await queryDns(domain, type);
  return (resp.Answer ?? [])
    .filter((a) => a.type === RecordType[type])
    .map((a) => a.data);
}

/**
 * Query TXT records and strip surrounding quotes from values.
 * Cloudflare DoH returns TXT data with surrounding quotes.
 */
export async function queryTxtRecords(domain: string): Promise<string[]> {
  const records = await queryDnsRecords(domain, "TXT");
  return records.map((r) => r.replace(/^"|"$/g, ""));
}

/**
 * Check if a domain has valid DNSSEC by examining the AD (Authenticated Data) flag.
 * Returns true if the response was DNSSEC-validated.
 */
export async function checkDnssec(domain: string): Promise<boolean> {
  const resp = await queryDns(domain, "A", true);
  return resp.AD === true;
}

/**
 * Query MX records and parse them into priority + exchange pairs.
 */
export async function queryMxRecords(
  domain: string,
): Promise<Array<{ priority: number; exchange: string }>> {
  const records = await queryDnsRecords(domain, "MX");
  return records.map((r) => {
    const parts = r.split(" ");
    return {
      priority: parseInt(parts[0], 10),
      exchange: parts.slice(1).join(" ").replace(/\.$/, ""),
    };
  });
}

