// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';

/** DNS answer record from DoH response. */
export const DnsAnswerSchema = z.object({
	name: z.string(),
	type: z.number(),
	TTL: z.number().optional(),
	data: z.string(),
});

/** DNS authority record from DoH response. */
export const DnsAuthoritySchema = z.object({
	name: z.string(),
	type: z.number(),
	TTL: z.number().optional(),
	data: z.string(),
});

/** Complete DoH JSON response. Validates shape before casting. */
export const DohResponseSchema = z
	.object({
		Status: z.number().finite(),
		TC: z.boolean().optional(),
		RD: z.boolean().optional(),
		RA: z.boolean().optional(),
		AD: z.boolean().optional(),
		CD: z.boolean().optional(),
		Question: z.array(z.object({ name: z.string(), type: z.unknown() })).optional(),
		Answer: z.array(DnsAnswerSchema).optional(),
		Authority: z.array(DnsAuthoritySchema).optional(),
	})
	.passthrough();

/** Parsed CAA record. */
export const CaaRecordSchema = z.object({
	flags: z.number(),
	tag: z.string(),
	value: z.string(),
});

/** Parsed TLSA record. */
export const TlsaRecordSchema = z.object({
	usage: z.number(),
	selector: z.number(),
	matchingType: z.number(),
	certData: z.string(),
});

/** Parsed MX record. */
export const MxRecordSchema = z.object({
	priority: z.number(),
	exchange: z.string(),
});

/** Parsed SRV record. */
export const SrvRecordSchema = z.object({
	priority: z.number(),
	weight: z.number(),
	port: z.number(),
	target: z.string(),
});
