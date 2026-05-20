// SPDX-License-Identifier: BUSL-1.1

import type { RootHintEntryEvidence } from './types';

export const ROOT_HINTS = [
	{
		name: 'a.root-servers.net',
		ipv4: '198.41.0.4',
		ipv6: '2001:503:ba3e::2:30',
		operator: 'Verisign',
	},
	{
		name: 'b.root-servers.net',
		ipv4: '170.247.170.2',
		ipv6: '2801:1b8:10::b',
		operator: 'USC-ISI',
	},
	{
		name: 'c.root-servers.net',
		ipv4: '192.33.4.12',
		ipv6: '2001:500:2::c',
		operator: 'Cogent',
	},
	{
		name: 'd.root-servers.net',
		ipv4: '199.7.91.13',
		ipv6: '2001:500:2d::d',
		operator: 'University of Maryland',
	},
	{
		name: 'e.root-servers.net',
		ipv4: '192.203.230.10',
		ipv6: '2001:500:a8::e',
		operator: 'NASA Ames',
	},
	{
		name: 'f.root-servers.net',
		ipv4: '192.5.5.241',
		ipv6: '2001:500:2f::f',
		operator: 'ISC',
	},
	{
		name: 'g.root-servers.net',
		ipv4: '192.112.36.4',
		ipv6: '2001:500:12::d0d',
		operator: 'US DoD NIC',
	},
	{
		name: 'h.root-servers.net',
		ipv4: '198.97.190.53',
		ipv6: '2001:500:1::53',
		operator: 'US Army Research Lab',
	},
	{
		name: 'i.root-servers.net',
		ipv4: '192.36.148.17',
		ipv6: '2001:7fe::53',
		operator: 'Netnod',
	},
	{
		name: 'j.root-servers.net',
		ipv4: '192.58.128.30',
		ipv6: '2001:503:c27::2:30',
		operator: 'Verisign',
	},
	{
		name: 'k.root-servers.net',
		ipv4: '193.0.14.129',
		ipv6: '2001:7fd::1',
		operator: 'RIPE NCC',
	},
	{
		name: 'l.root-servers.net',
		ipv4: '199.7.83.42',
		ipv6: '2001:500:9f::42',
		operator: 'ICANN',
	},
	{
		name: 'm.root-servers.net',
		ipv4: '202.12.27.33',
		ipv6: '2001:dc3::35',
		operator: 'WIDE Project',
	},
] as const satisfies readonly RootHintEntryEvidence[];

export const ROOT_SERVER_NAMES = ROOT_HINTS.map((root) => root.name);
