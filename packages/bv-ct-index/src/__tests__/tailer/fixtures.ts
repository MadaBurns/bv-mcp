// SPDX-License-Identifier: BUSL-1.1
/**
 * Real CT log data for the tailer tests, captured 2026-10-17 by SQ-342 (capture scripts and raw
 * evidence: sidequest verification/SQ-342/). Expected values come from an independent parse of the same certificates
 * with node:crypto X509Certificate, not from the tailer's own DER walker.
 *
 * Certificates in CT logs are public records. Only the tailer-relevant facts are restated in plain text.
 */

/** RFC 6962 get-entries leaf_input: a precert entry. DigiCert Wyvern2027h1, leaf index 258023333. */
export const RFC6962_PRECERT_LEAF_INPUT =
	'AAAAAAGhSHgecQABxwyjb5aN7tSRWj02XSZa2cKGLxXLdKHUBfLT/7twjhQAAiEwggIdoAMCAQICEQDfJ6NpdRl92I7IBUZb22uiMAoGCCqGSM49BAMCMEYxCzAJBgNVBAYTAkFUMRUwEwYDVQQKEwxaZXJvU1NMIEdtYkgxIDAeBgNVBAMTF1plcm9TU0wgRUNDIERWIFNTTCBDQSAyMB4XDTI2MTAxNzAwMDAwMFoXDTI3MDExNTIzNTk1OVowEzERMA8GA1UEAxMINGY2ay5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT5ZsMmJ5m5yQrpNpfRJOLMpNDOYhjxFFSTB9deCpjjHZWMlqsW1bzMN91F2pc0MJtyJ9Mvz459Jaj5HTjvuFm0o4IBHTCCARkwHwYDVR0jBBgwFoAUlEWf2lFHcdVzrqwdqwhyEm2tfGIwHQYDVR0OBBYEFK2CUKSJUxX/uAySCa5TnspecxcZMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBMGA1UdIAQMMAowCAYGZ4EMAQIBMG4GCCsGAQUFBwEBBGIwYDA5BggrBgEFBQcwAoYtaHR0cDovL2NydC5zZWN0aWdvLmNvbS9aZXJvU1NMRUNDRFZTU0xDQTIuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAfBgNVHREEGDAWggg0ZjZrLmNvbYIKKi40ZjZrLmNvbQAA';
export const RFC6962_PRECERT_FACTS = {
	names: ['4f6k.com', '*.4f6k.com'],
	notBefore: 1792195200,
	notAfter: 1800057599,
	issuer: 'ZeroSSL ECC DV SSL CA 2',
	apexes: ['4f6k.com'],
};

/** RFC 6962 get-entries leaf_input: an x509 (final certificate) entry, which the tailer skips. Same log, leaf index 258023326. */
export const RFC6962_X509_LEAF_INPUT =
	'AAAAAAGhSHgd+wAAAAOUMIIDkDCCAxagAwIBAgISBuKyKrAAKXHwXWFtfSLg5segMAoGCCqGSM49BAMDMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQDEwNZRTIwHhcNMjYxMDE3MDQxODUwWhcNMjcwMTE1MDQxODQ5WjAcMRowGAYDVQQDExF5b3V0dWJlY2hhbmVscy5waDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHt1IoWyUpPxkcYnMQCDSRtV44IUMp7jd6yjbHN4qmArCVqQEmQ9tAU0uVmk9Izscv0dJaPQVkMwYP61krKp59+jggIfMIICGzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUtf+g8+hlIwudCK3lFg8CwiZib9QwHwYDVR0jBBgwFoAUuVnyjs8i8IbTN0j/dhQYuoLYVYcwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzAChhdodHRwOi8veWUyLmkubGVuY3Iub3JnLzAcBgNVHREEFTATghF5b3V0dWJlY2hhbmVscy5waDATBgNVHSAEDDAKMAgGBmeBDAECATAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8veWUyLmMubGVuY3Iub3JnLzMzLmNybDCCAQwGCisGAQQB1nkCBAIEgf0EgfoA+AB3AExj3JjlnB2riPYeij3ero+rRKM3e1+blMP7oZz8wb4mAAABoUhLDO4AAAQDAEgwRgIhAJFF2LudAGKNG4Y6AoDT6q1Odf6uXkIbRIvj34MkgOreAiEAwhTmVa0PF0NdT3qQK9ZRFmj02cPDy+6kISCR052a1H8AfQBZbmwzhpSyWXKiVsig6N2QSnboCD3ahzsBCDgoFDzuWQAAAaFISw03AAgAAAUADvDSXwQDAEYwRAIgMQoIdRxxQs9Dbd838Vo5BJ73ZaB4Vx6uvJrxZ5E2IFQCIGCWt4iuniFgnBdMwIAf5KO0Vts2CdmMDZyv9blvnZK7MAoGCCqGSM49BAMDA2gAMGUCMHUur9B/H3lfyIwqETEecTP4fUzRgrL7mwG4pxeugNnou3o6at1aJmkpIQrwh6WD1wIxAPQqz2MjYUOKVYHUEhZe29VlYfEvCWdwEasnuFaI1048/FPH8eIGBjfvmwQlTOs9vQAA';

/** One static-ct-api TileLeaf (base64): a precert entry. Let's Encrypt Willow2027h1, leaf index 639113519. */
export const STATIC_PRECERT_TILE_LEAF =
	'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';
export const STATIC_PRECERT_FACTS = {
	names: [
		'*.bluemoonstudio.au',
		'totallyrenewableyack.org.au',
		'www.totallyrenewableyack.bluemoonstudio.au',
		'www.totallyrenewableyack.org.au',
	],
	notBefore: 1792213443,
	notAfter: 1799989442,
	issuer: 'YR2',
	apexes: ['bluemoonstudio.au', 'totallyrenewableyack.org.au'],
};

/** One static-ct-api TileLeaf (base64): an x509 entry. Let's Encrypt Willow2027h1, leaf index 639114242. */
export const STATIC_X509_TILE_LEAF =
	'AAABoUh0hr8AAAADqjCCA6YwggNMoAMCAQICEQDw2YcD4UHPmxNQSlRL7hNZMAoGCCqGSM49BAMCMDsxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3QgU2VydmljZXMxDDAKBgNVBAMTA1dFMTAeFw0yNjEwMTcwNDQwMjJaFw0yNzAxMTUwNTQwMTlaMC4xLDAqBgNVBAMTI3d3dy5wcm9mZWNhcmxvc2Zvb3RiYWxsdHJhaW5pbmcuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENyrX/LNckFNnUNrFEq+oWl0hO3Wr+bOZO3pufrc+mQAz8X7gj2Ccr5JATdpIAkBwKSPSeWYK8v58FCgWmhI9CqOCAjwwggI4MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTKzynkRAOCj6BRXuree/7L4yXrkjAfBgNVHSMEGDAWgBSQd5I1Z8T/qMyp5nvZgHl7zJP5ODA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAKGGWh0dHA6Ly9pLnBraS5nb29nL3dlMS5jcnQwLgYDVR0RBCcwJYIjd3d3LnByb2ZlY2FybG9zZm9vdGJhbGx0cmFpbmluZy5jb20wEwYDVR0gBAwwCjAIBgZngQwBAgEwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2MucGtpLmdvb2cvd2UxL0V4YnJFREItWTFVLmNybDCCAQ0GCisGAQQB1nkCBAIEgf4EgfsA+QB3AGBMmq96f3dfAdQG/JINyJnrCxx9+MlSG/r6F3c7l4vJAAABoUhgJywAAAQDAEgwRgIhAOAPR8FvRg1sSSrsIRUVxmv/1ns4I54HthOhlVYPSqmiAiEAy2KcC9LVMIo5RFQ7ZPXFj8PkMcw15nH3uyhyJ0vXQaYAfgBE6CL8K6sOku7Q6frWlmRgJ3bQF2DgiQUJySOhsD/DfwAAAaFIYBqPAAgAAAUAC6d45wQDAEcwRQIgTzCxCcwyVS9gFS+Oo8pSJrNQysxmosJiwROrY1xISvcCIQDq2n8rt00YsSbjopBHgDv/Q9Iqem34w0mMnn6ahLmZxzAKBggqhkjOPQQDAgNIADBFAiEAkTiCXL0Pud0yR2VTZvCY29WXvKj7ABNTZDpsPxuGNdECIGvHQJXisaEVivXjphuIqQLBy0FipY+O4uwXoI6RGI/6AAgAAAUAJhgcAgBgHfwWBfutNY2LyET3bRUgP6ycpcGnn9SFf/ryhk++v5Z2snuApYAn3Dzx2mjawXAQ7ZOZfQtgPi+tvoUBJJO1p+vUEEDkuz7HQsnjgdMe8qQaSLZoXJbnzvPB32zUMxyZ';

/** One static-ct-api TileLeaf (base64): a precert whose SAN spans more than 32 apexes. Google PlumbersArms2027h1, leaf index 308908015. */
export const MULTI_APEX_TILE_LEAF =
	'AAABoUhz38oAAcg7vaINueTTeRhH/gcGva066hUNBMnWdK9RQofU3QFuAAa/MIIGu6ADAgECAhEAhUhqqqv4BVkTbVmlivI6rzANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMQwwCgYDVQQDEwNXUjEwHhcNMjYxMDE3MDUwMTQ4WhcNMjcwMTE1MDUwMTQ3WjAWMRQwEgYDVQQDDAsqLmFnb2RhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALhGeELYtFotYHDc3snVCOAhx34DkSrUsD1BuT3PuugvOrHKm3P3r5kupK9OTuJKgTVPag7mdmfRo7LYjJq6RUsps51oCcO4jrRn6nQ+w2rIyx4Uj0TKw9yub2TkZJK8LE2kzq1u8uxxzXurqy2oi8OpZDhQr2Li1b+KNYyoBi5ROE4Z2+6I+ZNuIaRhYH7ky8RXFCGVOjEgJzIBzp0nTHNpzfDTKG+UTGAIHsFCaoUjxbEyvJXHbqMqcW4GXdSEM7KLOhc2jXfSodT2UF4EIEsQtmW+2RlS8VhEAB33rPNqV3/W3W6mv/7wuIrVATif+MhPA2hKq+k5WHLTtnL+UnsCAwEAAaOCBPUwggTxMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRZU12YJ+DzNmyo1AK6PjE6ryHWtTAfBgNVHSMEGDAWgBRmaUnU3iqckQPPiQ4kuA4wA26ILjA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAKGGWh0dHA6Ly9pLnBraS5nb29nL3dyMS5jcnQwggP2BgNVHREEggPtMIID6YILKi5hZ29kYS5jb22CCWFnb2RhLmNvbYIKKi5hZ29kYS5jboILKi5hZ29kYS5uZXSCDSouYWdvZGFjZG4uY26CDSouYWdvZGFkZXYuaW+CDyoud3d3LmFnb2RhLmNvbYIPKi54bWwuYWdvZGEuY29tgg5hZ2QtcGx1Z2luLmNvbYIIYWdvZGEuY26CCGFnb2RhLmNvggthZ29kYS5jby5rcoIJYWdvZGEubmV0ghBhZ29kYS54bi0tZmlxczhzggthZ29kYWNkbi5jboILYWdvZGFkZXYuaW+CCmFua2VkYS5jb22CEnByaWNlbGluZWFnb2RhLmNvbYISd3d3LmFnZC1wbHVnaW4uY29tggx3d3cuYWdvZGEuYWWCDHd3dy5hZ29kYS5iZYIMd3d3LmFnb2RhLmJnggx3d3cuYWdvZGEuY2GCDXd3dy5hZ29kYS5jYXSCDHd3dy5hZ29kYS5jb4IPd3d3LmFnb2RhLmNvLmlsgg93d3cuYWdvZGEuY28uaW6CD3d3dy5hZ29kYS5jby5rcoIPd3d3LmFnb2RhLmNvLm1hgg93d3cuYWdvZGEuY28ubnqCD3d3dy5hZ29kYS5jby50aIIPd3d3LmFnb2RhLmNvLnVrgg13d3cuYWdvZGEuY29tghB3d3cuYWdvZGEuY29tLmF1ghB3d3cuYWdvZGEuY29tLmNughB3d3cuYWdvZGEuY29tLm15ghB3d3cuYWdvZGEuY29tLnNnggx3d3cuYWdvZGEuY3qCDHd3dy5hZ29kYS5kZYIMd3d3LmFnb2RhLmRrggx3d3cuYWdvZGEuZWeCDHd3dy5hZ29kYS5lc4IMd3d3LmFnb2RhLmZpggx3d3cuYWdvZGEuZnKCDHd3dy5hZ29kYS5ncoIMd3d3LmFnb2RhLmh1ggx3d3cuYWdvZGEuaWWCDHd3dy5hZ29kYS5pboIMd3d3LmFnb2RhLml0ggx3d3cuYWdvZGEuam+CDHd3dy5hZ29kYS5qcIIMd3d3LmFnb2RhLmx0ggx3d3cuYWdvZGEubHaCDHd3dy5hZ29kYS5ubIIMd3d3LmFnb2RhLm5vggx3d3cuYWdvZGEucGiCDHd3dy5hZ29kYS5wbIIMd3d3LmFnb2RhLnJvggx3d3cuYWdvZGEuc2WCDHd3dy5hZ29kYS5zaYIMd3d3LmFnb2RhLnRoggx3d3cuYWdvZGEudWGCDHd3dy5hZ29kYS52boIUd3d3LmFnb2RhLnhuLS1maXFzOHOCDnd3dy5hbmtlZGEuY29tghZ3d3cucHJpY2VsaW5lYWdvZGEuY29tgg14bWwuYWdvZGEuY29tMBMGA1UdIAQMMAowCAYGZ4EMAQIBMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jLnBraS5nb29nL3dyMS9mLUxMOGliV2I4TS5jcmwACAAABQASaY/vAAfsMIIH6DCCBtCgAwIBAgIRAIVIaqqr+AVZE21ZpYryOq8wDQYJKoZIhvcNAQELBQAwOzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczEMMAoGA1UEAxMDV1IxMB4XDTI2MTAxNzA1MDE0OFoXDTI3MDExNTA1MDE0N1owFjEUMBIGA1UEAwwLKi5hZ29kYS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4RnhC2LRaLWBw3N7J1QjgIcd+A5Eq1LA9Qbk9z7roLzqxyptz96+ZLqSvTk7iSoE1T2oO5nZn0aOy2IyaukVLKbOdaAnDuI60Z+p0PsNqyMseFI9EysPcrm9k5GSSvCxNpM6tbvLscc17q6stqIvDqWQ4UK9i4tW/ijWMqAYuUThOGdvuiPmTbiGkYWB+5MvEVxQhlToxICcyAc6dJ0xzac3w0yhvlExgCB7BQmqFI8WxMryVx26jKnFuBl3UhDOyizoXNo130qHU9lBeBCBLELZlvtkZUvFYRAAd96zzald/1t1upr/+8LiK1QE4n/jITwNoSqvpOVhy07Zy/lJ7AgMBAAGjggUKMIIFBjAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUWVNdmCfg8zZsqNQCuj4xOq8h1rUwHwYDVR0jBBgwFoAUZmlJ1N4qnJEDz4kOJLgOMANuiC4wNQYIKwYBBQUHAQEEKTAnMCUGCCsGAQUFBzAChhlodHRwOi8vaS5wa2kuZ29vZy93cjEuY3J0MIID9gYDVR0RBIID7TCCA+mCCyouYWdvZGEuY29tgglhZ29kYS5jb22CCiouYWdvZGEuY26CCyouYWdvZGEubmV0gg0qLmFnb2RhY2RuLmNugg0qLmFnb2RhZGV2Lmlvgg8qLnd3dy5hZ29kYS5jb22CDyoueG1sLmFnb2RhLmNvbYIOYWdkLXBsdWdpbi5jb22CCGFnb2RhLmNugghhZ29kYS5jb4ILYWdvZGEuY28ua3KCCWFnb2RhLm5ldIIQYWdvZGEueG4tLWZpcXM4c4ILYWdvZGFjZG4uY26CC2Fnb2RhZGV2LmlvggphbmtlZGEuY29tghJwcmljZWxpbmVhZ29kYS5jb22CEnd3dy5hZ2QtcGx1Z2luLmNvbYIMd3d3LmFnb2RhLmFlggx3d3cuYWdvZGEuYmWCDHd3dy5hZ29kYS5iZ4IMd3d3LmFnb2RhLmNhgg13d3cuYWdvZGEuY2F0ggx3d3cuYWdvZGEuY2+CD3d3dy5hZ29kYS5jby5pbIIPd3d3LmFnb2RhLmNvLmlugg93d3cuYWdvZGEuY28ua3KCD3d3dy5hZ29kYS5jby5tYYIPd3d3LmFnb2RhLmNvLm56gg93d3cuYWdvZGEuY28udGiCD3d3dy5hZ29kYS5jby51a4INd3d3LmFnb2RhLmNvbYIQd3d3LmFnb2RhLmNvbS5hdYIQd3d3LmFnb2RhLmNvbS5jboIQd3d3LmFnb2RhLmNvbS5teYIQd3d3LmFnb2RhLmNvbS5zZ4IMd3d3LmFnb2RhLmN6ggx3d3cuYWdvZGEuZGWCDHd3dy5hZ29kYS5ka4IMd3d3LmFnb2RhLmVnggx3d3cuYWdvZGEuZXOCDHd3dy5hZ29kYS5maYIMd3d3LmFnb2RhLmZyggx3d3cuYWdvZGEuZ3KCDHd3dy5hZ29kYS5odYIMd3d3LmFnb2RhLmllggx3d3cuYWdvZGEuaW6CDHd3dy5hZ29kYS5pdIIMd3d3LmFnb2RhLmpvggx3d3cuYWdvZGEuanCCDHd3dy5hZ29kYS5sdIIMd3d3LmFnb2RhLmx2ggx3d3cuYWdvZGEubmyCDHd3dy5hZ29kYS5ub4IMd3d3LmFnb2RhLnBoggx3d3cuYWdvZGEucGyCDHd3dy5hZ29kYS5yb4IMd3d3LmFnb2RhLnNlggx3d3cuYWdvZGEuc2mCDHd3dy5hZ29kYS50aIIMd3d3LmFnb2RhLnVhggx3d3cuYWdvZGEudm6CFHd3dy5hZ29kYS54bi0tZmlxczhzgg53d3cuYW5rZWRhLmNvbYIWd3d3LnByaWNlbGluZWFnb2RhLmNvbYINeG1sLmFnb2RhLmNvbTATBgNVHSAEDDAKMAgGBmeBDAECATA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vYy5wa2kuZ29vZy93cjEvZi1MTDhpYldiOE0uY3JsMBMGCisGAQQB1nkCBAMBAf8EAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQCxF10N0zhhpGTm/M9551Oyt4WfLaXG/L+68E52t8L/K4auoohiFZCs/ORn12PeHK/jLLNlvvPv9hJV1v0ra8YR6Zqjox/lktiD0Ul0YZ6vX+vaZSYEkn3CPX20Pf+s8JT3khvuhC8IIEOyEe4sMva693mHV6DxnyagKYo4W3r9t0mjZycYroT9vIg42ES6KpKcAbWmBFJlv2zNRA29yiz4iccrF3yefe4WqO0oQn6avVZUq0cvYqDSxV18s4LISCRrlWCmNnOSBhmmi3z6fgJJqPfuY8xxb0wH5ZGs5VYUu33bjxCBx+XrSqfimUx89IWuxjix9RzC0vG+re21TVqBAECxC28A5glQnocA9tNGh6K/zjjqBaj98c3EDDoqDQ0ORSpXVHHjE0C8IVgcvSzxPhWEYyA+zpS8+dPMGWvwmlRy';
export const MULTI_APEX_FACTS = {
	nameCount: 67,
	apexCount: 52,
	notBefore: 1792213308,
	notAfter: 1799989307,
	issuer: 'WR1',
};

/** The Chrome CT log list v3 (version 95.2, 2026-10-16T13:42:55Z), trimmed to a few logs and without public keys. */
export const LOG_LIST = {
	version: '95.2',
	log_list_timestamp: '2026-10-16T13:42:55Z',
	operators: [
		{
			name: 'Google',
			logs: [
				{
					description: 'Google Argon2026h2',
					log_id: '1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc=',
					url: 'https://ct.googleapis.com/logs/us1/argon2026h2/',
					mmd: 86400,
					state: {
						usable: {
							timestamp: '2024-09-30T22:19:27Z',
						},
					},
					temporal_interval: {
						start_inclusive: '2026-07-01T00:00:00Z',
						end_exclusive: '2027-01-01T00:00:00Z',
					},
				},
				{
					description: 'Google Argon2027h1',
					log_id: '1tWNqdAXU/NqSqDHV0kCr+vH3CzTjNn3ZMgMiRkenwI=',
					url: 'https://ct.googleapis.com/logs/us1/argon2027h1/',
					mmd: 86400,
					state: {
						usable: {
							timestamp: '2025-12-28T00:30:00Z',
						},
					},
					temporal_interval: {
						start_inclusive: '2027-01-01T00:00:00Z',
						end_exclusive: '2027-07-01T00:00:00Z',
					},
				},
			],
			tiled_logs: [],
		},
		{
			name: 'DigiCert',
			logs: [
				{
					description: 'DigiCert Wyvern2027h1',
					log_id: 'ABpdGhwtk3W2SFV4+C9xoa5u7zl9KXyK4xV7yt7hoB4=',
					url: 'https://wyvern.ct.digicert.com/2027h1/',
					mmd: 86400,
					state: {
						usable: {
							timestamp: '2025-12-20T18:00:00Z',
						},
					},
					temporal_interval: {
						start_inclusive: '2027-01-01T00:00:00Z',
						end_exclusive: '2027-07-01T00:00:00Z',
					},
				},
			],
			tiled_logs: [],
		},
		{
			name: 'Sectigo',
			logs: [
				{
					description: 'Sectigo Mammoth2026h2',
					log_id: 'lLHBirDQV8R74KwEDh8svI3DdXJ7yVHyClJhJoY7pzw=',
					url: 'https://mammoth2026h2.ct.sectigo.com/',
					mmd: 86400,
					state: {
						readonly: {
							timestamp: '2025-09-18T17:20:00Z',
							final_tree_head: {
								sha256_root_hash: 'vJHecZC18lG3qp9lV2jZoi+7nkPHQx2SmM4VWglNsIk=',
								tree_size: 57634084,
							},
						},
					},
					temporal_interval: {
						start_inclusive: '2026-07-01T00:00:00Z',
						end_exclusive: '2027-01-01T00:00:00Z',
					},
				},
			],
			tiled_logs: [
				{
					description: 'Sectigo Monument2027h1',
					log_id: 'lU+RNjI2rVhXzDYVRyLcQOf5ugowsOdS+/DHSylmVrg=',
					submission_url: 'https://monument2027h1.sub.ct.sectigo.com/',
					monitoring_url: 'https://monument2027h1.mon.ct.sectigo.com/',
					mmd: 60,
					state: {
						qualified: {
							timestamp: '2026-10-14T13:50:00Z',
						},
					},
					temporal_interval: {
						start_inclusive: '2027-01-01T00:00:00Z',
						end_exclusive: '2027-07-01T00:00:00Z',
					},
				},
			],
		},
		{
			name: "Let's Encrypt",
			logs: [
				{
					description: "Let's Encrypt Oak2026h2",
					log_id: 'rKswcGzr7IQx9BPS9JFfER5CJEOx8qaMTzwrO6ceAsM=',
					url: 'https://oak.ct.letsencrypt.org/2026h2/',
					mmd: 86400,
					state: {
						retired: {
							timestamp: '2026-02-28T00:00:00Z',
						},
					},
					temporal_interval: {
						start_inclusive: '2026-06-20T00:00:00Z',
						end_exclusive: '2027-01-20T00:00:00Z',
					},
				},
			],
			tiled_logs: [
				{
					description: "Let's Encrypt Willow2026h2",
					log_id: 'qCbL4wrGNRJGUz/gZfFPGdluGQgTxB3ZbXkAsxI8VSc=',
					submission_url: 'https://log.willow.ct.letsencrypt.org/2026h2/',
					monitoring_url: 'https://mon.willow.ct.letsencrypt.org/2026h2/',
					mmd: 60,
					state: {
						usable: {
							timestamp: '2025-11-27T03:00:00Z',
						},
					},
					temporal_interval: {
						start_inclusive: '2026-06-17T00:00:00Z',
						end_exclusive: '2026-12-16T00:00:00Z',
					},
				},
				{
					description: "Let's Encrypt Willow2027h1",
					log_id: 'ooEAGHNOF24dR+CVQPOBulRml81jqENQcW64CU7a8Q0=',
					submission_url: 'https://log.willow.ct.letsencrypt.org/2027h1/',
					monitoring_url: 'https://mon.willow.ct.letsencrypt.org/2027h1/',
					mmd: 60,
					state: {
						usable: {
							timestamp: '2025-11-27T03:00:00Z',
						},
					},
					temporal_interval: {
						start_inclusive: '2026-12-16T00:00:00Z',
						end_exclusive: '2027-06-17T00:00:00Z',
					},
				},
				{
					description: "Let's Encrypt Willow2028h2",
					log_id: 'vey1qmLph0NZ/U7NvnDZ8G8+j71Fo6xrycKFEbx0wJw=',
					submission_url: 'https://log.willow.ct.letsencrypt.org/2028h2/',
					monitoring_url: 'https://mon.willow.ct.letsencrypt.org/2028h2/',
					mmd: 60,
					state: {
						qualified: {
							timestamp: '2026-10-14T13:50:00Z',
						},
					},
					temporal_interval: {
						start_inclusive: '2028-06-15T00:00:00Z',
						end_exclusive: '2028-12-21T00:00:00Z',
					},
				},
			],
		},
		{
			name: 'Geomys',
			logs: [],
			tiled_logs: [
				{
					description: 'Geomys Tuscolo2027h1',
					log_id: 'WW5sM4aUsllyolbIoOjdkEp26Ag92oc7AQg4KBQ87lk=',
					submission_url: 'https://tuscolo2027h1.sunlight.geomys.org/',
					monitoring_url: 'https://tuscolo2027h1.skylight.geomys.org/',
					mmd: 60,
					state: {
						usable: {
							timestamp: '2025-10-08T21:00:00Z',
						},
					},
					temporal_interval: {
						start_inclusive: '2027-01-01T00:00:00Z',
						end_exclusive: '2027-07-01T00:00:00Z',
					},
				},
			],
		},
		{
			name: 'IPng Networks',
			logs: [],
			tiled_logs: [
				{
					description: 'IPng Networks Halloumi2027h1',
					log_id: 'ROgi/CurDpLu0On61pZkYCd20Bdg4IkFCckjobA/w38=',
					submission_url: 'https://halloumi2027h1.log.ct.ipng.ch/',
					monitoring_url: 'https://halloumi2027h1.mon.ct.ipng.ch/',
					mmd: 60,
					state: {
						usable: {
							timestamp: '2025-12-17T18:30:00Z',
						},
					},
					temporal_interval: {
						start_inclusive: '2027-01-01T00:00:00Z',
						end_exclusive: '2027-07-01T00:00:00Z',
					},
				},
				{
					description: 'IPng Networks Gouda2027h1',
					log_id: 'Gouda43XkdHNBUnttgNV1ga2T60w23H+eI8Px8j7xLE=',
					submission_url: 'https://gouda2027h1.log.ct.ipng.ch/',
					monitoring_url: 'https://gouda2027h1.mon.ct.ipng.ch/',
					mmd: 60,
					state: {
						usable: {
							timestamp: '2025-11-27T03:00:00Z',
						},
					},
					temporal_interval: {
						start_inclusive: '2027-01-01T00:00:00Z',
						end_exclusive: '2027-07-01T00:00:00Z',
					},
				},
			],
		},
	],
};
