<!-- reconcile: SQ-418 -->

# Enterprise Managed Auth for BlackVeil DNS Security

Setup guide for identity and IT administrators at a Claude Team or Enterprise
organization. It covers connecting the BlackVeil DNS Security connector to your
organization through your single sign-on (SSO) provider, so people in your
organization can use it without a separate sign-in.

All values below are placeholders. Replace anything in `<angle brackets>` with
your own.

## 1. What Enterprise Managed Auth does

Enterprise Managed Auth (EMA) lets your identity provider (IdP) vouch for your
users to BlackVeil DNS Security on their behalf.

- **Silent connect.** When someone in your organization uses the connector,
  Claude asks your IdP for a short-lived identity assertion and exchanges it
  with BlackVeil for an access token. The person sees no sign-in window.
- **No per-user consent.** You approve the connection once, for the
  organization. Your IdP's existing access policies decide who is covered.
- **Plans.** EMA is available for Claude Team and Enterprise organizations.
- **Identity providers.** Okta is supported at launch. Other providers will work
  as Anthropic adds them to Claude; this guide will be updated when they do.

BlackVeil never sees your users' IdP passwords. It trusts only assertions signed
by the issuer you register with us.

## 2. Before you start

Send BlackVeil two things, through the [contact form](https://blackveilsecurity.com/contact):

| What                | Example                                                                                                             |
| ------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Your IdP issuer URL | `https://<your-org>.okta.com` or a custom authorization server such as `https://<your-org>.okta.com/oauth2/default` |
| Your plan or tier   | Claude Team, Claude Enterprise, or the BlackVeil tier you have agreed with us                                       |

The issuer URL must be the exact `issuer` value from your IdP's
`<issuer>/.well-known/openid-configuration` document. It must use `https`.

BlackVeil registers your issuer as a trusted tenant and replies to confirm that
the tenant is enabled. Do not continue to the next sections until you have that
confirmation. Until then, token exchanges fail with `invalid_grant`.

## 3. Values to enter in Okta

In the Okta Admin Console, use the Cross App Access (XAA) settings. Menu names
can vary slightly between Okta releases.

### Resource app (BlackVeil DNS Security)

Go to **Resource app > Machine assignments > Callers > Cross App Access** and
enter:

| Field      | Value                                   |
| ---------- | --------------------------------------- |
| Issuer URL | `https://dns-mcp.blackveilsecurity.com` |
| Audience   | `https://dns-mcp.blackveilsecurity.com` |
| Scope      | `mcp`                                   |

Enter the URLs exactly as shown, with no trailing slash. The audience is
BlackVeil's authorization server identifier, not the token endpoint address.

### AI agent (Claude)

Go to **AI agent (Claude) > Resource connections** and enter:

| Field         | Value                                               |
| ------------- | --------------------------------------------------- |
| Client ID     | `https://claude.ai/oauth/mcp-oauth-client-metadata` |
| Resource      | `https://dns-mcp.blackveilsecurity.com/mcp`         |
| Allowed scope | `mcp`                                               |

The client ID is a URL. Claude publishes its client details at that address, and
BlackVeil reads them from there. Use it as the client ID without changes.

## 4. Turn it on in Claude

A Claude organization owner or primary owner does this in Claude:

1. Open **Organization settings > Connectors**.
2. Select **BlackVeil DNS Security**, then **Configuration > Managed
   authorization > Set up**.
3. **Connect.** Claude runs a test exchange (**Run test**) against your IdP and
   BlackVeil. Wait for it to pass.
4. **Roles.** Choose which roles can use the connector.
5. **Scopes.** Keep `mcp`.
6. **Save & turn on.**

Browser sign-in can stay on as a fallback. People who are not covered by
managed authorization can still sign in the usual way.

## 5. How access behaves

- **Access tokens last up to 1 hour.** A token can be shorter if your
  entitlement with BlackVeil ends sooner.
- **There is no refresh token.** When a token expires, Claude silently asks your
  IdP for a fresh assertion and exchanges it again. The user sees nothing.
- **Each assertion is single-use.** BlackVeil rejects an assertion it has
  already accepted.
- **Disabling a user in your IdP** stops new tokens for that user. A token that
  was already issued works until it expires, at most one hour.
- **BlackVeil can revoke a whole tenant immediately** on request. Disabling the
  tenant makes every new exchange fail with `invalid_grant`.
- **Access level.** Tokens carry the tier agreed for your tenant. They are never
  owner tier.

## 6. Troubleshooting

Errors come back from `https://dns-mcp.blackveilsecurity.com/oauth/token` as
standard OAuth JSON (`error`, `error_description`). Claude and Okta usually
surface the `error` value.

| Error                            | Likely cause                                                                                                                                                                                                                                                                                                  | What to do                                                                                                               |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `unsupported_grant_type`         | The request did not use the JWT bearer grant, or the assertion was missing.                                                                                                                                                                                                                                   | Check that Managed authorization is selected in Claude and that Okta is returning an identity assertion.                 |
| `invalid_grant`                  | The assertion was rejected. Typical reasons: the issuer is not trusted by BlackVeil or the tenant is disabled or expired; the assertion is expired or dated in the future (check IdP clock); the audience does not match; the assertion was already used; the client ID inside it does not match the request. | Confirm your issuer URL with BlackVeil, check the Audience value (section 3), and retry. Do not replay an old assertion. |
| `invalid_client`                 | Claude's client ID is not allowed for your tenant, or it could not be resolved.                                                                                                                                                                                                                               | Ask BlackVeil to confirm the allowed client ID is `https://claude.ai/oauth/mcp-oauth-client-metadata`.                   |
| `invalid_target`                 | The resource in the request does not match the MCP server.                                                                                                                                                                                                                                                    | Set Resource to `https://dns-mcp.blackveilsecurity.com/mcp` in Okta.                                                     |
| HTTP 429                         | Too many token requests from one address in a short time.                                                                                                                                                                                                                                                     | Wait a minute and retry. Contact us if it persists.                                                                      |
| **Run test fails but SSO works** | Almost always an Audience mismatch.                                                                                                                                                                                                                                                                           | Check that Audience is `https://dns-mcp.blackveilsecurity.com` with **no trailing slash**.                               |

## 7. Testing without a Claude organization

Okta's Cross App Access playground at [xaa.dev](https://xaa.dev) can act as the
requesting app. Point it at BlackVeil's authorization server:

- Authorization server issuer: `https://dns-mcp.blackveilsecurity.com`
- Resource: `https://dns-mcp.blackveilsecurity.com/mcp`
- Scope: `mcp`

Your issuer must be registered with BlackVeil first (section 2).

A successful exchange returns JSON like this (token shortened):

```json
{
	"access_token": "<jwt>",
	"token_type": "Bearer",
	"expires_in": 3600,
	"scope": "mcp"
}
```

There is no `refresh_token` field. The access token is then sent as
`Authorization: Bearer <token>` to `https://dns-mcp.blackveilsecurity.com/mcp`.

## 8. Support

Contact BlackVeil through [https://blackveilsecurity.com/contact](https://blackveilsecurity.com/contact).
Include:

- your IdP issuer URL,
- the time of the failure, with time zone,
- the error code from section 6.

Never send access tokens, identity assertions, or client secrets. We do not need
them to investigate.
