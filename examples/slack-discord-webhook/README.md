# Blackveil DNS - Slack/Discord Weekly Reporter

Cloudflare Cron Trigger that scans a domain every Monday and posts a summary to Slack or Discord.

## Setup

1. Clone this directory or copy the files.
2. Install Wrangler: `npm install -g wrangler`.
3. Edit `wrangler.toml` and set your `DOMAIN`.
4. Add your webhook URL as a secret:

```bash
wrangler secret put WEBHOOK_URL
```

5. Deploy:

```bash
wrangler deploy
```

## Slack webhook

Create one at Slack > Apps > Incoming Webhooks > Add New Webhook.

## Discord webhook

Create one at Server Settings > Integrations > Webhooks > New Webhook.

Append `/slack` to the Discord webhook URL for Slack-compatible formatting:

`https://discord.com/api/webhooks/ID/TOKEN/slack`

## Customization

- Change the cron schedule in `wrangler.toml`.
- Modify `buildSlackPayload()` in `worker.ts`.
- Set `MCP_ENDPOINT` in `wrangler.toml` vars to use a self-hosted endpoint.
