# bv-mcp DevContainer for Cloudflare Workers
FROM mcr.microsoft.com/devcontainers/typescript-node:latest

# Install Wrangler CLI globally
RUN npm install -g wrangler@latest

# Install Vitest and Cloudflare pool workers for testing
RUN npm install -g vitest @cloudflare/vitest-pool-workers

# Set working directory
WORKDIR /workspace

# Install additional tools (optional)
RUN apt-get update && apt-get install -y git curl

# Default shell
CMD ["zsh"]