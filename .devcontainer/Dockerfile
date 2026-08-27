# bv-mcp DevContainer for Cloudflare Workers
FROM mcr.microsoft.com/devcontainers/typescript-node:1-22-bookworm

# Keep the image surface small and deterministic. Project tooling is installed
# from package-lock.json by the devcontainer post-create command.
USER root
RUN apt-get update \
	&& apt-get install -y --no-install-recommends git curl \
	&& rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /workspace

# Development commands do not need root privileges.
USER node

# Default shell
CMD ["zsh"]
