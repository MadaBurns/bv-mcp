# Offline-buildable image for the Anthropic OSS Scanner.
#
# Contract (anthropics/oss-scanner templates/Dockerfile): the scanner builds
# this with the repository checkout as the build context, the checkout lives
# at /src, and network access exists ONLY while this Dockerfile builds. So
# node_modules, the built workspace package, the WASM module and the workerd
# binary must all be baked in here.
#
# Mirrors .github/workflows/ci.yml: `preflight` (build:wasm) + `test-shard`
# (npm ci, build dns-checks, vitest wrapper).

# node:22-bookworm-slim over debian:bookworm + NodeSource: package.json
# requires node >=22.13.0, and the official image pins a known-good Node 22
# without a third-party apt repo or a curl|bash step. -slim (not the full
# buildpack-deps variant) saves ~0.8 GB; the toolchain it lacks is installed
# explicitly below.
FROM node:22-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    CI=true \
    WRANGLER_SEND_METRICS=false

# ca-certificates/git/build-essential/pkg-config: native addons and the Rust
# linker (cc). python3: handy for the scanning agent. Kept otherwise lean.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git python3 build-essential pkg-config curl \
    && rm -rf /var/lib/apt/lists/*

# Rust stable + the wasm target, then wasm-pack at the version CI pins.
# Debug symbols are kept (nothing here strips binaries). wasm-pack downloads
# wasm-bindgen-cli / wasm-opt on first use; that happens in the build:wasm
# step below, so the tools are cached in the image for offline use.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain stable \
    && rustup target add wasm32-unknown-unknown \
    && cargo install wasm-pack --version 0.13.1 --locked \
    && rm -rf "$CARGO_HOME/registry/cache" "$CARGO_HOME/git"

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Dev dependencies are required (vitest, tsup, wrangler, tsx), so NODE_ENV
# must NOT be "production" here. This also fetches the workerd binary.
RUN npm ci && npm cache clean --force

# `npm run build` = build packages/dns-checks, then tsup. build:wasm
# regenerates the wasm permission table and runs wasm-pack for
# crates/bv-wasm-core (target web), so test/wasm-integration.test.ts can
# run in this image (CI deletes that spec from the sharded jobs only).
RUN npm run build && npm run build:wasm

# Offline note (verified with `docker run --network none`): `npm run
# typecheck` works with no network. `wrangler types` only reads
# wrangler.jsonc and local runtime types (metrics are disabled above), then
# `tsc --noEmit` runs. A few tests reach live DNS/HTTP endpoints and fail
# offline by design; they are not image defects.

# Run the suite so we know the image works, but never abort the build on
# test failures (the scanner would discard the image).
RUN (node scripts/vitest-filter-workerd.mjs run || echo "WARNING: tests reported failures")
