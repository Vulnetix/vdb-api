# Vulnetix VDB Development Commands
# This justfile provides development workflow commands for the cybersecurity platform

# Default recipe
default: help

# Show available commands
help:
    @echo "Available commands:"
    @just --list --unsorted

# Cleanup tmp files
clean:
    @find . -type f -name '*.DS_Store' -delete 2>/dev/null || true

# FOR DOCO ONLY - Run these one at a time, do not call this target directly
setup:
    nvm install --lts
    nvm use --lts
    npm install -g corepack
    rm ~/.pnp.cjs || true
    corepack enable
    yarn set version stable
    yarn install
    # yarn dlx @yarnpkg/sdks vscode
    # yarn plugin import https://raw.githubusercontent.com/spdx/yarn-plugin-spdx/main/bundles/@yarnpkg/plugin-spdx.js
    # yarn plugin import https://github.com/CycloneDX/cyclonedx-node-yarn/releases/latest/download/yarn-plugin-cyclonedx.cjs

# Get info about the current cloudflare project
whoami:
    npx wrangler whoami

# Get app updates, migrate should be run first
update:
    yarn up

# Install deps and build icons
install:
    yarn install

# Generate types and run prisma generate
types:
    npx wrangler types
    npx prisma generate

# Build the worker (dry-run to validate bundle)
build:
    npx wrangler deploy --dry-run --outdir=dist --env production

# Run the worker in development mode with live reload
dev:
    npx wrangler dev --live-reload --port 8778 --local

# Preview the project in development mode (alias for dev)
preview: dev

# WARNING: this is only used if GitOps is broken, and cannot inherit Console Env vars!!! Manually Deploy to production
deploy:
    npx wrangler deploy --env production

# FOR DOCO ONLY - Run these one at a time, do not call this target directly
running:
    lsof -i tcp:8778

logs:
    npx wrangler tail --format pretty

update-clis:
    yarn add wrangler@latest
    yarn add @prisma/client@latest
    yarn add --dev prisma@latest

# Run integration tests
test:
    @echo "Running integration tests..."
    ./tests/scripts/run-tests.sh local

# Run integration tests (verbose)
test-verbose:
    @echo "Running integration tests (verbose)..."
    ./tests/scripts/run-tests.sh local true

# Run integration tests against production
test-prod:
    @echo "Running integration tests against production..."
    ./tests/scripts/run-tests.sh production

# Generate tests from OpenAPI specification
test-generate:
    @echo "Generating tests from OpenAPI specification..."
    ./tests/scripts/generate-from-oas.sh

# Generate tests from production OAS
test-generate-prod:
    @echo "Generating tests from production OpenAPI specification..."
    ./tests/scripts/generate-from-oas.sh https://api.vdb.vulnetix.com/v1/spec

# Install test dependencies
test-install:
    npm install -g httpyac openapi-to-postmanv2

# Clean test artifacts
test-clean:
    rm -rf tests/results tests/generated
