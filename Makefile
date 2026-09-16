.PHONY: build dev test test-e2e setup demo demo-logs demo-down

# Whichever runtime is installed. Override with: make demo CONTAINER=docker
CONTAINER ?= $(shell for c in podman docker; do command -v $$c >/dev/null 2>&1 && { echo $$c; break; }; done)

# `podman compose` hands off to podman-compose; `docker compose` is built in.
COMPOSE = $(CONTAINER) compose

KNAME=$(shell uname -s |  tr '[:upper:]' '[:lower:]')

# Copies the documented configuration into the two environment files, then
# leaves you to fill in the client id and secret.
setup:
	@test -f .env.local || cp .env.example .env.local
	@test -f .env.staging || sed 's|^SSO_BASE_URL=.*|SSO_BASE_URL=https://stg.sso.nuanu.com|; s|^APP_ENV=.*|APP_ENV=staging|' .env.example > .env.staging
	@bun install
	@echo "==> set SSO_CLIENT_ID and SSO_CLIENT_SECRET in .env.local, then: make dev"

build:
	@test -n "$(CONTAINER)" || { echo "make: no container runtime found - install podman or docker"; exit 1; }
	@echo "==> using $(CONTAINER)"
	@mkdir -p _build
	@$(CONTAINER) build --build-arg GOOS=$(KNAME) -t sso-demo:builder .
	@$(CONTAINER) container create --name sso-demo-builder sso-demo:builder
	@$(CONTAINER) container cp sso-demo-builder:/usr/local/bin/application ./_build/
	@$(CONTAINER) container rm sso-demo-builder
	@$(CONTAINER) rmi sso-demo:builder

dev:
	@foreman s -f Procfile

# The demo as it is deployed: built assets, one binary, no toolchain needed.
# DEMO_ENV_FILE picks the environment; it defaults to .env.staging.
demo:
	@test -n "$(CONTAINER)" || { echo "make: no container runtime found - install podman or docker"; exit 1; }
	@$(COMPOSE) up -d --build
	@echo "==> http://localhost:3001"

demo-logs:
	@$(COMPOSE) logs -f

demo-down:
	@$(COMPOSE) down

test:
	@go test ./... -race

test-e2e:
	@bunx playwright test
