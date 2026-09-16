.PHONY: build dev test test-e2e setup

# Prefer docker, fall back to podman. Override with: make build CONTAINER=podman
CONTAINER ?= $(shell for c in docker podman; do command -v $$c >/dev/null 2>&1 && { echo $$c; break; }; done)

KNAME=$(shell uname -s |  tr '[:upper:]' '[:lower:]')

# Copies the documented configuration into the two environment files, then
# leaves you to fill in the client id and secret.
setup:
	@test -f .env.local || cp .env.example .env.local
	@test -f .env.staging || sed 's|^SSO_BASE_URL=.*|SSO_BASE_URL=https://stg.sso.nuanu.com|; s|^APP_ENV=.*|APP_ENV=staging|' .env.example > .env.staging
	@bun install
	@echo "==> set SSO_CLIENT_ID and SSO_CLIENT_SECRET in .env.local, then: make dev"

build:
	@test -n "$(CONTAINER)" || { echo "make: no container runtime found - install docker or podman"; exit 1; }
	@echo "==> using $(CONTAINER)"
	@mkdir -p _build
	@$(CONTAINER) build --build-arg GOOS=$(KNAME) -t sso-demo:builder .
	@$(CONTAINER) container create --name sso-demo-builder sso-demo:builder
	@$(CONTAINER) container cp sso-demo-builder:/usr/local/bin/application ./_build/
	@$(CONTAINER) container rm sso-demo-builder
	@$(CONTAINER) rmi sso-demo:builder

dev:
	@foreman s -f Procfile

test:
	@go test ./... -race

test-e2e:
	@bunx playwright test
