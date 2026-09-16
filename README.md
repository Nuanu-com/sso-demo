# Nuanu SSO Demo

A relying party for the [Nuanu SSO](../authentication) identity provider: it signs a user in
over OpenID Connect and shows every value the flow produced next to the step that produced
it. There are no passwords here, no user table, and no database.

Built on the [potash](https://github.com/aaripurna/potash) template - Go, Fiber, `html/template`,
Tailwind and Preact islands - with the SSO client in [`sso/`](./sso).

## What it does

The authorization-code flow from [`SSO_INTEGRATION.md`](../authentication/docs/SSO_INTEGRATION.md),
with the parts that are easy to skip actually done:

| | |
|---|---|
| Discovery | Endpoints read from `/.well-known/openid-configuration`; only `SSO_BASE_URL` is configured |
| PKCE | A fresh `S256` verifier per attempt, kept server side |
| `state` | Generated per attempt, stored in the session, compared in constant time on return |
| `nonce` | Generated per attempt and matched against the `id_token` claim |
| Code exchange | Server side, form-encoded, with the client secret and the verifier |
| `id_token` | Signature, `iss`, `aud`, `exp` and `nonce` - HS256 against the client secret or RS256 against the JWKS |
| `access_token` | Verified against the published JWKS, keys cached and refreshed |
| UserInfo | Read from `/openid/userinfo`, with its `sub` compared against the `id_token`'s |
| Refresh | The `refresh_token` grant, with the rotated token persisted |
| Logout | RP-initiated, clearing this app's session and discarding its tokens |

Tokens live in a server-side session. The browser only ever holds an opaque session id.

## Getting started

Requires Go 1.27, [bun](https://bun.sh), and - for `make dev` - [air](https://github.com/air-verse/air)
and [foreman](https://github.com/ddollar/foreman). `.tool-versions` pins the first two for asdf/mise.

```console
$ make setup
```

That writes `.env.local` and `.env.staging` from `.env.example` and installs the JS
dependencies. Then register an OAuth client - an SSO superuser runs this:

```console
$ curl -X POST "http://127.0.0.1:8000/api/v1/oauth_clients/" \
    -H "Authorization: Bearer <superuser_access_token>" \
    -H "Content-Type: application/json" \
    -d '{"client_name": "SSO Demo",
         "allowed_redirect_urls": "http://localhost:3001/auth/callback,http://localhost:3001/auth/logout/callback"}'
```

The response carries the `client_id` (as `id`) and the `client_secret` - the secret is shown
in full only there. Put both in `.env.local`:

```
SSO_CLIENT_ID=0f4b...
SSO_CLIENT_SECRET=kQ7v...
```

Then:

```console
$ make dev
```

The app is on <http://localhost:3001>; vite serves the assets on 5173. Port 3001 rather than
8000, because the auth service itself runs on 8000 and running both at once is the point.

Until a client is configured the landing page says so and shows the registration call, rather
than offering a sign-in button that cannot work.

If you only want to *show* the demo rather than work on it, skip the toolchain entirely and
use Compose instead - see below.

## Run it with Compose

The quickest way to show the demo on a machine with no Go or bun on it:

```console
$ make demo        # build the image and start it
$ make demo-logs   # follow it
$ make demo-down   # stop and remove it
```

It comes up on <http://localhost:3001>. Podman and Docker both work - the Makefile picks
whichever is installed, preferring podman, and `make demo CONTAINER=docker` overrides that.
`podman compose` hands off to `podman-compose`; `docker compose` is built in. Plain
`podman compose up -d --build` does the same thing if you would rather not go through make.

The image is the deployment artifact: bun builds the assets, Go builds a static binary with
the assets and views embedded, and the runtime stage is alpine plus that one file. The first
build takes a few minutes; every one after it hits the layer cache.

Configuration comes from an environment file, and `DEMO_ENV_FILE` picks which:

```console
$ make demo                              # .env.staging, the default
$ DEMO_ENV_FILE=.env.local make demo     # read the caveat below first
```

Because the file is read by Compose rather than by the binary, the credentials stay on the
host; nothing secret is baked into the image.

### Why the container defaults to staging

The auth service builds its whole discovery document from `APP_BASE_URL` - the issuer, and
every endpoint hanging off it. A container configured against a local auth service is
therefore told to reach `http://127.0.0.1:8000`, which inside a container is the container
itself, and the token exchange fails with nothing listening.

Staging has no such problem: its URLs are absolute and reachable from anywhere. For working
against a local auth service, use `make dev` rather than Compose - the process runs on the
host, where `127.0.0.1:8000` means what the discovery document says it means. If it has to
be a container, give the auth service an `APP_BASE_URL` that the browser and the container
both resolve to the same place, and register a matching `redirect_uri`.

### Pointing at staging without a container

```console
$ APP_ENV=staging make dev
```

`main.go` picks the env file from `APP_ENV`: `.env.local`, `.env.staging`, `.env.test`, or
`.env` for production. Register the same callback URLs on a staging client, or edit
`SSO_REDIRECT_URI` to wherever it is deployed. Nothing in a `.env` file overrides a variable
already set in the environment, so a real deployment can ignore them entirely.

### `SSO_ID_TOKEN_ALG`

Clients default to **HS256**, where the `id_token` is signed with your client secret. That is
a per-client setting on the server which nothing in the protocol exposes, so this app has to
be told which to expect. If the auth team switches your client to RS256, change this to match
at the same time - the token is only ever signed one way, and the two sides have to agree.

## Layout

```
sso/           the OpenID Connect client: discovery, PKCE, token exchange, verification
session/       sign-in state and tokens, server side, keyed by an opaque cookie
web/           handlers - auth.go is the flow, pages.go is what it renders
views/         html/template pages and layout
assets/        Tailwind entry and the one Preact island (the token countdown)
endpoints/     routes
```

## Tests

```console
$ make test        # go test ./... -race
$ make test-e2e    # playwright
```

The Go tests cover the client against an identity provider stood up in-process - including
the failures that matter: a token minted for another client, a foreign issuer, a replayed
nonce, an HS256 token offered to an RS256 client, a payload rewritten after signing.

The Playwright suite runs against `.env.test`, which configures a fake client and skips
discovery, so it needs no identity provider: it asserts on the authorization request this app
builds and on how the callback handles what comes back. The dashboard is the one page it
cannot reach - rendering it needs a real sign-in - so the view tests in `web/views_test.go`
render those templates directly.

## Deploying

```console
$ make build
```

Builds in a container and drops a static binary in `_build/`, for deploying the
binary rather than the image. `make demo` builds the same image and runs it. `views/` and the built assets
are embedded, so the binary is the whole artifact. Set `NODE_ENV=production` (the Dockerfile
does) to serve assets from the built manifest rather than the vite dev server, and
`COOKIE_SECURE=true` behind HTTPS.

Sessions are in memory. More than one instance, or a restart that should not sign everyone
out, needs a shared session store - that is the change to make first.
