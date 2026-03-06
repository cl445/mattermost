# Mattermost Fork – OpenID/Keycloak SSO

This is a fork of [mattermost/mattermost](https://github.com/mattermost/mattermost) with a single custom feature: an OpenID Connect provider for self-hosted SSO via Keycloak.

## Fork Structure

- **Upstream:** `git@github.com:mattermost/mattermost.git` (remote `upstream`, branch `master`)
- **Origin:** `git@github.com:cl445/mattermost.git` (remote `origin`)
- **Feature branch:** `feature/openid-keycloak-sso` — single squashed commit on top of `master`

The delta to upstream is intentionally kept minimal (one commit). All custom changes should stay squashed into a single commit to simplify rebasing.

## Custom Files

- `server/channels/app/oauthproviders/openid/openid.go` — OpenID Connect OAuth provider
- `server/channels/app/oauthproviders/openid/openid_test.go` — Tests for the provider
- `server/cmd/mattermost/main.go` — Provider registration (import)
- `server/config/client.go` — Client-side config for OpenID login, without the license check
- `webapp/channels/src/components/global_header/left_controls/product_menu/product_branding_team_edition/product_branding_free_edition.tsx` — Edition badge renamed to "AKATOR EDITION" (unrelated to SSO)
- `Dockerfile.openid` — Docker build with the OpenID provider included
- `docker-compose.openid.yml` — Compose setup for Mattermost + PostgreSQL, optional Keycloak
- `.dockerignore` — Trims the build context (`.git` alone is >1 GB)
- `.env.openid.example` — Template for the `.env` the compose setup reads
- `scripts/sync-upstream.sh` — Script to sync with upstream

The provider resolves the authorization, token and userinfo endpoints from the
configured `DiscoveryEndpoint` at runtime. That resolution is what the enterprise
provider does upstream, and without it a Mattermost instance configured with only a
discovery endpoint — all the admin console offers for OpenID — cannot log anyone in.

## Syncing with Upstream

```bash
./scripts/sync-upstream.sh
```

This fetches upstream, fast-forwards `master`, rebases the feature branch, and optionally pushes.

## Building

```bash
cp .env.openid.example .env    # then fill in secrets and the discovery endpoint
BUILD_HASH=$(git rev-parse HEAD) docker compose -f docker-compose.openid.yml build
docker compose -f docker-compose.openid.yml up -d
```

The image is built from the working tree, not from a `git clone` of the pushed
branch — uncommitted changes are included. Add `--profile keycloak` to `up` to run a
throwaway Keycloak alongside it for local testing.

## Guidelines

- Keep the fork delta as small as possible — one squashed commit
- Do not cherry-pick upstream commits into the feature branch; always rebase
- When modifying custom files, amend the existing commit rather than adding new ones
- Run `./scripts/sync-upstream.sh` regularly to stay current with upstream
