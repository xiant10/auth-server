# AGENTS.md

For coding agents working in this repo. t10's only identity issuer: sign-in, tokens and JWKS, tenants, grants for agents, business roles.

## Build and test

```bash
make lint      # go vet, gofmt
make test      # needs nothing running; database tests skip
make db-up     # the throwaway Postgres on 55432 that every t10 repo's tests share
make test-db   # every test, against it, one package at a time
make ci        # what CI runs
node --test verifier/ts/verifier.test.ts   # the TypeScript verifier, on Node 24
```

## Read first

- `docs/design.md`
- `docs/api.md`
- `docs/guides/service-api.md`
- `docs/agent-identity.md`
- `docs/development.md`

## Rules

- This image serves its consumer docs at `/docs/mcp` with no token (the workspace's `contracts/docs/`). Anything marked `audience: consumer` is public to whoever reaches the service, so keep secrets and internal notes out, or mark the doc `contributor`.
- `third_party/t10-modkit` is a snapshot of `t10-modkit`: change it there, then run the workspace's `scripts/sync-modkit.sh` (its web-kit loop overwrites `web/src/kit` in workbench, so check that diff). `make check` fails when a copy drifts.
- `verifier/` is the original every service copies; after changing it, update the copies the workspace's `scripts/check-contracts.sh` lists.
- Every route declares its access in one table in `internal/server/server.go`; a test fails if one has none.
- A route change updates `docs/api.md` (and `docs/openapi.yaml` where there is one) in the same change.
- Every doc under `docs/` starts with front matter: `title`, `audience` (consumer, contributor or operator), `kind` (guide, reference, design or record), `status` and `summary`. Plans, reviews and validation logs go in `docs/records/`. The workspace's `make check` (`scripts/check-docs.py`) holds this and checks relative links.
- This repo is its own project inside the t10 workspace: it builds with nothing from the workspace. The workspace's `ARCHITECTURE.md` is the high-level design, and wins where they disagree.
- This repo is public: check what you add before it's pushed.
