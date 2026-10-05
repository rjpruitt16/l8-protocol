# AGENTS.md

The L8 protocol spec: trustless webhook delivery via an Ed25519 challenge-response handshake, signed deliveries, optional X25519 payload encryption, and optional per-route JSON Schemas for request bodies. `index.md` is the human-readable spec (served via GitHub Pages); `spec.json` is the machine-readable version. Keep them in sync.

## Related repos

These repos are developed together and are usually cloned as siblings under one folder (`SAAS/`). Before you search the web or guess, check whether the sibling exists locally at the path below and read it.

| Repo | Local path | GitHub | Role |
|---|---|---|---|
| aquifer | `../aquifer` | https://github.com/rjpruitt16/aquifer | Go load balancer for agentic workloads; reference implementation |
| ezthrottle-local | `../ezthrottle-local` | https://github.com/rjpruitt16/ezthrottle-local | Elixir/Phoenix sibling of Aquifer; kept feature-for-feature in sync |
| l8-protocol | `../l8-protocol` | https://github.com/rjpruitt16/l8-protocol | L8 spec (`index.md`, `spec.json`): handshake, signing, encryption, request schemas |
| aqueduct-runner | `../aqueduct-runner` | https://github.com/rjpruitt16/aqueduct-runner | Cross-repo contract tests (Dagger + Hurl) run against real Aquifer and ezthrottle-local containers |
| canalis-rs | `../canalis-rs` | https://github.com/rjpruitt16/canalis-rs | Rust control plane for Aquifer/ezthrottle-local fleets |

Shared contracts that must stay identical across Aquifer and ezthrottle-local: `X-Aqueduct-*` request/response headers, job JSON shape, idempotency hashing (`sha256(user_id + ":" + key)`, or `sha256("shared\0" + key)` for `idempotency_scope: "shared"`), drain ledger events, `POST /proxy` direct-then-fallback behavior, and L8. A change to any of these in one repo needs the matching change in the other, an update to `l8-protocol` if it touches L8, and ideally a contract test in `aqueduct-runner`.

## Working on the spec

- Any wire change bumps `version` in `spec.json`, the title in `index.md`, and the roadmap table.
- Implementations to update alongside the spec: Aquifer (`../aquifer/l8*.go`, plus `l8SpecDocument` in `l8.go`, which is served at `GET /l8-spec`), ezthrottle-local (`../ezthrottle-local/lib/ezthrottle_local/l8.ex`, plus the spec text in `l8_controller.ex`), and the Python reference receiver (`../aquifer/tests/l8_receiver.py`, copied to `../ezthrottle-local/test/integration/`).
- Verify cross-language: the Python receiver must verify and decrypt deliveries from both Go and Elixir senders.

## Conventions

- New behavior is opt-in: gate it behind an env flag that defaults off. Background loops and processes should not start at all when their flag is off.
- Work on a feature branch and open a PR for review. Do not push to `main` or merge.
- Commits: no `Co-Authored-By` or `Claude-Session` trailers.
- Docs prose: avoid em dashes outside titles and headings.
- Report failures and limits honestly in PR descriptions; don't overstate results.
