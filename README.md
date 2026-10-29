# Gauge

[![CI](https://github.com/unified-field-dev/gauge/actions/workflows/ci.yml/badge.svg)](https://github.com/unified-field-dev/gauge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[GitHub](https://github.com/unified-field-dev/gauge) · `cargo doc -p gauge --features ssr --open`

## About

Gauge is the Unified Field **permission domain**: permission taxonomy, groups
(nested membership + owners), grant/revoke, request/review, and audit history.
Hosts wire Valence + auth and call `actor_can` / `user_can` at runtime.

- **Domain** — Valence schemas, service APIs, `actor_can` / `user_can`,
  request/review, Super User bootstrap helpers, resource-permission bundles
- **Runtime checks** — gate routes with `permission_name`; gate Higgs
  `#[server]` with `permission = "…"`

Crate-root rustdoc owns the **Features** index and primary-task guides. Start at
`cargo doc -p gauge --features ssr --open`.

Operator pages (`PermissionRoutes` at `/permission`) live in
[gauge-uf-app](https://github.com/unified-field-dev/gauge-uf-app).

## Getting started

```toml
[dependencies]
# Pin a release tag or commit SHA — do not use branch = "main".
gauge = { git = "https://github.com/unified-field-dev/gauge", package = "gauge", rev = "<tag-or-sha>", default-features = false }
```

Runtime check (SSR):

```rust,ignore
use gauge::service::actor_can;

if !actor_can(&valence, "some.permission").await? {
    return Err(anyhow::anyhow!("not authorized"));
}
```

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-gauge
cargo test -p gauge --features ssr --test permission_domain_contract --test permission_flows_integration
```

## Workspace

| Crate | Role |
|-------|------|
| [`gauge`](gauge/) | Permission domain: schemas, service, `actor_can` / `user_can`, workflows |
| [`embedded-gauge-host`](examples/embedded-gauge-host/) | Teaching host: bootstrap owner + deny/allow |

## Examples

See [`examples/README.md`](examples/README.md) for the teaching host
(`embedded-gauge-host`: bootstrap owner + deny/allow). Copy `Cargo.toml` +
`main.rs` from that host README when wiring a composite product.

## Service users (preview)

A Lepton service user is a non-human principal, such as an agent calling an API with a
token. Gauge checks it as itself, never as the person who owns it.

- **What it can hold:** permissions through group membership, directly or through nested
  groups, while it is active. It has no direct grants, owns no group, domain, or permission,
  and every Gauge write refuses it. It never joins the Super User group.
- **Who can add one to a group:** an owner of the group or a Super User, who can also see the
  service user (its owner, or someone who manages every service user). A service user's owner
  can request group access for it with `on_behalf_of` on a permission request.
- **Who can create one:** members of the "Service user creators" group, or Super User.
- **Status:** preview. The service-user API may change in a `0.1.x` release.

Guides: `cargo doc -p gauge --features ssr --open`, then "Give a service user permissions
through a group". Trust-boundary notes are in [`SECURITY.md`](SECURITY.md).

## Security

Super User pinning, Valence policy notes, and auth expectations for hosts that
mount the sibling UI: [`SECURITY.md`](SECURITY.md). Report vulnerabilities
privately — do not open a public issue for security-sensitive reports.

## Verify

CI (`.github/workflows/ci.yml`) runs the subset documented in
[`docs/VERIFICATION.md`](docs/VERIFICATION.md) (`gauge` domain tests and the
teaching host).

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-gauge
cargo test -p gauge --features ssr --test permission_domain_contract --test permission_flows_integration
cargo run -p embedded-gauge-host
```

Teaching host success line:
`embedded_gauge_host: OK — bootstrap owner + /permissions deny/allow`.
Contribute: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## FAQ

**Is it a standalone server?** `gauge` is a domain library. Composite hosts wire
Valence and session chrome, then call service APIs / `actor_can`.

**How do Super User groups work?** Bootstrap helpers pin privilege to the well-known
group id `super_user_group`. A duplicate group that only reuses the display name does
not grant privilege — see [`SECURITY.md`](SECURITY.md).

**Can an agent hold permissions?** Yes, as a service user in a group. See
[Service users](#service-users-preview).

**Where do resource permission bundles fit?** Call product wrappers
(`gluon::create_initial_gluon_groups`, `neutrino::create_initial_neutrino_groups`,
`nucleus::credentials::create_initial_nucleus_groups`) or
`gauge::resource_permissions::seed_resource_kind_catalog` at host bootstrap before
product create APIs that auto-ensure per-resource bundles.

## License

MIT. See [LICENSE](LICENSE).
