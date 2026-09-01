# embedded-gauge-host

Embedded Valence host for Gauge: bootstrap Super User owner, create a permission,
prove **deny → grant → allow** via `actor_can`, serve under a session-gated Axum
route.

Production Leptos hosts mount `PermissionRoutes` at **`/permission`** and call
`actor_can` / `user_can` from backend code. This example proves Super User
bootstrap + evaluation without the SSR/WASM / Orbital graph. The oneshot path
`/permissions` is a teaching stand-in for a protected host API; the Orbital app
id/path remain `permission` / `/permission`.

| | |
|---|---|
| **When to use** | First smoke of permission bootstrap + evaluation in an embedded host |
| **Command** | `CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=target-gauge cargo run -p embedded-gauge-host` |
| **Success** | Stdout: `embedded_gauge_host: OK — bootstrap owner + /permissions deny/allow` |
| **Look next** | Mount `PermissionRoutes` from [gauge-uf-app](https://github.com/unified-field-dev/gauge-uf-app); sync permission manifests at host boot |

**Open first:** [`src/main.rs`](src/main.rs)

## Copy into your host

| File | What to take |
|------|----------------|
| This [`Cargo.toml`](Cargo.toml) | Axum oneshot shape + `gauge` `ssr` (bootstrap / `actor_can` smoke) |
| Product mount `Cargo.toml` (below) | `gauge` + `gauge-app` with `ssr` / `hydrate` features |
| [`src/main.rs`](src/main.rs) | Super User bootstrap, deny→grant→allow, protect a host API |
| Leptos sketch (below) | `<PermissionRoutes />` under `/permission` |

### Product mount dependencies

```toml
[dependencies]
# Pin a release tag or commit SHA — do not use branch = "main".
gauge = { git = "https://github.com/unified-field-dev/gauge", package = "gauge", rev = "<tag-or-sha>", default-features = false }
gauge-app = { git = "https://github.com/unified-field-dev/gauge-uf-app", package = "gauge-app", rev = "<tag-or-sha>", default-features = false }
uf-product = { /* your pin */, default-features = false }
uf-integrations = { /* your pin */, default-features = false }

[features]
ssr = [
    "gauge/ssr",
    "gauge-app/ssr",
    "uf-product/ssr",
    "uf-integrations/ssr",
]
hydrate = [
    "gauge-app/hydrate",
    "uf-product/hydrate",
    "uf-integrations/hydrate",
]
```

### Leptos mount sketch

```rust,ignore
use gauge_app::PermissionRoutes;
use leptos_router::components::Routes;

view! {
    <Routes fallback=|| "not found">
        <PermissionRoutes />
    </Routes>
}
```

Backend check (Leptos-free):

```rust,ignore
use gauge::service::actor_can;

if !actor_can(&valence, "some.permission").await? {
    return Err(anyhow::anyhow!("not authorized"));
}
```

At host boot, call product resource-permission helpers (or
`gauge::resource_permissions::seed_resource_kind_catalog`) before product APIs that
auto-ensure per-resource bundles. Sync the `GaugePermission` manifest
(`GaugeAdmin`) with your host permission registration.

For shell chrome (layout, fonts, Axum + Leptos boot), copy
[`shell-chrome-host`](https://github.com/unified-field-dev/unified-field-product/tree/main/examples/shell-chrome-host)
from unified-field-product, then mount `PermissionRoutes`.

## Run (documented gate)

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-gauge
cargo check -p embedded-gauge-host
cargo run -p embedded-gauge-host
```

**Success:** stdout prints `embedded_gauge_host: OK — bootstrap owner + /permissions deny/allow`.

## Hydrate / browser

Out of gate for this host. Full admin UI needs a product binary with
`cargo-leptos`, `wasm32`, session chrome, and a working Orbital / `uf-product`
graph. Prefer the oneshot above.
