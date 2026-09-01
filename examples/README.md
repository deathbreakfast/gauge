# Examples

Runnable teaching hosts for this product. Copy `Cargo.toml` + `main.rs` (and
the product mount snippets in the host README) into your composite host.

## `embedded-gauge-host` — bootstrap owner + deny/allow

**Teaches:** Super User bootstrap, permission create/grant, and `actor_can`
under a session-gated route. Inventory names match the `permission` `uf_app!`
id/path (`/permission`) and `GaugeAdmin`.

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-gauge
cargo run -p embedded-gauge-host
```

**Success:** stdout prints `embedded_gauge_host: OK — bootstrap owner + /permissions deny/allow`.

**Next step:** Mount `<PermissionRoutes />` from `gauge-app` in
[gauge-uf-app](https://github.com/unified-field-dev/gauge-uf-app).
Full copy table + product mount: [`embedded-gauge-host/README.md`](embedded-gauge-host/README.md).
