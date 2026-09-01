# Gauge

Permission domain crate: Valence schemas, service APIs, and runtime checks for
permissions, groups, grants, and request/review.

## Host integration

Gate frontend routes with Orbital `RequireAuthenticated` and `permission_name`.
Gate server functions with Higgs `#[higgs_macros::server(permission = "…")]`.

Super User bootstrap Chronon jobs (`ensure_super_user_group`,
`sync_super_user_membership_roles`) compose account membership from the
host/identity stack with Gauge permission models.

## Documentation

- Crate rustdoc: `cargo doc -p gauge --features ssr --open`
- Root [`README.md`](../README.md) and [`docs/VERIFICATION.md`](../docs/VERIFICATION.md)
- Admin UI: [gauge-uf-app](https://github.com/unified-field-dev/gauge-uf-app) (`gauge-app` / `PermissionRoutes`)
