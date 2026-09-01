# Contributing to Gauge

## Development setup

1. Clone [unified-field-dev/gauge](https://github.com/unified-field-dev/gauge)
2. Install Rust stable
3. From the repository root:

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-gauge
cargo fmt -p gauge -- --check
cargo test -p gauge --features ssr --test permission_domain_contract --test permission_flows_integration
```

Full gates: [`docs/VERIFICATION.md`](docs/VERIFICATION.md).

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Security
reports: [`SECURITY.md`](SECURITY.md).

## Pull requests

- Prefer small, focused PRs.
- Update [`README.md`](README.md) when public API or UI flows change.
