# gauge verification

Re-run after code or doc changes. This workspace is the **Gauge domain** repo
(`gauge` crate only). The Leptos admin UI (`gauge-app` / `PermissionRoutes`) lives
in the sibling **gauge-uf-app** composer repo under `L4-composers/gauge-uf-app`.
Layer 1 covers the product-local service that backs permission/domain CRUD,
grant/revoke, `actor_can` / `user_can`, and request/review.

## Environment

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-gauge
```

## Teaching host

Axum oneshot under [`examples/embedded-gauge-host`](../examples/embedded-gauge-host/).
Copy table + product mount sketches live in that host README.

```bash
cargo check -p embedded-gauge-host
cargo run -p embedded-gauge-host
```

Success line: `embedded_gauge_host: OK — bootstrap owner + /permissions deny/allow`.
Hydrate/browser is out of gate for the oneshot (`cargo-leptos` + `wasm32` +
Orbital / `uf-product` belong to a composite product host).

## Layer 1 — Unit + integration (CI)

### PR CI parity (`.github/workflows/ci.yml`)

Standalone checkout on `unified-field-dev/gauge`. UF deps use git `branch = "main"`.
No monorepo sibling clones. Playwright / `gauge-app` hydrate are **not** CI jobs here.

| Job | Commands |
|-----|----------|
| **fmt** | `cargo fmt -p gauge -p embedded-gauge-host -- --check` |
| **clippy** | `cargo clippy -p gauge --features ssr --lib -- -D warnings` then scoped `--test …` suites below, then `cargo clippy -p embedded-gauge-host --all-targets -- -D warnings` |
| **test** | `cargo test -p gauge --test workspace_members --test product_surface`; domain `--features ssr` contract suites; `cargo check` + `cargo run -p embedded-gauge-host` |
| **docs** | `RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc -p gauge --features ssr --no-deps` |

Clippy/test contract suite names (same list in both jobs):

```text
permission_domain_contract
permission_flows_integration
privacy_authorization_integration
privacy_policy_integration
history_integration
no_elevate_path_gate
resource_permissions_integration
permission_request_notifications_integration
principal_connection_migration_integration
super_user_scripts_integration
search_source_dispatch_integration
manifest_sync_integration
permission_check_emission_integration
```

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-gauge

cargo fmt -p gauge -p embedded-gauge-host -- --check
cargo clippy -p gauge --features ssr --lib -- -D warnings
cargo clippy -p gauge --features ssr \
  --test permission_domain_contract \
  --test permission_flows_integration \
  --test privacy_authorization_integration \
  --test privacy_policy_integration \
  --test history_integration \
  --test no_elevate_path_gate \
  --test resource_permissions_integration \
  --test permission_request_notifications_integration \
  --test principal_connection_migration_integration \
  --test super_user_scripts_integration \
  --test search_source_dispatch_integration \
  --test manifest_sync_integration \
  --test permission_check_emission_integration \
  -- -D warnings
cargo clippy -p embedded-gauge-host --all-targets -- -D warnings
cargo test -p gauge --test workspace_members --test product_surface
cargo test -p gauge --features ssr \
  --test permission_domain_contract \
  --test permission_flows_integration \
  --test privacy_authorization_integration \
  --test privacy_policy_integration \
  --test history_integration \
  --test no_elevate_path_gate \
  --test resource_permissions_integration \
  --test permission_request_notifications_integration \
  --test principal_connection_migration_integration \
  --test super_user_scripts_integration \
  --test search_source_dispatch_integration \
  --test manifest_sync_integration \
  --test permission_check_emission_integration
cargo check -p embedded-gauge-host
cargo run -p embedded-gauge-host
RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc -p gauge --features ssr --no-deps
```

`product_surface` reads `L4-composers/gauge-uf-app` when present (local monorepo);
each needle test **returns early** when that tree is absent so standalone uf-dev CI stays green.
Domain contract suites above are the behavioral merge gate.

Do not run `--all-targets` clippy on `gauge`: older smoke suites
(`trait_registry_smoke`, `search_registry_integration`) stay outside the primary
matrix. Clippy CI uses `-- -D warnings` for the scoped targets (workspace deny
lints still apply).

### leptos-lints (local; not a CI hard gate)

Needs `cargo-dylint` / `dylint-link` 6.0.1 and toolchain `nightly-2025-05-14`
(leptos-lints v0.1.2 pin). Domain CI does not hard-gate hydrate dylint — UI
lives in gauge-uf-app.

```bash
# cargo install cargo-dylint --locked --version 6.0.1
# cargo install dylint-link --locked --version 6.0.1
# rustup toolchain install nightly-2025-05-14 --component rustc-dev,llvm-tools-preview

export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
export RUSTFLAGS="-D warnings -Zcrate-attr=feature(stdarch_x86_avx512)"
cargo dylint --all -p gauge-app --no-deps -- --features hydrate
```

Focused contract suite:

```bash
cargo test -p gauge --features ssr --test permission_domain_contract
```

`gauge-app` (Leptos UI + Higgs `#[server]` wrappers) may fail to compile when the
host Orbital / `uf-product` graph drifts. Prefer the `gauge` crate for CI contract
gates; treat UI-crate compile failures as a separate host product issue.
## Layer 2 — E2E

Product UI Playwright lives in the sibling **gauge-uf-app** workspace
(`gauge-uf-app-e2e`). Domain Layer 1 integ remains the primary gate for service
contracts; Layer 2 covers Higgs/`PermissionRoutes` operator workflows.

From gauge-uf-app (see that repo’s `docs/VERIFICATION.md` and
`gauge-uf-app-e2e/README.md` for the full scenario catalog):

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-gauge-uf-app
cd ~/unified-field/L4-composers/gauge-uf-app
cd gauge-uf-app-e2e/end2end && npm ci && npx playwright install chromium && cd ../..
cargo leptos end-to-end --project gauge-uf-app-e2e
```

Layer 1 integ still covers service happy/sad (named below). Sibling-source UI
needles stay in `product_surface`.

Covering integ tests (service primary):

- `permission_workflow_domain_grant_request_review_happy_path`
- `grant_revoke_direct_and_group_inheritance_happy_path`
- `permission_request_approve_grants_access_happy_path`
- `domain_create_list_get_happy_path`
- `create_and_mutate_permission_flows_happy_path`
- `actor_can_unknown_permission_returns_false_happy_path`
- `actor_can_empty_permission_name_returns_false_sad`
- `duplicate_permission_and_group_names_rejected_sad`
- `create_permission_missing_domain_rejected_sad`
- `non_owner_cannot_grant_permission_sad`
- `non_owner_cannot_update_group_sad`
- `unauthenticated_cannot_create_group_sad`
- `unauthenticated_cannot_list_or_create_domain_sad`
  (`list_domains` / `get_domain_detail` / `create_domain`)
- `owners_group_member_cannot_mutate_permission_sad`
- `duplicate_named_super_user_group_does_not_grant_privilege_sad`
- `create_permission_request_empty_reason_rejected_sad`
- `create_permission_request_already_has_permission_rejected_sad`
- `get_permission_request_detail_unauthorized_viewer_sad`
- `outsider_cannot_decide_permission_request_sad`
- `owner_can_delegate_group_ownership` / `owner_can_remove_delegated_group_owner`
- `history_tracks_description_and_membership_changes` /
  `list_history_hides_subjects_outsider_cannot_edit_sad`
- `creator_becomes_maintainer_outsider_cannot_update_tm_sec_07`
- `service_and_side_effects_must_not_elevate_to_system_tm_sec_06`
  (`no_elevate_path_gate`)
- privacy policy Model A: owner Valence mutate Ok / non-owner denied /
  Super User Ok / session principal walk (`privacy_policy_integration`)
- `ensure_creates_bundle_and_maintainer_owns_maintain` /
  `ensure_rejects_missing_maintainer` / `ensure_rejects_invalid_resource_id`
- `create_permission_request_notifies_permission_owners` /
  `create_permission_request_does_not_notify_non_owners_sad`
- `search_registry_dispatches_to_registered_sources` /
  `search_registry_no_match_returns_empty_sad`
- `migration_script_backfills_principal_edges_idempotently` /
  `migration_fails_when_legacy_user_edge_targets_missing_user_sad`
- `ensure_super_user_group_script_is_idempotent_and_sync_seeds_roles` /
  `seed_super_user_member_by_email_rejects_unknown_email_sad`
- `nested_group_membership_inherits_permission_happy_path` /
  `nested_group_remove_breaks_inheritance_happy_path` /
  `add_group_member_group_self_rejected_sad` /
  `non_owner_cannot_add_group_member_group_sad`
- `group_request_approve_adds_member_happy_path` /
  `group_request_deny_does_not_add_member_sad`
- `decide_non_pending_request_rejected_sad`
- `owner_delete_group_happy_path` / `non_owner_cannot_delete_group_sad`
- `sync_permission_manifest_creates_rows_happy_path` /
  `sync_permission_manifest_empty_is_noop_sad`
- `ensure_gluon_operator_groups_idempotent_happy_path` /
  `ensure_gluon_operator_groups_before_manifest_skips_grants_sad`
- `actor_can_records_allow_and_deny_outcomes_happy_path` /
  `actor_can_empty_name_and_no_actor_record_outcomes_sad`

Sibling-source UI contracts (also Layer 1; **smoke / needle**, not primary
behavioral coverage):

- `gauge_product_workspace_members_happy_path`
- `permission_routes_mount_happy_path` / `permission_routes_drop_leaf_sad_path`
- `layout_auth_gate_and_nav_happy_path` / `layout_drop_auth_guard_sad_path`
- `admin_mutations_require_gauge_admin_happy_path` / `request_workflow_must_not_require_gauge_admin_sad_path`
- `index_pages_testid_and_list_bindings_happy_path` / `request_detail_decide_binding_happy_path`

Runtime GaugeAdmin deny (TM-SEC-09) is Layer 2 in gauge-uf-app-e2e:
`e2e.perm.detail.save_no_admin`, `e2e.group.detail.save_no_admin`,
`e2e.search.principals_no_admin`, and related `*_no_admin` scenarios.

## Layer 3 — Cloud + performance

**Waived.** This workspace; no cloud resources or Criterion benches.
Correctness is in-process against Valence in-memory storage (`MEM_ENGINE_ID`;
gauge `DEFAULT_STORAGE`). Tests also alias `SQLITE_ENGINE_ID` for lepton `User`
rows when needed.

## Rustdoc

Workspace `Cargo.toml` allows `broken_intra_doc_links` by default. Honest local
deny for the domain crate:

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-gauge
RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc -p gauge --features ssr --no-deps
```

Guide-contract audit (after `cargo doc`; use an **absolute** `--doc-root`):

```bash
CONTRACT=~/unified-field/uf-docs-guide-contracts/workspaces/gauge
python3 ~/.cursor/skills/uf-high-signal-docs/guide_audit.py \
  "$CONTRACT/doc-guide-spec.toml" \
  --doc-root "$PWD/target-gauge/doc" \
  --freeze "$CONTRACT/doc-guide-freeze.json"
```

`gauge-app` rustdoc lives in the sibling gauge-uf-app workspace (`target-gauge-uf-app`)
and is pin-dependent on Orbital / `uf-product`. Prefer the `gauge` gate above for
docs CI signal.

## Notes

- Prefer `cargo test -p gauge --features ssr` with the named primary suites above
  for backend contract CI.
- Prefer `cargo test -p gauge --test workspace_members --test product_surface` for
  UI surface **smoke** gates (source needles; not primary behavioral coverage).
- Tests may `unwrap`/`expect`; production server fns map failures to
  `ServerFnError` (no ordinary-path unwrap).
- Sad-path assertions check message content, typed variants, or explicit `false`
  — stronger than `is_err()` alone.
- Happy-path tests are named `*_happy_path` so audits detect them; primary
  coverage also includes named `*_sad` cases with classifying asserts.
- `PermissionRoutes` / gauge-app server fns wrap `gauge::service::*`.
- Registry discovery suites (`trait_registry_smoke`, `search_registry_integration`)
  are intentional smokes and are not CI primary gates.