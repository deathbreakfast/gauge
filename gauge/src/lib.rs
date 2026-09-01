//! Permission domain runtime and APIs.
//!
//! Authorization library for hosts: permission taxonomy, principal and group
//! relationships, access checks, and request/review workflows. Valence schemas
//! and `service` rules live here. The Orbital admin UI is the sibling crate
//! `gauge-app` in [gauge-uf-app](https://github.com/unified-field-dev/gauge-uf-app).
//!
//! ## Features
//!
//! - **Runtime access checks** — Resolve whether the current Valence actor
//!   (or an explicit user) holds a named permission, including nested group
//!   inheritance. Use on route guards and sensitive server paths.
//!   [Get started](#runtime-access-checks)
//! - **Resource ACL anatomy** — The domain, owners group, and per-action
//!   permissions that appear when a product creates a resource, with the real
//!   row names so you can find them.
//!   [Get started](#what-a-resource-bundle-creates)
//! - **Per-kind grant policy** — Which principals get access to a resource
//!   automatically, how that differs between secrets, apps, and stacks, and
//!   what Super User can always do.
//!   [Get started](#who-can-act-on-a-resource)
//! - **Bundle teardown** — Remove a resource's ACL when the resource goes away,
//!   in the order the schema's Restrict edges require.
//!   [Get started](#delete-a-resource-bundle)
//! - **Resource permission bundles** — Idempotent catalog seed for resource-kind
//!   groups and coarse Create* permissions. Product crates wrap
//!   [`resource_permissions::seed_resource_kind_catalog`]; create/seal then
//!   auto-ensures per-resource bundles.
//!   [Get started](#resource-permission-bootstrap)
//! - **App permission manifest sync** — Idempotent materialization of
//!   enum-first app manifests into Valence domain/permission rows and a per-app
//!   owners group. Hosts call this at boot after schema inventory is linked.
//!   [Get started](#app-permission-manifest-sync)
//! - **Permission taxonomy CRUD** — Create and manage domains, permissions, and
//!   groups (owners, nested membership) that back admin screens and grants.
//!   [Get started](#domain-permission-and-group-crud)
//! - **Grant and revoke** — Attach or remove direct user/group allow-list entries
//!   on a permission, with history recorded for operators.
//!   [Get started](#grant-and-revoke-allow-lists)
//! - **Request and review workflow** — Let actors request access and eligible
//!   reviewers approve or deny pending rows.
//!   [Get started](#permission-request-and-review)
//! - **Super User group** — Chronon/script helpers that ensure the well-known
//!   Super User group exists at boot so privilege is pinned to a fixed group id.
//!   [Get started](#super-user-bootstrap)
//!
//! Domain CRUD and access checks return `anyhow::Result`; classifiable failures
//! use [`service::GaugeServiceError`] (downcast). Host resource wiring returns
//! [`resource_permissions::ResourcePermissionError`]. Route-guard server
//! functions use Leptos `ServerFnError`. Session chrome and identity providers
//! stay in the host (lepton / higgs); admin pages and Higgs wrappers stay in
//! `gauge-app`.
//!
//! ## Runtime access checks
//!
//! [`service::actor_can`] is the primary route-guard check. It reads the calling
//! Valence actor's user id, then evaluates direct grants and grants inherited
//! through nested group membership. Call it on each protected request (or inside
//! a server function) when you need a boolean allow/deny for a permission name.
//!
//! **Prerequisites:** `ssr` feature; a `Valence` handle whose actor is the
//! caller (or use [`service::user_can`] with an explicit user id for admin
//! screens). [`service::has_permission`] is a same-signature alias of `actor_can`.
//!
//! 1. Obtain `Valence` for the request actor.
//! 2. Call `actor_can(&v, "permission.name")`.
//! 3. On `false`, reject the request (hosts often map this to a `GaugeError` or
//!    `ServerFnError`).
//!
//! ```ignore
//! use gauge::service::actor_can;
//!
//! // `v` carries the current request's actor (e.g. from an Orbital route guard).
//! let allowed = actor_can(&v, "CreateGluonApplications").await?;
//! assert!(!allowed); // outsider before grant
//! if !allowed {
//!     // Host maps deny to GaugeError / ServerFnError
//!     return Err(anyhow::anyhow!("not authorized"));
//! }
//! ```
//!
//! ### Typed vs raw-walk checks
//!
//! | Call site | Use |
//! |-----------|-----|
//! | Route guards, server functions, ordinary request code | [`service::actor_can`] (Spectra telemetry + request cache) |
//! | Inside a Valence `PolicyEvaluator` / privacy rule | [`actor_can_raw::actor_can_raw`] (or [`service::actor_can_raw`]) |
//!
//! Typed `actor_can` re-enters ORM privacy via `Permission::query` and elevates
//! for Super User detection. Calling it from a privacy evaluator stack-overflows.
//! `actor_can_raw` walks the grant graph with raw backend reads and a visited-set
//! guard — that is the only form safe under privacy evaluation.
//!
//! ```ignore
//! use gauge::actor_can_raw::actor_can_raw;
//!
//! // Safe from a PolicyEvaluator that already holds `&Valence`.
//! let allowed = actor_can_raw(&v, "neutrino_secret.abc_123deadbeef.Reveal").await?;
//! assert!(!allowed);
//! ```
//!
//! On success you get `Ok(true)` or `Ok(false)`. Resolution errors surface as
//! `anyhow::Error` (missing schema/graph). Next: [Grant and revoke](#grant-and-revoke-allow-lists)
//! or [Who can act on a resource](#who-can-act-on-a-resource).
//!
//! ## Resource permission bootstrap
//!
//! Before serving product create/seal APIs, seed each resource kind’s default
//! groups and coarse Create* permission via
//! [`resource_permissions::seed_resource_kind_catalog`] (idempotent). Product
//! crates expose wrappers (`gluon::create_initial_gluon_groups`,
//! `neutrino::create_initial_neutrino_groups`,
//! `nucleus::credentials::create_initial_nucleus_groups`) that call the seed
//! with fixed domain ids. Per-resource bundles then come from
//! [`resource_permissions::ensure_resource_permission_bundle`]. Host owners run
//! this during startup wiring, not per request.
//!
//! **Prerequisites:** `ssr`; Valence with schema inventory linked
//! ([`touch_schema_inventory`]).
//!
//! 1. At boot, call the product wrapper (or `seed_resource_kind_catalog` for a
//!    custom kind).
//! 2. Proceed to product create APIs that call `ensure_resource_permission_bundle`.
//!
//! ```ignore
//! use gauge::resource_permissions::{
//!     seed_resource_kind_catalog, ResourceKind, ResourcePermissionError,
//! };
//!
//! async fn wire(valence: &valence::Valence) -> Result<(), ResourcePermissionError> {
//!     seed_resource_kind_catalog(
//!         valence,
//!         ResourceKind::GluonApp,
//!         "rp_catalog_gluon_app",
//!         "Gluon application create",
//!         "rp_perm_create_gluon_applications",
//!     )
//!     .await?;
//!     Ok(())
//! }
//! assert!(matches!(wire(&valence).await, Ok(())));
//! ```
//!
//! On success each helper returns `Ok(())`. Typed failures use
//! [`resource_permissions::ResourcePermissionError`]. Next: [What a resource
//! bundle creates](#what-a-resource-bundle-creates) or
//! [App permission manifest sync](#app-permission-manifest-sync).
//!
//! ## What a resource bundle creates
//!
//! When a product create/seal path calls
//! [`resource_permissions::ensure_resource_permission_bundle`], Gauge writes a
//! fixed set of Valence rows for that one resource. Host catalog seed
//! ([Resource permission bootstrap](#resource-permission-bootstrap)) must already
//! have run so umbrella groups and the coarse Create* permission exist.
//!
//! **Prerequisites:** `ssr`; catalog seeded for the kind; a non-empty maintainer
//! user id.
//!
//! For resource id `abc-123` of kind Neutrino secret, expect rows like:
//!
//! 1. `PermissionDomain` — id `rp_domain_neutrino_secret_{normalized}`, with
//!    `resource_scoped = true` and `resource_id` set to the raw id. The marker
//!    does not deny catalog reads today; it is a tenancy / UI hook.
//! 2. Owners group — id `rp_owners_neutrino_secret_{normalized}` (the maintainer
//!    group; there is no single-maintainer slot).
//! 3. One permission per action — name
//!    `neutrino_secret.{normalized}.{Action}` (for example
//!    `neutrino_secret.abc_123_{digest}.Reveal`). Build names with
//!    [`resource_permissions::permission_name`].
//! 4. Every action on that resource, including `Maintain`, granted to the owners
//!    group.
//! 5. The caller-supplied maintainer added as an owner of that group.
//! 6. Umbrella grants for the kind — see [Who can act on a resource](#who-can-act-on-a-resource).
//!
//! `ensure` does **not** create shared user principals, umbrella groups, or the
//! coarse Create* permission; those are pre-existing catalog rows.
//!
//! ```ignore
//! use gauge::resource_permissions::{
//!     ensure_resource_permission_bundle, permission_name, ResourceAction,
//!     ResourceKind, ResourcePermissionSpec,
//! };
//!
//! let bundle = ensure_resource_permission_bundle(
//!     &valence,
//!     ResourcePermissionSpec {
//!         kind: ResourceKind::NeutrinoSecret,
//!         resource_id: "abc-123".into(),
//!         display_name: "Demo secret".into(),
//!         actions: vec![],
//!         maintainer_actor: "alice".into(),
//!     },
//! )
//! .await?;
//! let reveal = permission_name(
//!     ResourceKind::NeutrinoSecret,
//!     "abc-123",
//!     ResourceAction::Reveal,
//! );
//! assert!(reveal.starts_with("neutrino_secret."));
//! assert!(reveal.ends_with(".Reveal"));
//! assert_eq!(bundle.name_for(ResourceAction::Reveal), Some(reveal.as_str()));
//! ```
//!
//! Typed failures use [`resource_permissions::ResourcePermissionError`]. Next:
//! [Who can act on a resource](#who-can-act-on-a-resource) or
//! [Bundle teardown](#delete-a-resource-bundle).
//!
//! ## Who can act on a resource
//!
//! Per-resource access comes from the grant graph `ensure` builds. The table is
//! the source of truth; [`resource_permissions::ResourceKind::umbrella_policy`] /
//! [`resource_permissions::UmbrellaPolicy`] encode the umbrella column in code.
//!
//! | Principal | Gets |
//! |-----------|------|
//! | Owners-group member (`rp_owners_*`) | Every action on that one resource, including `Maintain` |
//! | Holder of `{kind}.{id}.{Action}` | That one action on that one resource |
//! | `gluon.app.*` / `nucleus.stack.*` umbrella groups | Kind-wide access on every resource of their kind |
//! | `neutrino.secret.viewers` / `.operators` | Nothing per-secret after umbrella narrowing (`UmbrellaPolicy::None`). Those groups previously received View, Reveal, Edit, and Delete on every secret |
//! | Coarse `Create*` holders | May create new resources; no access to existing ones |
//! | Super User (`super_user_group`) | Full maintainer access on every bundle of every kind, with no grant and no group membership. Privilege is pinned to the group id |
//! | System | Bypasses these checks entirely |
//!
//! Super User access is unconditional: a resource maintainer cannot exclude it.
//! See [Super User bootstrap](#super-user-bootstrap). Neutrino operators upgrading
//! past umbrella narrowing need an explicit per-secret grant (or owners-group
//! membership) for Reveal and other actions.
//!
//! ```ignore
//! use gauge::resource_permissions::{
//!     permission_name, ResourceAction, ResourceKind, UmbrellaPolicy,
//! };
//! use gauge::service::actor_can;
//!
//! assert_eq!(
//!     ResourceKind::NeutrinoSecret.umbrella_policy(),
//!     UmbrellaPolicy::None
//! );
//! let reveal = permission_name(
//!     ResourceKind::NeutrinoSecret,
//!     "abc-123",
//!     ResourceAction::Reveal,
//! );
//! assert!(actor_can(&maintainer_v, &reveal).await?);
//! assert!(!actor_can(&operator_v, &reveal).await?);
//! ```
//!
//! Next: [Runtime access checks](#runtime-access-checks) or
//! [Delete a resource bundle](#delete-a-resource-bundle).
//!
//! ## Delete a resource bundle
//!
//! [`resource_permissions::delete_resource_permission_bundle`] removes the ACL
//! for one resource when the resource itself is deleted. Schema Restrict edges
//! force the order: per-resource permissions first, then the owners group, then
//! the domain. Allowed-principal M2M edges cascade with the permission rows.
//!
//! The call runs as System internally because `permission_domain` delete is
//! Super-User-only (same elevation pattern as `ensure`). It is idempotent: a
//! never-ensured or already-removed resource returns `Ok(())`. Umbrella groups,
//! shared user principals, and catalog Create* permissions survive.
//!
//! **Prerequisites:** `ssr`; Valence with Gauge schemas linked.
//!
//! ```ignore
//! use gauge::resource_permissions::{
//!     delete_resource_permission_bundle, ResourceKind,
//! };
//!
//! delete_resource_permission_bundle(
//!     &valence,
//!     ResourceKind::GluonApp,
//!     "app-del",
//! )
//! .await?;
//! assert!(matches!(
//!     delete_resource_permission_bundle(
//!         &valence,
//!         ResourceKind::GluonApp,
//!         "never-ensured",
//!     )
//!     .await,
//!     Ok(())
//! ));
//! ```
//!
//! Typed failures use [`resource_permissions::ResourcePermissionError`]. Next:
//! [What a resource bundle creates](#what-a-resource-bundle-creates).
//!
//! ## App permission manifest sync
//!
//! [`manifest_sync::sync_permission_manifests`] turns compile-time app catalogs
//! ([`manifest_sync::PermissionManifestInput`] rows, often mapped from
//! uf-product `AppPermissionManifest` / `UfPermissionManifest` derives) into
//! Valence `PermissionDomain` and `Permission` records plus an auto-managed
//! owners group per `app_id`. Existing domains (normalized key) and permissions
//! (by name) are left alone; only missing rows are created. Call it once at host
//! boot with a system Valence after [`touch_schema_inventory`], before serving
//! routes that depend on those names.
//!
//! **Prerequisites:** `ssr`; Valence with Gauge schemas linked; manifests built
//! as `&[PermissionManifestInput]` (host maps from product inventory).
//!
//! 1. Build one [`manifest_sync::PermissionManifestInput`] per app (domains + permission names).
//! 2. Call `sync_permission_manifests(&valence, &manifests)`.
//! 3. Inspect [`manifest_sync::ManifestSyncStats`] (created vs existing counts).
//! 4. Wire route/`PermissionBackend` checks; names must match the synced catalog.
//!
//! ```ignore
//! use gauge::manifest_sync::{
//!     sync_permission_manifests, PermissionDomainInput, PermissionInput,
//!     PermissionManifestInput,
//! };
//!
//! let manifests = [PermissionManifestInput {
//!     app_id: "counter".into(),
//!     domains: vec![PermissionDomainInput {
//!         key: "counter_admin".into(),
//!         name: "Counter Admin".into(),
//!         description: "Administrative actions".into(),
//!         permissions: vec![PermissionInput {
//!             name: "counter.admin.set".into(),
//!             description: "Change the global counter value".into(),
//!         }],
//!     }],
//! }];
//! let first = sync_permission_manifests(&system_valence, &manifests).await?;
//! assert!(first.permissions_created >= 1 || first.permissions_existing >= 1);
//! let second = sync_permission_manifests(&system_valence, &manifests).await?;
//! assert_eq!(second.permissions_created, 0);
//! assert!(second.permissions_existing >= 1);
//! ```
//!
//! Returns [`manifest_sync::ManifestSyncStats`] on success. Valence create/lookup failures
//! surface as `anyhow::Error`. Empty manifest slices are a no-op (zero stats).
//! Hosts may also schedule a Chronon reconcile job that re-runs the same sync
//! after deploys. Next: [Runtime access checks](#runtime-access-checks) or
//! [Permission taxonomy CRUD](#domain-permission-and-group-crud) for ad-hoc rows.
//!
//! ## Domain, permission, and group CRUD
//!
//! Taxonomy CRUD builds the domains, named permissions, and owner groups that
//! grants and admin UI operate on. Operators (or seed scripts) call these under
//! an authenticated Valence actor before wiring grants.
//!
//! **Prerequisites:** `ssr`; authenticated actor on `Valence`.
//!
//! 1. `create_domain` for a taxonomy root.
//! 2. `create_group` for an owners group.
//! 3. `create_permission` under that domain and owners group.
//!
//! ```ignore
//! use gauge::service::{create_domain, create_group, create_permission};
//! use gauge::types::{
//!     PermissionCreateInput, PermissionDomainCreateInput, PermissionGroupCreateInput,
//! };
//!
//! let domain = create_domain(
//!     PermissionDomainCreateInput {
//!         name: "gluon".into(),
//!         description: "Gluon applications and cloud".into(),
//!     },
//!     &v,
//! )
//! .await?;
//! assert_eq!(domain.name(), "gluon");
//!
//! let group = create_group(
//!     PermissionGroupCreateInput {
//!         name: "gluon.app.creators".into(),
//!         description: "Owners".into(),
//!     },
//!     &v,
//! )
//! .await?;
//!
//! let permission = create_permission(
//!     PermissionCreateInput {
//!         name: "CreateGluonApplications".into(),
//!         description: "Create Gluon applications".into(),
//!         owners_group_id: /* group id */ String::new(),
//!         domain_id: /* domain id */ String::new(),
//!     },
//!     &v,
//! )
//! .await?;
//! assert_eq!(permission.name(), "CreateGluonApplications");
//! ```
//!
//! Duplicate names and empty required fields return `anyhow` errors. List/get/
//! update/delete helpers live on [`service`]. Next:
//! [Grant and revoke](#grant-and-revoke-allow-lists).
//!
//! ## Grant and revoke allow-lists
//!
//! Direct allow-list grants attach a user (or group) to a permission so
//! `actor_can` succeeds after inheritance is resolved. Owners and Super Users
//! call grant/revoke when changing who may act; each change records history.
//!
//! **Prerequisites:** `ssr`; actor that can edit the permission's owners group.
//!
//! 1. `grant_permission_to_user` with permission id and target user id.
//! 2. Confirm with `actor_can` / `user_can`.
//! 3. `revoke_permission_from_user` to remove the direct grant.
//!
//! ```ignore
//! use gauge::service::{
//!     actor_can, grant_permission_to_user, revoke_permission_from_user,
//! };
//!
//! grant_permission_to_user(&permission_id, "alice", &v).await?;
//! assert!(actor_can(&alice_v, "CreateGluonApplications").await?);
//!
//! revoke_permission_from_user(&permission_id, "alice", &v).await?;
//! assert!(!actor_can(&alice_v, "CreateGluonApplications").await?);
//! assert!(matches!(
//!     revoke_permission_from_user(&permission_id, "alice", &v).await,
//!     Ok(())
//! ));
//! ```
//!
//! Unauthorized editors and missing permission ids return `anyhow` errors.
//! Group variants: `grant_permission_to_group` / `revoke_permission_from_group`.
//! Next: [Permission request and review](#permission-request-and-review).
//!
//! ## Permission request and review
//!
//! Request/review lets an actor ask for a permission or group membership and an
//! eligible reviewer approve or deny. Use this when self-service access is
//! preferred over an owner granting directly.
//!
//! **Prerequisites:** `ssr`; requestor authenticated; reviewer must own the
//! target (or be Super User) to decide.
//!
//! 1. `create_permission_request` with target and reason.
//! 2. Reviewer calls `decide_permission_request` with
//!    [`types::PermissionRequestDecision::Approve`] or `Deny`.
//!
//! ```ignore
//! use gauge::service::{create_permission_request, decide_permission_request};
//! use gauge::types::{
//!     PermissionRequestCreateInput, PermissionRequestDecision,
//!     PermissionRequestDecisionInput, PermissionRequestRowDto,
//!     PermissionRequestTargetKind,
//! };
//!
//! let row: PermissionRequestRowDto = create_permission_request(
//!     PermissionRequestCreateInput {
//!         target_kind: PermissionRequestTargetKind::Permission,
//!         target_id: permission_id.clone(),
//!         reason: "Need create access for a new application".into(),
//!     },
//!     &requestor_v,
//! )
//! .await?;
//! assert!(!row.id.is_empty());
//!
//! let decided: PermissionRequestRowDto = decide_permission_request(
//!     PermissionRequestDecisionInput {
//!         request_id: row.id.clone(),
//!         decision: PermissionRequestDecision::Approve,
//!     },
//!     &owner_v,
//! )
//! .await?;
//! assert!(matches!(
//!     decided.status,
//!     gauge::types::PermissionRequestStatusDto::Approved
//! ));
//! ```
//!
//! Empty/overlong reasons, already-held access, and unauthorized reviewers fail
//! with `anyhow`. Inbox helpers: `list_permission_requests_for_actor` /
//! `list_permission_requests_for_review`. Next:
//! [Runtime access checks](#runtime-access-checks).
//!
//! ## Super User bootstrap
//!
//! [`scripts::ensure_super_user_group_script`] ensures the well-known Super User
//! group exists (fixed id `super_user_group`) so bypass privilege is pinned to
//! that id, not a display name. Hosts or Chronon run this once at boot (or via
//! the default run-once job), not on every request.
//!
//! Members of that group have full maintainer access on every resource permission
//! bundle of every kind, with no grant and no owners-group membership. A resource
//! maintainer cannot exclude them. See [Who can act on a resource](#who-can-act-on-a-resource).
//!
//! **Prerequisites:** `ssr`; Chronon script context (or call
//! [`super_user::ensure_super_user_group`] with a system Valence in tests).
//!
//! 1. Register/run `ensure_super_user_group_script` at boot.
//! 2. Confirm membership sync scripts if you pin operators into the group.
//!
//! ```ignore
//! use gauge::scripts::ensure_super_user_group_script;
//! // Chronon delivers `ctx`; the script loads Valence and ensures the group.
//! // In tests, prefer `gauge::super_user::ensure_super_user_group(&system).await?`.
//! let result = ensure_super_user_group_script(ctx).await;
//! assert!(matches!(result, Ok(())));
//! ```
//!
//! Failures wrap as `anyhow` with context (`failed ensuring Super User group`).
//! See root `SECURITY.md` for id vs display-name pinning. Next:
//! [Runtime access checks](#runtime-access-checks).
//!
//! ## Feature flags
//!
//! | Flag | What it enables |
//! |------|-----------------|
//! | `ssr` | Service APIs, Valence schemas, resource bundles, scripts, Super User helpers |
//! | `spectra-topics` | Permission-check Spectra topic types via `spectra_topics` without full `ssr` |
//! | `db-sqlite` / `db-hybrid` | Valence storage backends for hosts that select them |
//!
//! ## Examples
//!
//! Start with [Runtime access checks](#runtime-access-checks) for route-guard
//! `actor_can` calls, [What a resource bundle creates](#what-a-resource-bundle-creates)
//! for per-resource row names, [Who can act on a resource](#who-can-act-on-a-resource)
//! for the grant table, [App permission manifest sync](#app-permission-manifest-sync)
//! for enum catalogs at boot, and [Resource permission bootstrap](#resource-permission-bootstrap)
//! for per-resource kind seed.
//!
//! Run `cargo test -p gauge --test permission_domain_contract`,
//! `cargo test -p gauge --test resource_permissions_integration`, and
//! `cargo test -p gauge --test permission_flows_integration`.
//!
//! For a headless host sketch (bootstrap, deny/allow), see workspace example
//! `embedded-gauge-host` and its README.
//!
//! Related surfaces: route-guard [`server`] fns, [`search_sources`],
//! [`instrumentation`], [`privacy_policies`], DTO contracts in [`types`].

pub mod server;
pub mod types;

#[cfg(feature = "ssr")]
pub mod embedded_surreal;
#[cfg(feature = "ssr")]
pub mod generated;
#[cfg(feature = "ssr")]
mod schemas;

/// Force-link all schema/trait `inventory` submissions and initialize the global
/// [`valence::TraitRegistry`]. Called once at load via a retained static initializer;
/// safe to call again.
#[cfg(feature = "ssr")]
#[inline(never)]
pub fn touch_schema_inventory() {
    schemas::ensure_inventory_linked();
    // Initialize after schema modules are linked so implementors are visible.
    let _ = valence::TraitRegistry::global();
}

#[cfg(feature = "ssr")]
#[inline(never)]
fn ensure_schema_inventory_linked() {
    touch_schema_inventory();
}

#[cfg(feature = "ssr")]
#[used]
static __GAUGE_SCHEMA_INVENTORY: fn() = ensure_schema_inventory_linked;

#[cfg(feature = "ssr")]
pub mod spectra_schemas;

/// Re-export of the Spectra topic types for consumers that only need the
/// `spectra-topics` feature (without pulling in the full `ssr` feature).
#[cfg(feature = "spectra-topics")]
pub mod spectra_topics {
    pub use crate::spectra_schemas::gauge_permission_check_log::*;
    pub use crate::spectra_schemas::gauge_permission_checks::*;
}

#[cfg(feature = "ssr")]
pub mod instrumentation;

#[cfg(feature = "ssr")]
pub mod actor_can_raw;
#[cfg(feature = "ssr")]
pub mod gluon_operator_groups;
#[cfg(feature = "ssr")]
pub mod manifest_sync;
#[cfg(feature = "ssr")]
pub mod privacy_policies;
#[cfg(feature = "ssr")]
pub mod resource_permissions;
#[cfg(feature = "ssr")]
pub mod scripts;
pub mod search_sources;
#[cfg(feature = "ssr")]
pub mod service;
#[cfg(feature = "ssr")]
pub mod side_effects;
#[cfg(feature = "ssr")]
pub mod super_user;
