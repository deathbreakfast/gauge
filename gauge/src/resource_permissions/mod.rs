//! Per-resource Gauge permission bundles and host catalog seeding.
//!
//! # Owns
//!
//! - Host catalog seed: [`crate::resource_permissions::seed_resource_kind_catalog`]
//! - Per-resource ensure: [`crate::resource_permissions::ensure_resource_permission_bundle`]
//!   (creator = Maintain owner)
//! - Valence privacy helpers: [`crate::resource_permissions::StaticPermissionGate`],
//!   [`crate::resource_permissions::ResourcePermissionPolicy`] (products declare their
//!   own `CREATE_*` / `*_RESOURCE` consts beside their descriptors)
//!
//! # Does not own
//!
//! - Product-named bootstraps (`create_initial_*_groups` live on Gluon / Neutrino /
//!   Nucleus and call [`seed_resource_kind_catalog`])
//! - Product create/seal orchestration (Neutrino / Gluon / Nucleus call ensure internally)
//! - Product-named Valence privacy consts (`CREATE_*`, `*_RESOURCE` live on Gluon /
//!   Neutrino / Nucleus)
//! - Static app manifests ([`crate::manifest_sync`]) or Gluon registry operator groups
//!   ([`crate::gluon_operator_groups`])
//!
//! # Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Host wiring (per resource kind) | [`crate::resource_permissions::seed_resource_kind_catalog`] |
//! | Per-resource domain + actions | [`crate::resource_permissions::ensure_resource_permission_bundle`] |
//! | What a bundle creates (crate guide) | [What a resource bundle creates](crate#what-a-resource-bundle-creates) |
//! | Who can act on a resource | [Who can act on a resource](crate#who-can-act-on-a-resource) |
//! | Tear down per-resource ACL | [`crate::resource_permissions::delete_resource_permission_bundle`] |
//! | Revoke standing umbrella grants | [`crate::resource_permissions::revoke_umbrella_grants`] |
//! | Typed host-wiring errors | [`crate::resource_permissions::ResourcePermissionError`] |
//! | Permission name for `actor_can` | [`crate::resource_permissions::permission_name`] |
//! | Per-kind umbrella grants | [`crate::resource_permissions::UmbrellaPolicy`] / [`ResourceKind::umbrella_policy`] |
//! | Declare a product-owned kind | [`crate::resource_permissions::ResourceKindDescriptor`] |
//! | Coarse create privacy type | [`crate::resource_permissions::StaticPermissionGate`] |
//! | Per-resource CRUD privacy type | [`crate::resource_permissions::ResourcePermissionPolicy`] |
//!
//! # Host wiring (required)
//!
//! Prefer product helpers (`gluon::create_initial_gluon_groups`, …). For a custom
//! kind, call [`seed_resource_kind_catalog`] during bootstrap **before** serving
//! create/seal APIs (same phase as manifest sync /
//! [`crate::gluon_operator_groups::ensure_gluon_default_operator_groups`]):
//!
//! ```ignore
//! use gauge::resource_permissions::{
//!     seed_resource_kind_catalog, ResourceKind, ResourcePermissionError,
//! };
//!
//! // Prerequisites: Valence bootstrapped with Gauge schemas (System actor ok).
//! async fn wire_custom_kind(
//!     valence: &valence::Valence,
//! ) -> Result<(), ResourcePermissionError> {
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
//! ```
//!
//! Product APIs then auto-ensure per-resource bundles; integrators do **not** call
//! [`crate::resource_permissions::ensure_resource_permission_bundle`] as a second step after create.
//!
//! # Kinds Gauge does not name
//!
//! [`ResourceKind`] is a **frozen wire-format compatibility shim** for the four
//! kinds that predate [`crate::resource_permissions::ResourceKindDescriptor`].
//! Products must declare their own `const ResourceKindDescriptor` and
//! [`StaticPermissionGate`] / [`ResourcePermissionPolicy`] consts; do not add
//! variants here. A later Gauge publish can retire the enum once golden tests and
//! git consumers no longer need the variants. Until then, prefer
//! [`ResourceKind::descriptor`] or a product descriptor over the enum itself.

mod default_groups;
mod ensure;
mod error;
#[cfg(test)]
mod golden_names;
mod kinds;
mod policy;
mod revoke_umbrella_grants;
mod spec;

pub use default_groups::{seed_resource_kind_catalog, KindDefaultGroups};
pub use ensure::{delete_resource_permission_bundle, ensure_resource_permission_bundle};
pub use error::ResourcePermissionError;
pub use kinds::{
    domain_id, normalize_id_fragment, owners_group_id, permission_name, permission_record_id,
    ResourceAction, ResourceKind, ResourceKindDescriptor, UmbrellaPolicy,
};
pub use policy::{
    ResourcePermissionPolicy, StaticPermissionGate, CREATE_GLUON_APPLICATIONS,
    CREATE_GLUON_APP_SETS, CREATE_NEUTRINO_SECRETS, CREATE_NUCLEUS_STACKS, GLUON_APP_RESOURCE,
    GLUON_APP_SET_RESOURCE, NEUTRINO_SECRET_RESOURCE, NUCLEUS_STACK_RESOURCE,
};
pub use revoke_umbrella_grants::revoke_umbrella_grants;
pub use spec::{ResourcePermissionBundle, ResourcePermissionSpec};
