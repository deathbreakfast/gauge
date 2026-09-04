//! Chronon-scheduled operational scripts for the permission domain.
//!
//! ## Concern → API
//!
//! | Concern | API |
//! |---------|-----|
//! | Ensure Super User group (run-once) | [`ensure_super_user_group_script`] |
//! | Sync Super User membership from roles | [`sync_super_user_membership_roles_script`] |
//! | Migrate legacy principal edges | [`migrate_permission_principal_connections`] |
//!
//! Script entry points return [`anyhow::Result`] (Chronon / Valence aggregation).
//! Domain Super User helpers used by scripts live under [`crate::super_user`].
//!
//! Product-owned migration scripts (for example Neutrino secret umbrella revoke) live
//! in the owning product crate behind its `chronon` feature.

/// One-shot script that ensures the Super User group exists.
#[cfg(feature = "ssr")]
pub mod ensure_super_user_group;

/// One-shot migration script for legacy principal connection edges.
#[cfg(feature = "ssr")]
pub mod migrate_principal_connections;

/// Recurring (cron) script that syncs Super User group membership from account roles.
#[cfg(feature = "ssr")]
pub mod sync_super_user_membership_roles;

#[cfg(feature = "ssr")]
pub use ensure_super_user_group::ensure_super_user_group_script;
#[cfg(feature = "ssr")]
pub use migrate_principal_connections::migrate_permission_principal_connections;
#[cfg(feature = "ssr")]
pub use sync_super_user_membership_roles::sync_super_user_membership_roles_script;
