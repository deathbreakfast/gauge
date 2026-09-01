//! Spec and bundle types for resource permission ensure.

use std::collections::HashMap;

use super::kinds::{ResourceAction, ResourceKind};

/// Input to [`super::ensure_resource_permission_bundle`].
#[derive(Debug, Clone)]
pub struct ResourcePermissionSpec {
    /// Resource kind (drives naming and default umbrella groups).
    pub kind: ResourceKind,
    /// Stable resource identifier (stack id, app id, secret id, …).
    pub resource_id: String,
    /// Human-readable label for the domain.
    pub display_name: String,
    /// Actions to materialize. Empty → [`ResourceKind::default_actions`].
    pub actions: Vec<ResourceAction>,
    /// Creating actor user id (bare id or `user:…`). **Required.**
    pub maintainer_actor: String,
}

/// Result of ensuring a resource permission bundle.
#[derive(Debug, Clone)]
pub struct ResourcePermissionBundle {
    /// Permission domain record id.
    pub domain_id: String,
    /// Owners group record id (Maintain ACL).
    pub owners_group_id: String,
    /// Map of [`ResourceAction`] suffix → Gauge permission **name** for `actor_can`.
    pub permission_names: HashMap<String, String>,
}

impl ResourcePermissionBundle {
    /// Permission name for an action, if present in this bundle.
    #[must_use]
    pub fn name_for(&self, action: ResourceAction) -> Option<&str> {
        self.permission_names
            .get(action.as_str())
            .map(String::as_str)
    }
}
