//! Valence privacy policies for coarse create and per-resource View/Edit/Delete.

use async_trait::async_trait;
use std::any::Any;
use valence::{Actor, ActorContext, Error, PolicyEvaluator, PrivacyOperation, Result, Valence};

use super::kinds::{permission_name, ResourceAction, ResourceKind, ResourceKindDescriptor};

fn actor_from_context(actor: &dyn ActorContext) -> Result<Actor> {
    serde_json::from_value(actor.actor_json().clone())
        .map_err(|e| Error::Internal(format!("invalid actor context: {e}")))
}

/// Valence privacy rule that requires a fixed Gauge permission name (coarse create, etc.).
///
/// System actors always pass. Same shape as Gluon's registry `PermissionGatePolicy`.
/// Product crates declare their own `const` of this type beside their
/// [`ResourceKindDescriptor`]; Gauge no longer ships product-named gates.
#[derive(Debug, Clone)]
pub struct StaticPermissionGate {
    /// Valence privacy rule name (e.g. `"gluon::CREATE_GLUON_APPLICATIONS"`).
    pub rule_name: &'static str,
    /// Gauge permission name checked via [`crate::service::actor_can`].
    pub permission_name: &'static str,
}

#[async_trait]
impl PolicyEvaluator for StaticPermissionGate {
    fn name(&self) -> &'static str {
        self.rule_name
    }

    fn description(&self) -> Option<&'static str> {
        Some("Static Gauge permission gate")
    }

    async fn evaluate(
        &self,
        _op: PrivacyOperation,
        _record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> Result<bool> {
        let viewer = actor_from_context(actor)?;
        if viewer.is_system() {
            return Ok(true);
        }
        let allowed = crate::service::actor_can(v, self.permission_name)
            .await
            .map_err(|e| {
                Error::Privacy(format!(
                    "Permission policy check failed for '{}': {}",
                    self.permission_name, e
                ))
            })?;
        Ok(allowed)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

const fn action_for_op(op: PrivacyOperation) -> Option<ResourceAction> {
    match op {
        PrivacyOperation::Read => Some(ResourceAction::View),
        PrivacyOperation::Update => Some(ResourceAction::Edit),
        PrivacyOperation::Delete => Some(ResourceAction::Delete),
        PrivacyOperation::Create => None,
    }
}

/// Bare resource id from a Valence record JSON field.
///
/// Accepts a plain string **or** a serialized [`valence::RecordId`] object
/// (`{"table":"…","id":"…"}`) — Model privacy checks pass the latter.
fn resource_id_from_value(value: &serde_json::Value) -> Option<&str> {
    if let Some(s) = value.as_str() {
        let trimmed = s.trim();
        return (!trimmed.is_empty()).then_some(trimmed);
    }
    value
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Dynamic Valence privacy rule: maps CRUD op → resource action → `actor_can` on
/// `{kind}.{id}.{Action}`.
///
/// System actors always pass. **Create** is not handled here — use
/// [`StaticPermissionGate`] coarse create permissions (bundle does not exist yet).
///
/// `K` is the kind: [`ResourceKind`] by default, or [`ResourceKindDescriptor`] when
/// the wiring crate owns the resource kind and declares its own descriptor.
/// Product crates construct this beside their descriptor; Gauge ships the type only.
#[derive(Debug, Clone)]
pub struct ResourcePermissionPolicy<K = ResourceKind> {
    /// Valence privacy rule name (stable, e.g. `"gluon::GLUON_APP_RESOURCE"`).
    pub rule_name: &'static str,
    /// Resource kind for permission name construction.
    pub kind: K,
    /// JSON field holding the resource id (default `"id"`).
    pub id_field: &'static str,
}

#[async_trait]
impl<K> PolicyEvaluator for ResourcePermissionPolicy<K>
where
    K: Into<ResourceKindDescriptor> + Copy + std::fmt::Debug + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        self.rule_name
    }

    fn description(&self) -> Option<&'static str> {
        Some("Per-resource Gauge permission gate (View/Edit/Delete from record id)")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> Result<bool> {
        let viewer = actor_from_context(actor)?;
        if viewer.is_system() {
            return Ok(true);
        }

        let Some(action) = action_for_op(op) else {
            // Create must use coarse StaticPermissionGate — deny if mis-wired.
            return Ok(false);
        };

        let Some(resource_id) = record.get(self.id_field).and_then(resource_id_from_value) else {
            return Ok(false);
        };

        let name = permission_name(self.kind, resource_id, action);
        let allowed = crate::service::actor_can(v, &name).await.map_err(|e| {
            Error::Privacy(format!(
                "Resource permission policy check failed for '{name}': {e}"
            ))
        })?;
        Ok(allowed)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// Compatibility shims for git consumers that have not migrated yet (Release B).
// Products own the canonical consts in their resource_gauge / vault_gauge modules.
// These keep the same rule_name / permission_name / wire prefix as before.
// ---------------------------------------------------------------------------

/// Coarse create: Gluon applications.
///
/// Prefer `gluon::applications::CREATE_GLUON_APPLICATIONS` once that crate is on
/// the F29 consumer migration.
pub const CREATE_GLUON_APPLICATIONS: StaticPermissionGate = StaticPermissionGate {
    rule_name: "gauge::CREATE_GLUON_APPLICATIONS",
    permission_name: "CreateGluonApplications",
};

/// Coarse create: Gluon app sets.
///
/// Prefer `gluon::applications::CREATE_GLUON_APP_SETS`.
pub const CREATE_GLUON_APP_SETS: StaticPermissionGate = StaticPermissionGate {
    rule_name: "gauge::CREATE_GLUON_APP_SETS",
    permission_name: "CreateGluonAppSets",
};

/// Coarse create: Neutrino secrets.
///
/// Prefer `neutrino::CREATE_NEUTRINO_SECRETS`.
pub const CREATE_NEUTRINO_SECRETS: StaticPermissionGate = StaticPermissionGate {
    rule_name: "gauge::CREATE_NEUTRINO_SECRETS",
    permission_name: "CreateNeutrinoSecrets",
};

/// Coarse create: Nucleus stacks.
///
/// Prefer `nucleus::credentials::CREATE_NUCLEUS_STACKS`.
pub const CREATE_NUCLEUS_STACKS: StaticPermissionGate = StaticPermissionGate {
    rule_name: "gauge::CREATE_NUCLEUS_STACKS",
    permission_name: "CreateNucleusStacks",
};

/// Per-resource CRUD gate for Gluon applications.
///
/// Prefer `gluon::applications::GLUON_APP_RESOURCE`.
pub const GLUON_APP_RESOURCE: ResourcePermissionPolicy = ResourcePermissionPolicy {
    rule_name: "gauge::GLUON_APP_RESOURCE",
    kind: ResourceKind::GluonApp,
    id_field: "id",
};

/// Per-resource CRUD gate for Gluon app sets.
///
/// Prefer `gluon::applications::GLUON_APP_SET_RESOURCE`.
pub const GLUON_APP_SET_RESOURCE: ResourcePermissionPolicy = ResourcePermissionPolicy {
    rule_name: "gauge::GLUON_APP_SET_RESOURCE",
    kind: ResourceKind::GluonAppSet,
    id_field: "id",
};

/// Per-resource CRUD gate for Neutrino secrets.
///
/// Prefer `neutrino::NEUTRINO_SECRET_RESOURCE`.
pub const NEUTRINO_SECRET_RESOURCE: ResourcePermissionPolicy = ResourcePermissionPolicy {
    rule_name: "gauge::NEUTRINO_SECRET_RESOURCE",
    kind: ResourceKind::NeutrinoSecret,
    id_field: "id",
};

/// Per-resource CRUD gate for Nucleus database stacks.
///
/// Prefer `nucleus::credentials::NUCLEUS_STACK_RESOURCE`.
pub const NUCLEUS_STACK_RESOURCE: ResourcePermissionPolicy = ResourcePermissionPolicy {
    rule_name: "gauge::NUCLEUS_STACK_RESOURCE",
    kind: ResourceKind::NucleusStack,
    id_field: "id",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_create_names_match_kind_create_permission() {
        let gluon_create = StaticPermissionGate {
            rule_name: "test::CREATE_GLUON_APPLICATIONS",
            permission_name: ResourceKind::GluonApp.create_permission_name(),
        };
        let neutrino_create = StaticPermissionGate {
            rule_name: "test::CREATE_NEUTRINO_SECRETS",
            permission_name: ResourceKind::NeutrinoSecret.create_permission_name(),
        };
        assert_eq!(gluon_create.permission_name, "CreateGluonApplications");
        assert_eq!(neutrino_create.permission_name, "CreateNeutrinoSecrets");
    }

    #[test]
    fn resource_id_from_string_or_record_id_object() {
        assert_eq!(
            resource_id_from_value(&serde_json::json!("app-1")),
            Some("app-1")
        );
        assert_eq!(
            resource_id_from_value(&serde_json::json!({
                "table": "gluon_application",
                "id": "2b0e709a-816f-4d12-821d-b86a48fe1104"
            })),
            Some("2b0e709a-816f-4d12-821d-b86a48fe1104")
        );
        assert_eq!(resource_id_from_value(&serde_json::json!({})), None);
        assert_eq!(resource_id_from_value(&serde_json::json!("  ")), None);
    }

    #[test]
    fn resource_policy_maps_ops() {
        assert_eq!(
            action_for_op(PrivacyOperation::Read),
            Some(ResourceAction::View)
        );
        assert_eq!(
            action_for_op(PrivacyOperation::Update),
            Some(ResourceAction::Edit)
        );
        assert_eq!(
            action_for_op(PrivacyOperation::Delete),
            Some(ResourceAction::Delete)
        );
        assert_eq!(action_for_op(PrivacyOperation::Create), None);
    }

    #[test]
    fn policy_accepts_a_descriptor_kind() {
        const WIDGET: ResourceKindDescriptor = ResourceKind::GluonApp.descriptor();
        let policy = ResourcePermissionPolicy {
            rule_name: "test::WIDGET_RESOURCE",
            kind: WIDGET,
            id_field: "id",
        };
        assert_eq!(policy.name(), "test::WIDGET_RESOURCE");
        assert_eq!(
            permission_name(policy.kind, "app-1", ResourceAction::View),
            permission_name(ResourceKind::GluonApp, "app-1", ResourceAction::View)
        );
    }

    #[test]
    fn inline_resource_policy_uses_kind_descriptor() {
        let policy = ResourcePermissionPolicy {
            rule_name: "test::GLUON_APP_RESOURCE",
            kind: ResourceKind::GluonApp.descriptor(),
            id_field: "id",
        };
        assert_eq!(policy.kind.prefix, "gluon_app");
        assert_eq!(
            permission_name(policy.kind, "app1", ResourceAction::View),
            permission_name(ResourceKind::GluonApp, "app1", ResourceAction::View)
        );
    }
}
