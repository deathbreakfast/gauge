//! Valence privacy policies for coarse create and per-resource View/Edit/Delete.

use async_trait::async_trait;
use std::any::Any;
use valence::{Actor, ActorContext, Error, PolicyEvaluator, PrivacyOperation, Result, Valence};

use super::kinds::{permission_name, ResourceAction, ResourceKind};

fn actor_from_context(actor: &dyn ActorContext) -> Result<Actor> {
    serde_json::from_value(actor.actor_json().clone())
        .map_err(|e| Error::Internal(format!("invalid actor context: {e}")))
}

/// Valence privacy rule that requires a fixed Gauge permission name (coarse create, etc.).
///
/// System actors always pass. Same shape as Gluon's registry `PermissionGatePolicy`.
#[derive(Debug, Clone)]
pub struct StaticPermissionGate {
    /// Valence privacy rule name (e.g. `"gauge::CREATE_GLUON_APPLICATIONS"`).
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

/// Dynamic Valence privacy rule: maps CRUD op → resource action → `actor_can` on
/// `{kind}.{id}.{Action}`.
///
/// System actors always pass. **Create** is not handled here — use
/// [`StaticPermissionGate`] coarse create permissions (bundle does not exist yet).
#[derive(Debug, Clone)]
pub struct ResourcePermissionPolicy {
    /// Valence privacy rule name (stable, e.g. `"gauge::GLUON_APP_RESOURCE"`).
    pub rule_name: &'static str,
    /// Resource kind for permission name construction.
    pub kind: ResourceKind,
    /// JSON field holding the resource id (default `"id"`).
    pub id_field: &'static str,
}

impl ResourcePermissionPolicy {
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
}

#[async_trait]
impl PolicyEvaluator for ResourcePermissionPolicy {
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

        let Some(action) = Self::action_for_op(op) else {
            // Create must use coarse StaticPermissionGate — deny if mis-wired.
            return Ok(false);
        };

        let Some(resource_id) = record
            .get(self.id_field)
            .and_then(Self::resource_id_from_value)
        else {
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

/// Coarse create: Gluon applications.
pub const CREATE_GLUON_APPLICATIONS: StaticPermissionGate = StaticPermissionGate {
    rule_name: "gauge::CREATE_GLUON_APPLICATIONS",
    permission_name: "CreateGluonApplications",
};

/// Coarse create: Gluon app sets.
pub const CREATE_GLUON_APP_SETS: StaticPermissionGate = StaticPermissionGate {
    rule_name: "gauge::CREATE_GLUON_APP_SETS",
    permission_name: "CreateGluonAppSets",
};

/// Coarse create: Neutrino secrets.
pub const CREATE_NEUTRINO_SECRETS: StaticPermissionGate = StaticPermissionGate {
    rule_name: "gauge::CREATE_NEUTRINO_SECRETS",
    permission_name: "CreateNeutrinoSecrets",
};

/// Coarse create: Nucleus stacks.
pub const CREATE_NUCLEUS_STACKS: StaticPermissionGate = StaticPermissionGate {
    rule_name: "gauge::CREATE_NUCLEUS_STACKS",
    permission_name: "CreateNucleusStacks",
};

/// Per-resource CRUD gate for Gluon applications (read→View, update→Edit, delete→Delete).
pub const GLUON_APP_RESOURCE: ResourcePermissionPolicy = ResourcePermissionPolicy {
    rule_name: "gauge::GLUON_APP_RESOURCE",
    kind: ResourceKind::GluonApp,
    id_field: "id",
};

/// Per-resource CRUD gate for Gluon app sets.
pub const GLUON_APP_SET_RESOURCE: ResourcePermissionPolicy = ResourcePermissionPolicy {
    rule_name: "gauge::GLUON_APP_SET_RESOURCE",
    kind: ResourceKind::GluonAppSet,
    id_field: "id",
};

/// Per-resource CRUD gate for Neutrino secrets (Valence rows).
pub const NEUTRINO_SECRET_RESOURCE: ResourcePermissionPolicy = ResourcePermissionPolicy {
    rule_name: "gauge::NEUTRINO_SECRET_RESOURCE",
    kind: ResourceKind::NeutrinoSecret,
    id_field: "id",
};

/// Per-resource CRUD gate for Nucleus database stacks.
pub const NUCLEUS_STACK_RESOURCE: ResourcePermissionPolicy = ResourcePermissionPolicy {
    rule_name: "gauge::NUCLEUS_STACK_RESOURCE",
    kind: ResourceKind::NucleusStack,
    id_field: "id",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_create_names_are_stable() {
        assert_eq!(
            CREATE_GLUON_APPLICATIONS.permission_name,
            "CreateGluonApplications"
        );
        assert_eq!(
            CREATE_NEUTRINO_SECRETS.permission_name,
            "CreateNeutrinoSecrets"
        );
    }

    #[test]
    fn resource_id_from_string_or_record_id_object() {
        assert_eq!(
            ResourcePermissionPolicy::resource_id_from_value(&serde_json::json!("app-1")),
            Some("app-1")
        );
        assert_eq!(
            ResourcePermissionPolicy::resource_id_from_value(&serde_json::json!({
                "table": "gluon_application",
                "id": "2b0e709a-816f-4d12-821d-b86a48fe1104"
            })),
            Some("2b0e709a-816f-4d12-821d-b86a48fe1104")
        );
        assert_eq!(
            ResourcePermissionPolicy::resource_id_from_value(&serde_json::json!({})),
            None
        );
        assert_eq!(
            ResourcePermissionPolicy::resource_id_from_value(&serde_json::json!("  ")),
            None
        );
    }

    #[test]
    fn resource_policy_maps_ops() {
        assert_eq!(
            ResourcePermissionPolicy::action_for_op(PrivacyOperation::Read),
            Some(ResourceAction::View)
        );
        assert_eq!(
            ResourcePermissionPolicy::action_for_op(PrivacyOperation::Update),
            Some(ResourceAction::Edit)
        );
        assert_eq!(
            ResourcePermissionPolicy::action_for_op(PrivacyOperation::Delete),
            Some(ResourceAction::Delete)
        );
        assert_eq!(
            ResourcePermissionPolicy::action_for_op(PrivacyOperation::Create),
            None
        );
    }
}
