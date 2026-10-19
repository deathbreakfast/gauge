//! Privacy rule letting a service user's manager delete its Gauge principal row.

use std::any::Any;

use async_trait::async_trait;
use lepton_identity::service_users::installed_service_user_gate;
use valence::{Actor, ActorContext, Error, PolicyEvaluator, PrivacyOperation, Valence};

use crate::actor_can_raw::raw_get_json;
use crate::generated::PermissionServiceUserPrincipal;

/// Allows **delete** of a `permission_service_user_principal` row by the service user's owner, or
/// by a user the installed Lepton service user gate lets manage every service user.
///
/// Deleting a service user cascades to its principal row (and from there to its group
/// memberships), and that delete runs as whoever deleted the service user. Without this
/// rule only System and super users could delete a service user that belongs to a group.
/// Reads are raw, and the caller's actor is never changed.
#[derive(Debug, Clone, Copy)]
pub struct ServiceUserPrincipalManager;

/// Rule instance for `permission_service_user_principal` delete policies.
pub const SERVICE_USER_PRINCIPAL_MANAGER: ServiceUserPrincipalManager = ServiceUserPrincipalManager;

#[async_trait]
impl PolicyEvaluator for ServiceUserPrincipalManager {
    fn name(&self) -> &'static str {
        "perm::SERVICE_USER_PRINCIPAL_MANAGER"
    }

    fn description(&self) -> Option<&'static str> {
        Some(
            "Allow service user principal delete for the service user's owner or a manage-any user",
        )
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> valence::Result<bool> {
        if !matches!(op, PrivacyOperation::Delete) {
            return Ok(false);
        }
        let actor: Actor = serde_json::from_value(actor.actor_json().clone())
            .map_err(|e| Error::Internal(format!("invalid actor context: {e}")))?;
        let Some(user_id) = actor.user_id() else {
            return Ok(false);
        };
        let principal: PermissionServiceUserPrincipal = serde_json::from_value(record.clone())
            .map_err(|e| Error::Privacy(format!("service user principal decode failed: {e}")))?;
        let service_user_id =
            valence::extract_id_from_record(principal.service_user()).unwrap_or_default();
        let service_user_row = raw_get_json("service_user_account", &service_user_id, v)
            .await
            .map_err(|e| Error::Privacy(format!("service user lookup failed: {e}")))?;
        if let Some(row) = service_user_row {
            let service_user: lepton::generated::ServiceUserAccount =
                serde_json::from_value(row)
                    .map_err(|e| Error::Privacy(format!("service user decode failed: {e}")))?;
            let owner = service_user
                .user()
                .and_then(|r| valence::extract_id_from_record(r).ok())
                .unwrap_or_default();
            let caller = user_id.split_once(':').map_or(user_id, |(_, bare)| bare);
            if !owner.is_empty() && owner == caller {
                return Ok(true);
            }
        }
        match installed_service_user_gate() {
            Some(gate) => Ok(gate.may_manage_any_service_user(v).await.unwrap_or(false)),
            None => Ok(false),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
