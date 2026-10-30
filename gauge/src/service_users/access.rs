//! Permission checks for service user actors: group membership only, raw reads only.
//!
//! A service user gets a permission when a group that holds it (directly, or through
//! nested groups) lists the service user as a member, and the service user is active. Direct
//! grants to a service user are ignored, and a service user is never a super user. Every read is
//! a raw backend read, so this is safe inside privacy evaluation.

use std::collections::HashSet;

use lepton::generated::{ServiceUserAccount, ServiceUserAccountStatus};
use lepton_identity::service_users::ServiceUserId;
use valence::ownership::OwnershipService;
use valence::{RecordId, Valence};

use super::{service_user_principal_id, SERVICE_USER_PRINCIPAL_TABLE};
use crate::actor_can_raw::{model_pk_id, permissions_named_raw, raw_get_json};
use crate::generated::{PermissionGroup, PermissionGroupPrincipal};

/// Why a service user check came out the way it did. Logged, never shown to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceUserDecision {
    /// A group holding the permission lists the service user.
    Member,
    /// No group holding the permission lists the service user.
    NotMember,
    /// The service user is missing, suspended, or being deleted.
    Inactive,
}

impl ServiceUserDecision {
    pub const fn allowed(self) -> bool {
        matches!(self, Self::Member)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::NotMember => "not_member",
            Self::Inactive => "service_user_inactive",
        }
    }
}

/// Decide whether `service_user` holds `permission_name`.
///
/// # Errors
///
/// Backend read or decode failures. Callers treat an error as a refusal.
pub async fn service_user_decision(
    v: &Valence,
    service_user: &ServiceUserId,
    permission_name: &str,
) -> anyhow::Result<ServiceUserDecision> {
    let permission_name = permission_name.trim();
    if permission_name.is_empty() {
        return Ok(ServiceUserDecision::NotMember);
    }
    if !service_user_is_active_raw(v, service_user).await? {
        return Ok(ServiceUserDecision::Inactive);
    }
    let principal_id = service_user_principal_id(service_user);
    for permission in permissions_named_raw(permission_name, v).await? {
        for principal in permission.get_allowed_principals_record_ids(v, valence::use_!(r"When a **service user** calls an API that needs a **Gauge permission**, we **follow the permission's allowed-principal edges** to find the groups that hold it, or a direct grant to the service user. Used only to allow or deny the service user's request; nothing is shown.")).await? {
            // A grant made straight to the service user's principal (how an approved permission
            // request on its behalf lands), the same shape as a direct user grant.
            if principal.table() == SERVICE_USER_PRINCIPAL_TABLE && principal.id() == principal_id {
                return Ok(ServiceUserDecision::Member);
            }
            let Some(group) = group_behind_principal(&principal, v).await? else {
                continue;
            };
            if group_has_service_user_raw(&group, &principal_id, v).await? {
                return Ok(ServiceUserDecision::Member);
            }
        }
    }
    Ok(ServiceUserDecision::NotMember)
}

/// `true` when `service_user` is already a member of `group_id` (directly, through a nested
/// group, or through a group that owns it — the same holder semantics as
/// [`service_user_decision`]). Raw reads only, so it is safe to call before a write.
///
/// # Errors
///
/// Backend read or decode failures.
pub async fn service_user_in_group(
    v: &Valence,
    group_id: &str,
    service_user: &ServiceUserId,
) -> anyhow::Result<bool> {
    let Some(row) = raw_get_json("permission_group", group_id, v).await? else {
        return Ok(false);
    };
    let group: PermissionGroup = serde_json::from_value(row)?;
    let principal_id = service_user_principal_id(service_user);
    group_has_service_user_raw(&group, &principal_id, v).await
}

/// Log a decision at the service-user check boundary.
pub fn log_decision(permission_name: &str, decision: &anyhow::Result<ServiceUserDecision>) {
    match decision {
        Ok(d) => log::debug!(
            target: "gauge.service_user_access",
            "service user permission check permission={permission_name} outcome={} reason={}",
            if d.allowed() { "allow" } else { "deny" },
            d.as_str()
        ),
        Err(_) => log::warn!(
            target: "gauge.service_user_access",
            "service user permission check failed permission={permission_name} outcome=error"
        ),
    }
}

/// The service user row exists, is `active`, and is not waiting on deletion. Raw reads only.
///
/// # Errors
///
/// Backend read or decode failures.
pub async fn service_user_is_active(
    v: &Valence,
    service_user: &ServiceUserId,
) -> anyhow::Result<bool> {
    service_user_is_active_raw(v, service_user).await
}

/// The service user row exists, is `active`, and is not waiting on deletion.
async fn service_user_is_active_raw(
    v: &Valence,
    service_user: &ServiceUserId,
) -> anyhow::Result<bool> {
    let Some(row) = raw_get_json("service_user_account", service_user.as_str(), v).await? else {
        return Ok(false);
    };
    let service_user_row: ServiceUserAccount = serde_json::from_value(row)?;
    if service_user_row.status() != &ServiceUserAccountStatus::Active {
        return Ok(false);
    }
    match OwnershipService::pending_deletion_gate("service_user_account", service_user.as_str(), v)
        .await
    {
        Ok(()) => Ok(true),
        Err(valence::Error::PendingDeletion(_)) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("service user pending-deletion check: {e}")),
    }
}

/// The group a `permission_group_principal` points at; `None` for any other principal.
async fn group_behind_principal(
    principal: &RecordId,
    v: &Valence,
) -> anyhow::Result<Option<PermissionGroup>> {
    if principal.table() != "permission_group_principal" {
        return Ok(None);
    }
    let Some(row) = raw_get_json("permission_group_principal", principal.id(), v).await? else {
        return Ok(None);
    };
    let principal: PermissionGroupPrincipal = serde_json::from_value(row)?;
    let group_id = valence::extract_id_from_record(principal.group()).unwrap_or_default();
    match raw_get_json("permission_group", &group_id, v).await? {
        Some(row) => Ok(Some(serde_json::from_value(row)?)),
        None => Ok(None),
    }
}

/// Walk `group`, the groups nested in it, and groups that own it (owners count as
/// holders, the same as for users), looking for the service user's principal among members.
async fn group_has_service_user_raw(
    group: &PermissionGroup,
    service_user_principal_id: &str,
    v: &Valence,
) -> anyhow::Result<bool> {
    let mut visited = HashSet::new();
    let mut queue = vec![group.clone()];
    while let Some(current) = queue.pop() {
        if !visited.insert(model_pk_id(current.id())) {
            continue;
        }
        let owners = current.get_owners_record_ids(v, valence::use_!(r"When a **service user** needs a **Gauge permission**, we **follow a group's owner edges** to find owner groups the service user might belong to. Used only to allow or deny the service user's request; nothing is shown.")).await?;
        let members = current.get_members_record_ids(v, valence::use_!(r"When a **service user** needs a **Gauge permission**, we **follow a group's member edges** to see whether the service user, or a group it belongs to, is a member. Used only to allow or deny the service user's request; nothing is shown.")).await?;
        for principal in owners.iter().chain(members.iter()) {
            if principal.table() == SERVICE_USER_PRINCIPAL_TABLE {
                // Service users are only ever members; an owner edge to a service user would
                // be a forged row.
                if principal.id() == service_user_principal_id
                    && members.iter().any(|m| m == principal)
                {
                    return Ok(true);
                }
            } else if let Some(child) = group_behind_principal(principal, v).await? {
                queue.push(child);
            }
        }
    }
    Ok(false)
}
