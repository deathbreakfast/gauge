//! Read a service user's groups and effective permissions under the caller's own Valence.
//!
//! Both reads are for the service user's owner, or a user who manages every service user. They
//! check that the caller can see the service user, then walk the grant graph with the same raw
//! reads and holder rules as [`service_user_decision`](super::access::service_user_decision).
//! Nothing here switches to [`valence::Actor::System`].

use lepton::generated::ServiceUserAccount;
use lepton_identity::service_users::ServiceUserId;
use valence::{Model, Valence};

use super::access::{group_behind_principal, group_has_service_user_raw, service_user_is_active};
use super::{service_user_principal_id, SERVICE_USER_PRINCIPAL_TABLE};
use crate::actor_can_raw::model_pk_id;
use crate::generated::{Permission, PermissionGroup};
use crate::service::{raw_table_rows, GaugeServiceError};
use crate::types::{ServiceUserGroupDto, ServiceUserPermissionDto};

/// Fail with `NotFound` unless the caller is a signed-in user who can see `service_user`.
///
/// Visibility is Lepton's own privacy rule: the owner, or a user holding
/// `lepton.service_user.manage_any`. A service user the caller can't see looks the same as one
/// that doesn't exist.
async fn require_visible_service_user(
    v: &Valence,
    service_user: &ServiceUserId,
) -> anyhow::Result<()> {
    if !matches!(v.actor(), valence::Actor::User { .. }) {
        return Err(GaugeServiceError::not_authorized("read service user access").into());
    }
    let visible = ServiceUserAccount::get(service_user.as_str(), v, valence::use_!(r"When an owner opens a **service user's access page**, we **check that they can see the service user**, meaning they own it or manage every service user. Nothing about the service user is shown here; the check only decides whether its groups and permissions are listed."))
        .await?
        .is_some();
    if visible {
        Ok(())
    } else {
        Err(GaugeServiceError::not_found("service_user", service_user.as_str()).into())
    }
}

fn group_dto(group: &PermissionGroup) -> ServiceUserGroupDto {
    ServiceUserGroupDto {
        id: model_pk_id(group.id()),
        name: group.name().clone(),
        description: group.description().cloned().unwrap_or_default(),
    }
}

async fn scan_table<T: serde::de::DeserializeOwned>(
    table: &str,
    v: &Valence,
) -> anyhow::Result<Vec<T>> {
    raw_table_rows(table, v)
        .await?
        .into_iter()
        .map(|row| serde_json::from_value(row).map_err(|e| anyhow::anyhow!("decode {table}: {e}")))
        .collect()
}

/// Every group that holds `service_user`, sorted by name.
///
/// A group holds the service user when the service user is a member of it, of a group nested in
/// it, or of a group that owns it, the same rule that decides the service user's permissions.
/// The scan visits every group, so cost grows with the number of groups and their nesting.
///
/// # Errors
///
/// [`GaugeServiceError`] (via `anyhow`): `NotFound` when the caller can't see the service user
/// (not its owner and not a manage-any user) or it doesn't exist. An error when the caller isn't
/// a signed-in user. Valence failures otherwise.
pub async fn service_user_groups(
    v: &Valence,
    service_user: &ServiceUserId,
) -> anyhow::Result<Vec<ServiceUserGroupDto>> {
    require_visible_service_user(v, service_user).await?;
    let principal_id = service_user_principal_id(service_user);
    let mut out = Vec::new();
    for group in scan_table::<PermissionGroup>("permission_group", v).await? {
        if group_has_service_user_raw(&group, &principal_id, v).await? {
            out.push(group_dto(&group));
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
    Ok(out)
}

/// Every permission `service_user` holds, each with the group it comes through, sorted by
/// permission name.
///
/// A permission granted to several groups the service user belongs to appears once per group.
/// `via_group` is the group the permission is granted to; a grant made straight to the service
/// user (how an approved on-behalf-of request lands) has `via_group: None`. A service user that is
/// suspended or being deleted holds nothing, so the list is empty.
///
/// # Errors
///
/// As [`service_user_groups`].
pub async fn service_user_effective_permissions(
    v: &Valence,
    service_user: &ServiceUserId,
) -> anyhow::Result<Vec<ServiceUserPermissionDto>> {
    require_visible_service_user(v, service_user).await?;
    if !service_user_is_active(v, service_user).await? {
        return Ok(Vec::new());
    }
    let principal_id = service_user_principal_id(service_user);
    let mut out = Vec::new();
    for permission in scan_table::<Permission>("permission", v).await? {
        let name = permission.name().clone();
        let description = permission.description().cloned().unwrap_or_default();
        let mut seen_groups = std::collections::HashSet::new();
        for principal in permission.get_allowed_principals_record_ids(v, valence::use_!(r"When an owner opens a **service user's access page**, we **follow each permission's allowed-principal edges** to find the permissions the service user holds and the group each comes through. The owner sees that list.")).await? {
            let via_group = if principal.table() == SERVICE_USER_PRINCIPAL_TABLE {
                if principal.id() != principal_id {
                    continue;
                }
                None
            } else {
                let Some(group) = group_behind_principal(&principal, v).await? else {
                    continue;
                };
                if !seen_groups.insert(model_pk_id(group.id()))
                    || !group_has_service_user_raw(&group, &principal_id, v).await?
                {
                    continue;
                }
                Some(group_dto(&group))
            };
            out.push(ServiceUserPermissionDto {
                name: name.clone(),
                description: description.clone(),
                via_group,
            });
        }
    }
    out.sort_by(|a, b| {
        a.name.cmp(&b.name).then_with(|| {
            a.via_group
                .as_ref()
                .map(|g| &g.name)
                .cmp(&b.via_group.as_ref().map(|g| &g.name))
        })
    });
    Ok(out)
}
