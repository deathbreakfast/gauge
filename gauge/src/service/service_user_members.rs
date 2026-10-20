//! Add and remove Lepton service users as permission group members.
//!
//! Members show up in [`get_group_detail`](super::get_group_detail) as
//! [`PrincipalKind::ServiceUser`](crate::types::PrincipalKind::ServiceUser) entries, with the
//! service user's handle as the label and the owner's label in `owner_label`.

use lepton_identity::service_users::ServiceUserId;
use valence::{Model, RecordId, Valence};

use crate::generated::{PermissionGroup, PermissionServiceUserPrincipal};
use crate::service_users::{service_user_principal_id, SERVICE_USER_PRINCIPAL_TABLE};
use crate::super_user::{actor_is_super_user, SUPER_USER_GROUP_ID};
use crate::types::HistoryDiffItemDto;

use super::helpers::{
    get_group_raw, group_has_owner_user, persist_history_entry, require_model_id, require_user_id,
    user_id_candidates,
};
use super::GaugeServiceError;

/// Load the group and check the caller owns it (directly or through a group) or is a super user.
async fn group_for_member_edit(
    group_id: &str,
    actor_user_id: &str,
    v: &Valence,
) -> anyhow::Result<PermissionGroup> {
    let group = get_group_raw(group_id, v)
        .await?
        .ok_or_else(|| GaugeServiceError::not_found("permission_group", group_id))?;
    if !group_has_owner_user(&group, &user_id_candidates(actor_user_id), v).await?
        && !actor_is_super_user(v).await?
    {
        return Err(GaugeServiceError::not_authorized("edit group membership").into());
    }
    Ok(group)
}

async fn get_service_user_principal_raw(
    service_user: &ServiceUserId,
    v: &Valence,
) -> anyhow::Result<Option<PermissionServiceUserPrincipal>> {
    match crate::actor_can_raw::raw_get_json(
        SERVICE_USER_PRINCIPAL_TABLE,
        &service_user_principal_id(service_user),
        v,
    )
    .await?
    {
        Some(row) => Ok(Some(serde_json::from_value(row)?)),
        None => Ok(None),
    }
}

/// Whether the caller may add service users to `group_id` with [`add_group_member_service_user`].
///
/// True when the caller is a signed-in user who owns the group (directly or
/// through a group) or is a super user, and the group isn't the Super User
/// group. Use it to decide whether a UI offers the group as a choice; the add
/// itself checks again, and also checks that the caller can see the service user.
///
/// # Errors
///
/// [`GaugeServiceError`] (via `anyhow`): `NotFound` when the group doesn't
/// exist. Valence failures otherwise. A caller that isn't a signed-in user gets
/// `Ok(false)`.
pub async fn can_add_group_member_service_user(
    group_id: &str,
    v: &Valence,
) -> anyhow::Result<bool> {
    let Ok(actor_user_id) = require_user_id(v) else {
        return Ok(false);
    };
    if group_id == SUPER_USER_GROUP_ID {
        return Ok(false);
    }
    let group = get_group_raw(group_id, v)
        .await?
        .ok_or_else(|| GaugeServiceError::not_found("permission_group", group_id))?;
    Ok(
        group_has_owner_user(&group, &user_id_candidates(&actor_user_id), v).await?
            || actor_is_super_user(v).await?,
    )
}

/// Add `service_user` as a member of `group_id`, so it holds everything the group holds.
///
/// The caller must own the group (or be a super user) **and** be able to see the
/// service user under their own Valence: its owner, or a user who manages every service user. A
/// group owner can't pull in a service user they can't see, and a service user owner can't put
/// their service user in a group they don't own. Service users never join the Super User group.
/// Adding a service user that is already a member changes nothing.
///
/// # Errors
///
/// [`GaugeServiceError`] (via `anyhow`): `NotAuthorized` when the caller isn't a
/// signed-in user, doesn't own the group, or isn't a super user; `NotFound` for a
/// missing group or a service user the caller can't see; `Validation` for the Super User
/// group. Valence failures otherwise.
pub async fn add_group_member_service_user(
    group_id: &str,
    service_user: &ServiceUserId,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    if group_id == SUPER_USER_GROUP_ID {
        return Err(GaugeServiceError::validation(
            "Service users cannot join the Super User group",
        )
        .into());
    }
    let group = group_for_member_edit(group_id, &actor_user_id, v).await?;
    let visible = lepton::generated::ServiceUserAccount::get(service_user.as_str(), v, valence::use_!(r"When an operator **adds a service user to a permission group**, we **check that they can see the service user**, meaning they own it or manage every service user. Nothing about the service user is shown here; the check only decides whether the add may go ahead."))
        .await?
        .is_some();
    if !visible {
        return Err(GaugeServiceError::not_found("service_user", service_user.as_str()).into());
    }

    let principal_id = service_user_principal_id(service_user);
    if get_service_user_principal_raw(service_user, v)
        .await?
        .is_none()
    {
        let row = PermissionServiceUserPrincipal::new(
            RecordId::new("service_user_account", service_user.as_str()),
            service_user.as_str().to_string(),
        )?;
        PermissionServiceUserPrincipal::upsert(&principal_id, row, v, valence::use_!(r"When an operator **adds a service user to a permission group**, we **save a principal row for the service user** that points at the service user's id. Group member lists show the service user's handle, and permission checks use the row to tell whether the service user belongs to the group."))
            .await?;
    }
    let principal = get_service_user_principal_raw(service_user, v)
        .await?
        .ok_or_else(|| GaugeServiceError::invariant("service user principal missing after save"))?;
    group
        .relate_to_member_record(&require_model_id(principal.id(), "principal")?, v, valence::use_!(r"When an operator **adds a service user to a permission group**, we **write the member edge** so the service user holds the group's permissions while it is active. Operators see the service user in the group's member list."))
        .await?;
    persist_history_entry(
        v,
        "permission_group",
        group_id.to_string(),
        "add_member_service_user",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "member_service_users".to_string(),
            old_value: serde_json::Value::Null,
            new_value: serde_json::Value::String(service_user.as_str().to_string()),
        }],
    )
    .await?;
    Ok(())
}

/// Remove `service_user` from `group_id`. The service user loses what the group granted at once.
///
/// The caller must own the group or be a super user. Seeing the service user isn't
/// required, so a group owner can always remove a service user someone else added.
/// Removing a service user that isn't a member changes nothing.
///
/// # Errors
///
/// [`GaugeServiceError`] (via `anyhow`): `NotAuthorized` or `NotFound` for the
/// group, as for [`add_group_member_service_user`]. Valence failures otherwise.
pub async fn remove_group_member_service_user(
    group_id: &str,
    service_user: &ServiceUserId,
    v: &Valence,
) -> anyhow::Result<()> {
    let actor_user_id = require_user_id(v)?;
    let group = group_for_member_edit(group_id, &actor_user_id, v).await?;
    let Some(principal) = get_service_user_principal_raw(service_user, v).await? else {
        return Ok(());
    };
    group
        .unrelate_from_member_record(&require_model_id(principal.id(), "principal")?, v, valence::use_!(r"When an operator **removes a service user from a permission group**, we **delete the member edge** so the service user stops holding the group's permissions. Operators see the updated member list."))
        .await?;
    persist_history_entry(
        v,
        "permission_group",
        group_id.to_string(),
        "remove_member_service_user",
        Some(actor_user_id),
        vec![HistoryDiffItemDto {
            field: "member_service_users".to_string(),
            old_value: serde_json::Value::String(service_user.as_str().to_string()),
            new_value: serde_json::Value::Null,
        }],
    )
    .await?;
    Ok(())
}
