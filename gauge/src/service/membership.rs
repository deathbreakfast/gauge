//! Authorization shared by the group membership edits.

use valence::Valence;

use crate::generated::PermissionGroup;
use crate::super_user::actor_is_super_user;

use super::helpers::{get_group_raw, group_has_owner_user, user_id_candidates};
use super::GaugeServiceError;

/// Load the group and check the caller owns it (directly or through a group) or is a super user,
/// and that its members aren't managed by another product (see [`refuse_managed_member_edit`]).
pub(super) async fn group_for_member_edit(
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
    refuse_managed_member_edit(&group, v)?;
    Ok(group)
}

/// Refuse a member edit on a group whose members another product manages, unless the caller is
/// System.
///
/// A managed group (`managed_by` set, for example a Polaron team) gets its members from the
/// product that manages it, through a sync that starts as System. Anyone else, Super User and
/// the group's owners included, edits the members there instead. Owners can still grant the
/// group permissions and nest it in other groups.
///
/// # Errors
///
/// [`GaugeServiceError::Validation`] with the text
/// `managed_group: members of this group come from {managed_by}; change them there`.
pub(super) fn refuse_managed_member_edit(
    group: &PermissionGroup,
    v: &Valence,
) -> Result<(), GaugeServiceError> {
    match group.managed_by() {
        Some(managed_by) if !v.actor().is_system() => {
            log::warn!(
                target: "gauge.write_guard",
                "gauge write refused op=edit_managed_group_members managed_by={managed_by}"
            );
            Err(GaugeServiceError::validation(format!(
                "managed_group: members of this group come from {managed_by}; change them there"
            )))
        }
        _ => Ok(()),
    }
}
