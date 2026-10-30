//! Authorization shared by the group membership edits.

use valence::Valence;

use crate::generated::PermissionGroup;
use crate::super_user::actor_is_super_user;

use super::helpers::{get_group_raw, group_has_owner_user, user_id_candidates};
use super::GaugeServiceError;

/// Load the group and check the caller owns it (directly or through a group) or is a super user.
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
    Ok(group)
}
