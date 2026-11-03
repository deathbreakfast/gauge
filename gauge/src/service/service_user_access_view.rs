//! See which groups a Lepton service user belongs to and which permissions it holds.
//!
//! Both views follow the same rules as the permission check itself
//! ([`crate::service_users::access`]): group membership counts directly, through nested groups
//! and through owning groups, a direct grant counts for permissions, and a suspended or deleted
//! service user holds nothing. Each entry is the same DTO [`get_group_detail`](super::get_group_detail)
//! or [`get_permission_detail`](super::get_permission_detail) returns, so owners, members and
//! allow-lists stay hidden from callers who couldn't see them there.

use lepton_identity::service_users::ServiceUserId;
use valence::{Model, Valence};

use crate::generated::{Permission, PermissionGroup};
use crate::service_users::access::{
    service_user_decision, service_user_in_group, service_user_is_active,
};
use crate::types::{PermissionDetailDto, PermissionGroupDetailDto};

use super::helpers::{raw_table_rows, record_pk_id, require_user_id};
use super::permissions::{get_group_detail, get_permission_detail};
use super::GaugeServiceError;

/// The caller is a signed-in user who can see the service user (its owner, or a user who
/// manages every service user). Anyone else gets `NotFound`, so existence isn't revealed.
async fn require_visible_service_user(
    service_user: &ServiceUserId,
    v: &Valence,
) -> anyhow::Result<()> {
    require_user_id(v)?;
    let visible = lepton::generated::ServiceUserAccount::get(service_user.as_str(), v, valence::use_!(r"When someone **views a service user's groups or permissions**, we **check that they can see the service user**, meaning they own it or manage every service user. Nothing about the service user is shown by this check; it only decides whether the view may go ahead."))
        .await?
        .is_some();
    if visible {
        Ok(())
    } else {
        Err(GaugeServiceError::not_found("service_user", service_user.as_str()).into())
    }
}

/// List the groups `service_user` belongs to, sorted by name.
///
/// A group counts when it lists the service user as a member, directly or through a nested
/// group, or when a group that owns it does. An inactive service user (suspended, being
/// deleted, or missing its row) belongs to nothing, so the list is empty.
///
/// The caller must be a signed-in user who owns the service user or manages every service user.
///
/// # Errors
///
/// [`GaugeServiceError`] (via `anyhow`): `NotFound` when the caller can't see the service user.
/// Valence failures otherwise; a caller that isn't a signed-in user is refused.
pub async fn list_service_user_groups(
    service_user: &ServiceUserId,
    v: &Valence,
) -> anyhow::Result<Vec<PermissionGroupDetailDto>> {
    require_visible_service_user(service_user, v).await?;
    if !service_user_is_active(v, service_user).await? {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for row in raw_table_rows("permission_group", v).await? {
        let group: PermissionGroup = serde_json::from_value(row)?;
        let group_id = record_pk_id(group.id());
        if !service_user_in_group(v, &group_id, service_user).await? {
            continue;
        }
        if let Some(detail) = get_group_detail(&group_id, v).await? {
            out.push(detail);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// List the permissions `service_user` holds, sorted by name.
///
/// A permission counts when the service user passes the same check `actor_can` runs for it:
/// a group it belongs to holds the permission, or the permission was granted to it directly.
/// An inactive service user holds nothing, so the list is empty.
///
/// The caller must be a signed-in user who owns the service user or manages every service user.
///
/// # Errors
///
/// As [`list_service_user_groups`].
pub async fn list_service_user_permissions(
    service_user: &ServiceUserId,
    v: &Valence,
) -> anyhow::Result<Vec<PermissionDetailDto>> {
    require_visible_service_user(service_user, v).await?;
    if !service_user_is_active(v, service_user).await? {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for row in raw_table_rows("permission", v).await? {
        let permission: Permission = serde_json::from_value(row)?;
        if !service_user_decision(v, service_user, permission.name())
            .await?
            .allowed()
        {
            continue;
        }
        if let Some(detail) = get_permission_detail(&record_pk_id(permission.id()), v).await? {
            out.push(detail);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}
