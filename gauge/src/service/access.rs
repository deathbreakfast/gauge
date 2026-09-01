use valence::Valence;

use crate::generated::{Permission, PermissionGroup};
use crate::instrumentation::{PermissionCheckOutcome, PermissionCheckRecord};
use crate::super_user::actor_is_super_user;
use crate::types::{PermissionRequestTargetKind, PrincipalKind};

use super::helpers::{
    current_user_id, get_group_principal_raw, get_group_raw, get_permission_raw,
    get_user_principal_raw, group_has_owner_user, group_has_user, permissions_named,
    principal_kind_from_record, user_id_candidates,
};

/// `true` when the current actor is a super user or an owner (direct or nested) of `group`.
pub async fn can_edit_group(group: &PermissionGroup, v: &Valence) -> anyhow::Result<bool> {
    if actor_is_super_user(v).await? {
        return Ok(true);
    }
    let Some(user_id) = current_user_id(v) else {
        return Ok(false);
    };
    let candidates = user_id_candidates(&user_id);
    // Use system Valence for membership graph reads (typed user reads can miss trait fields).
    let system = v;
    group_has_owner_user(group, &candidates, system).await
}

/// `true` when the current actor is a super user or an owner (direct or nested)
/// of `permission`'s owners group.
pub async fn can_edit_permission(permission: &Permission, v: &Valence) -> anyhow::Result<bool> {
    if actor_is_super_user(v).await? {
        return Ok(true);
    }
    let system = v;
    let owners_group_id =
        valence::extract_id_from_record(permission.owners_group()).unwrap_or_default();
    if owners_group_id.is_empty() {
        return Ok(false);
    }
    // Raw read avoids typed relation hops that can drop trait fields under MEM.
    let Some(owners_group) = get_group_raw(&owners_group_id, system).await? else {
        return Ok(false);
    };
    can_edit_group(&owners_group, v).await
}

pub async fn actor_can_review_target(
    target: &valence::RecordId,
    v: &Valence,
) -> anyhow::Result<bool> {
    let system = v;
    let target_id = valence::extract_id_from_record(target).unwrap_or_default();
    if target_id.is_empty() {
        return Ok(false);
    }

    match target.table() {
        "permission" => {
            let Some(permission) = get_permission_raw(&target_id, system).await? else {
                return Ok(false);
            };
            can_edit_permission(&permission, v).await
        }
        "permission_group" => {
            let Some(group) = get_group_raw(&target_id, system).await? else {
                return Ok(false);
            };
            can_edit_group(&group, v).await
        }
        _ => Ok(false),
    }
}

pub async fn permission_allows_user(
    permission: &Permission,
    user_ids: &[String],
    v: &Valence,
) -> anyhow::Result<bool> {
    for principal_thing in permission.get_allowed_principals_record_ids(v).await? {
        let principal_id = principal_thing.id().to_string();
        match principal_kind_from_record(&principal_thing) {
            Some(PrincipalKind::User) => {
                if let Some(principal) = get_user_principal_raw(&principal_id, v).await? {
                    let allowed_user_id =
                        valence::extract_id_from_record(principal.user()).unwrap_or_default();
                    if user_ids.iter().any(|id| id == &allowed_user_id) {
                        return Ok(true);
                    }
                }
            }
            Some(PrincipalKind::Group) => {
                if let Some(principal) = get_group_principal_raw(&principal_id, v).await? {
                    let group_id =
                        valence::extract_id_from_record(principal.group()).unwrap_or_default();
                    if let Some(group) = get_group_raw(&group_id, v).await? {
                        if group_has_user(&group, user_ids, v).await? {
                            return Ok(true);
                        }
                    }
                }
            }
            None => {}
        }
    }

    Ok(false)
}

pub fn request_target_kind_from_record(
    rid: &valence::RecordId,
) -> Option<PermissionRequestTargetKind> {
    match rid.table() {
        "permission" => Some(PermissionRequestTargetKind::Permission),
        "permission_group" => Some(PermissionRequestTargetKind::Group),
        _ => None,
    }
}

pub fn request_target_record(
    kind: &PermissionRequestTargetKind,
    target_id: &str,
) -> valence::RecordId {
    match kind {
        PermissionRequestTargetKind::Permission => valence::RecordId::new("permission", target_id),
        PermissionRequestTargetKind::Group => valence::RecordId::new("permission_group", target_id),
    }
}

/// Returns `true` when the current actor has the named permission.
///
/// This checks direct user grants and grants inherited through allowed groups
/// (including nested group membership).
pub async fn actor_can(v: &Valence, permission_name: &str) -> anyhow::Result<bool> {
    let permission_name = permission_name.trim();
    let Some(actor_user_id) = current_user_id(v) else {
        crate::instrumentation::record_permission_check(&PermissionCheckRecord::from_valence(
            v,
            permission_name,
            PermissionCheckOutcome::NoActor,
        ));
        return Ok(false);
    };
    if actor_is_super_user(v).await? {
        crate::instrumentation::record_permission_check(&PermissionCheckRecord::from_valence(
            v,
            permission_name,
            PermissionCheckOutcome::Allow,
        ));
        return Ok(true);
    }
    user_can(v, &actor_user_id, permission_name).await
}

/// Alias for `actor_can`.
pub async fn has_permission(v: &Valence, permission_name: &str) -> anyhow::Result<bool> {
    actor_can(v, permission_name).await
}

/// Returns `true` when the provided user has the named permission.
///
/// This checks direct user grants and grants inherited through allowed groups
/// (including nested group membership).
pub async fn user_can(v: &Valence, user_id: &str, permission_name: &str) -> anyhow::Result<bool> {
    let permission_name = permission_name.trim();
    if permission_name.is_empty() {
        crate::instrumentation::record_permission_check(&PermissionCheckRecord::from_valence(
            v,
            permission_name,
            PermissionCheckOutcome::Deny,
        ));
        return Ok(false);
    }

    let cache_key = format!("{user_id}:{permission_name}");
    if let Some(cache) = v.permission_cache() {
        if let Some(cached) = cache.get(&cache_key) {
            let outcome = if cached {
                PermissionCheckOutcome::Allow
            } else {
                PermissionCheckOutcome::Deny
            };
            crate::instrumentation::record_permission_check(&PermissionCheckRecord::from_valence(
                v,
                permission_name,
                outcome,
            ));
            return Ok(cached);
        }
    }

    let user_ids = user_id_candidates(user_id);
    let system = v;
    let check_result: anyhow::Result<bool> = async {
        let permissions = permissions_named(permission_name, system).await?;

        for permission in permissions {
            if permission_allows_user(&permission, &user_ids, system).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }
    .await;

    match &check_result {
        Ok(true) => crate::instrumentation::record_permission_check(
            &PermissionCheckRecord::from_valence(v, permission_name, PermissionCheckOutcome::Allow),
        ),
        Ok(false) => crate::instrumentation::record_permission_check(
            &PermissionCheckRecord::from_valence(v, permission_name, PermissionCheckOutcome::Deny),
        ),
        Err(e) => crate::instrumentation::record_permission_check(
            &PermissionCheckRecord::from_valence(v, permission_name, PermissionCheckOutcome::Error)
                .with_error(e.to_string()),
        ),
    }

    if let (Some(cache), Ok(allowed)) = (v.permission_cache(), &check_result) {
        cache.set(&cache_key, *allowed);
    }

    check_result
}
